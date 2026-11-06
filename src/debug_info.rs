use std::fs::File;
use std::io::BufReader;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::anyhow;
use crossbeam_channel::{Receiver, Sender, bounded};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use tracing::debug;
use tracing::instrument;

use lightswitch_object::BuildId;
use tracing::warn;

use crate::NAME_AND_VERSION;

/// Handles with debug information.
///
/// This currently experimental, not feature-complete and not used yet during
/// symbolization. The end goal would be to keep track of every debug info
/// that's either present locally or remotely (depending on configuration),
/// while minimizing the number of open FDs, file copies, and race condition
/// windows.
pub trait DebugInfoManager {
    fn add_if_not_present(
        &mut self,
        name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()>;
    fn debug_info_path(&self) -> Option<PathBuf>;
}

pub struct DebugInfoBackendNull {}
impl DebugInfoManager for DebugInfoBackendNull {
    fn add_if_not_present(
        &mut self,
        _name: &str,
        _build_id: &BuildId,
        _debug_info: &Path,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn debug_info_path(&self) -> Option<PathBuf> {
        None
    }
}

#[derive(Debug)]
pub struct DebugInfoBackendFilesystem {
    pub path: PathBuf,
}
impl DebugInfoManager for DebugInfoBackendFilesystem {
    #[instrument(level = "debug")]
    fn add_if_not_present(
        &mut self,
        _name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()> {
        // try to find, else extract
        if self.find_in_fs(build_id) {
            return Ok(());
        }

        self.add_to_fs(build_id, debug_info)
    }

    fn debug_info_path(&self) -> Option<PathBuf> {
        todo!()
    }
}

impl DebugInfoBackendFilesystem {
    fn find_in_fs(&self, build_id: &BuildId) -> bool {
        self.path.join(build_id.to_string()).exists()
    }

    fn add_to_fs(&self, build_id: &BuildId, debug_info: &Path) -> anyhow::Result<()> {
        // TODO: add support for other methods beyond copying. For example
        // hardlinks could be used and only fall back to copying if the src
        // and dst filesystems differ.
        let mut reader = BufReader::new(File::open(debug_info)?);
        let mut writer = std::fs::File::create(self.path.join(build_id.to_string()))?;
        std::io::copy(&mut reader, &mut writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DebugInfoBackendRemote {
    server_url: String,
    query_client: reqwest::blocking::Client,
    sender: Sender<JobArguments>,
    _threads: Vec<JoinHandle<()>>,
}

struct JobArguments {
    name: String,
    build_id: BuildId,
    file: File,
}

/// This implementation is lossy and might result in some debug infos not being
/// uploaded, either because the queue is full, or during shutdown as the queue
/// is not drained. This set of trade-offs were chosen in the name of using as
/// little memory as possible.
impl DebugInfoBackendRemote {
    fn spawn_worker(
        i: usize,
        receiver: Receiver<JobArguments>,
        upload_client: Client,
        token: Option<String>,
        server_url: String,
    ) -> std::io::Result<JoinHandle<()>> {
        thread::Builder::new()
            .name(format!("debug-upload-{i}"))
            .spawn(move || {
                loop {
                    match receiver.recv() {
                        Ok(arg) => {
                            let ret = Self::upload_to_backend(
                                &upload_client,
                                &token,
                                &server_url,
                                &arg.name,
                                &arg.build_id,
                                arg.file,
                            );
                            if let Err(e) = ret {
                                warn!("failed to upload to backend due to {:?}", e);
                            }
                        }
                        Err(e) => {
                            debug!("debug info worker failed with {:?}", e);
                            break;
                        }
                    };
                }
            })
    }

    pub fn new(
        token: Option<String>,
        server_url: String,
        query_timeout: Duration,
        upload_timeout: Duration,
        workers: usize,
    ) -> anyhow::Result<Self> {
        let query_client = reqwest::blocking::Client::builder()
            .timeout(query_timeout)
            .user_agent(NAME_AND_VERSION)
            .build()?;
        let upload_client = reqwest::blocking::Client::builder()
            .timeout(upload_timeout)
            .user_agent(NAME_AND_VERSION)
            .build()?;

        let (sender, receiver) = bounded(200);
        let _threads = (0..workers)
            .map(|i| {
                let receiver: Receiver<JobArguments> = receiver.clone();
                let upload_client = upload_client.clone();
                let token = token.clone();
                let server_url = server_url.clone();

                Self::spawn_worker(i, receiver, upload_client, token, server_url)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(DebugInfoBackendRemote {
            server_url,
            query_client,
            sender,
            _threads,
        })
    }

    /// Enqueues a debug info upload in a best-effort fashion, since the queue
    /// is bounded and we'll drop entries if we are lagging behind uploads
    /// and it fills up.
    fn enqueue(&mut self, name: &str, build_id: &BuildId, file: File) {
        let ret = self.sender.try_send(JobArguments {
            name: name.to_string(),
            build_id: build_id.clone(),
            file,
        });

        if let Err(e) = ret {
            debug!("enqueueing debug info failed with {:?}", e);
        }
    }
}

impl DebugInfoManager for DebugInfoBackendRemote {
    #[instrument(level = "debug")]
    fn add_if_not_present(
        &mut self,
        name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()> {
        if self.find_in_backend(build_id)? {
            return Ok(());
        }

        // Open the file as fast as possible to reduce the window for race conditions.
        let file = File::open(debug_info)?;
        self.enqueue(name, build_id, file);
        Ok(())
    }

    fn debug_info_path(&self) -> Option<PathBuf> {
        None
    }
}

impl DebugInfoBackendRemote {
    /// Whether the backend knows about some debug information.
    #[instrument(level = "debug")]
    fn find_in_backend(&self, build_id: &BuildId) -> anyhow::Result<bool> {
        let response = self
            .query_client
            .get(format!(
                "{}/debuginfo/{}",
                self.server_url.clone(),
                build_id
            ))
            .send();

        Ok(response?.status() == StatusCode::OK)
    }

    /// Send the debug information to the backend.
    #[instrument(level = "debug")]
    fn upload_to_backend(
        upload_client: &Client,
        token: &Option<String>,
        server_url: &str,
        name: &str,
        build_id: &BuildId,
        file: File,
    ) -> anyhow::Result<()> {
        let size = file.metadata()?.size();
        let reader = BufReader::new(file);
        let body = reqwest::blocking::Body::sized(reader, size);
        let mut request = upload_client
            .post(format!(
                "{}/debuginfo/new/{}/{}",
                server_url, name, build_id
            ))
            .body(body);

        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }

        let response = request.send()?;

        if !response.status().is_success() {
            return Err(anyhow!("debuginfo upload failed with {:?}", response));
        }
        Ok(())
    }
}

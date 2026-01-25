use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use reqwest::StatusCode;
use tracing::instrument;

use lightswitch_object::BuildId;

/// Handles with debug information.
///
/// This currently experimental, not feature-complete and not used yet during
/// symbolization. The end goal would be to keep track of every debug info
/// that's either present locally or remotely (depending on configuration),
/// while minimizing the number of open FDs, file copies, and race condition
/// windows.
pub trait DebugInfoManager {
    fn add_if_not_present(
        &self,
        name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()>;
    fn debug_info_path(&self) -> Option<PathBuf>;
}

pub struct DebugInfoBackendNull {}
impl DebugInfoManager for DebugInfoBackendNull {
    fn add_if_not_present(
        &self,
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
    #[instrument]
    fn add_if_not_present(
        &self,
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
    pub token: Option<String>,
    pub server_url: String,
    pub query_client: reqwest::blocking::Client,
    pub upload_client: reqwest::blocking::Client,
}

impl DebugInfoBackendRemote {
    pub fn new(
        token: Option<String>,
        server_url: String,
        query_timeout: Duration,
        upload_timeout: Duration,
    ) -> anyhow::Result<Self> {
        Ok(DebugInfoBackendRemote {
            token,
            server_url,
            query_client: reqwest::blocking::Client::builder()
                .timeout(query_timeout)
                .build()?,
            upload_client: reqwest::blocking::Client::builder()
                .timeout(upload_timeout)
                .build()?,
        })
    }
}

impl DebugInfoManager for DebugInfoBackendRemote {
    #[instrument(level = "debug")]
    fn add_if_not_present(
        &self,
        name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()> {
        // TODO: add a local cache to not have to reach to the backend
        // unnecessarily.
        if self.find_in_backend(build_id)? {
            return Ok(());
        }

        // TODO: do this in another thread.
        self.upload_to_backend(name, build_id, debug_info)?;
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
    #[instrument]
    fn upload_to_backend(
        &self,
        name: &str,
        build_id: &BuildId,
        debug_info: &Path,
    ) -> anyhow::Result<()> {
        let mut request = self
            .upload_client
            .post(format!(
                "{}/debuginfo/new/{}/{}",
                self.server_url.clone(),
                name,
                build_id
            ))
            .body(File::open(debug_info)?);

        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }

        let response = request.send()?;

        if !response.status().is_success() {
            return Err(anyhow!("debuginfo upload failed with {:?}", response));
        }
        Ok(())
    }
}

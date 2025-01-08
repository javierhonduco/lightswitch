use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::StatusCode;
use tracing::instrument;

use lightswitch_object::BuildId;
use lightswitch_object::ExecutableId;

/// Handles with debug information.
///
/// This currently experimental, not feature-complete and not used yet during
/// symbolization. The end goal would be to keep track of every debug info
/// that's either present locally or remotely (depending on configuration), while
/// minimizing the number of open FDs, file copies, and race condition windows.
pub trait DebugInfoManager {
    fn add_if_not_present(
        &self,
        name: &str,
        build_id: &BuildId,
        executable_id: ExecutableId,
        file: &mut std::fs::File,
    ) -> anyhow::Result<()>;
    fn debug_info_path(&self) -> Option<PathBuf>;
}

pub struct DebugInfoBackendNull {}
impl DebugInfoManager for DebugInfoBackendNull {
    fn add_if_not_present(
        &self,
        _name: &str,
        _build_id: &BuildId,
        _executable_id: ExecutableId,
        _file: &mut std::fs::File,
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
        executable_id: ExecutableId,
        file: &mut std::fs::File,
    ) -> anyhow::Result<()> {
        // try to find, else extract
        if self.find_in_fs(build_id) {
            return Ok(());
        }

        self.add_to_fs(build_id, executable_id, file)
    }

    fn debug_info_path(&self) -> Option<PathBuf> {
        todo!()
    }
}

impl DebugInfoBackendFilesystem {
    fn find_in_fs(&self, build_id: &BuildId) -> bool {
        self.path.join(build_id.to_string()).exists()
    }

    fn add_to_fs(
        &self,
        build_id: &BuildId,
        _executable_id: ExecutableId,
        file: &mut std::fs::File,
    ) -> anyhow::Result<()> {
        // TODO: add support for other methods beyond copying. For example
        // hardlinks could be used and only fall back to copying if the src
        // and dst filesystems differ.
        let mut writer = std::fs::File::create(self.path.join(build_id.to_string()))?;
        std::io::copy(file, &mut writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DebugInfoBackendRemote {
    pub http_client_timeout: Duration,
    pub server_url: String,
}
impl DebugInfoManager for DebugInfoBackendRemote {
    #[instrument(level = "debug")]
    fn add_if_not_present(
        &self,
        name: &str,
        build_id: &BuildId,
        executable_id: ExecutableId,
        file: &mut std::fs::File,
    ) -> anyhow::Result<()> {
        // TODO: add a local cache to not have to reach to the backend
        // unnecessarily.
        if self.find_in_backend(build_id)? {
            return Ok(());
        }

        // TODO: do this in another thread.
        self.upload_to_backend(name, build_id, executable_id, file)?;
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
        let client_builder = reqwest::blocking::Client::builder().timeout(self.http_client_timeout);
        let client = client_builder.build()?;
        let response = client
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
        executable_id: ExecutableId,
        file: &mut std::fs::File,
    ) -> anyhow::Result<()> {
        let client_builder = reqwest::blocking::Client::builder().timeout(self.http_client_timeout);
        let client = client_builder.build()?;
        let mut debug_info = Vec::new();
        file.read_to_end(&mut debug_info)?;

        let response = client
            .post(format!(
                "{}/debuginfo/new/{}/{}/{}",
                self.server_url.clone(),
                name,
                build_id,
                executable_id
            ))
            .body(debug_info)
            .send()?;
        println!("wrote debug info to server {:?}", response);
        Ok(())
    }
}

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use reqwest::header::RETRY_AFTER;
use reqwest::StatusCode;
use tracing::{debug, instrument, warn};

use lightswitch_object::BuildId;

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

/// Upper bound on a server-provided `Retry-After`, so a bad value cannot stay
/// in the cache for a build ID for the rest of the agent's life.
const MAX_RETRY_AFTER_SECS: u32 = 3600;

/// What the backend told us about a build ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendQuery {
    /// The backend has it. Nothing to do.
    Present,
    /// The backend definitely does not have it. Upload.
    Absent,
    /// We do not know: the backend is shedding load, broken, or unreachable.
    /// Do *not* upload — a multi-megabyte POST chasing every failed query is
    /// how a slow backend can turn into a dead one.
    Unavailable { retry_after_secs: Option<u32> },
}

/// Map the response status of a debuginfo query onto what it tells us.
///
/// Only 404 is taken as a definitive "absent". A 401/403 would reject the
/// upload too, and an unrecognised status is not evidence of anything, so both
/// back off rather than uploading.
fn classify(status: StatusCode) -> BackendQuery {
    if status.is_success() {
        BackendQuery::Present
    } else if status == StatusCode::NOT_FOUND {
        BackendQuery::Absent
    } else {
        BackendQuery::Unavailable {
            retry_after_secs: None,
        }
    }
}

/// Parse a `Retry-After` header in delta-seconds form.
///
/// The HTTP-date form is not supported: it would need a date parser we do not
/// need anywhere else. An unparseable value simply means "no hint from the
/// server".
fn parse_retry_after(header: Option<&str>) -> Option<u32> {
    let secs = header?.trim().parse::<u32>().ok()?;
    Some(secs.min(MAX_RETRY_AFTER_SECS))
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
                .user_agent(NAME_AND_VERSION)
                .build()?,
            upload_client: reqwest::blocking::Client::builder()
                .timeout(upload_timeout)
                .user_agent(NAME_AND_VERSION)
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
        match self.find_in_backend(build_id) {
            BackendQuery::Present => Ok(()),
            BackendQuery::Unavailable { retry_after_secs } => {
                warn!(
                    "debuginfo backend did not answer for {}, skipping upload (retry-after: {:?})",
                    build_id, retry_after_secs
                );
                Ok(())
            }
            // TODO: do this in another thread.
            BackendQuery::Absent => self.upload_to_backend(name, build_id, debug_info),
        }
    }

    fn debug_info_path(&self) -> Option<PathBuf> {
        None
    }
}

impl DebugInfoBackendRemote {
    /// Whether the backend knows about some debug information.
    ///
    /// A transport error or a timeout is reported as
    /// [`BackendQuery::Unavailable`] rather than an error: not being able
    /// to ask is not conclusive evidence that the backend lacks the build ID.
    #[instrument(level = "debug")]
    fn find_in_backend(&self, build_id: &BuildId) -> BackendQuery {
        let response = self
            .query_client
            .get(format!(
                "{}/debuginfo/{}",
                self.server_url.clone(),
                build_id
            ))
            .send();

        let response = match response {
            Ok(response) => response,
            Err(e) => {
                debug!("debuginfo query for {} failed: {}", build_id, e);
                return BackendQuery::Unavailable {
                    retry_after_secs: None,
                };
            }
        };

        match classify(response.status()) {
            BackendQuery::Unavailable { .. } => BackendQuery::Unavailable {
                retry_after_secs: parse_retry_after(
                    response
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|value| value.to_str().ok()),
                ),
            },
            settled => settled,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    const UNAVAILABLE: BackendQuery = BackendQuery::Unavailable {
        retry_after_secs: None,
    };

    #[rstest]
    #[case(StatusCode::OK, BackendQuery::Present)]
    #[case(StatusCode::NO_CONTENT, BackendQuery::Present)]
    #[case(StatusCode::NOT_FOUND, BackendQuery::Absent)]
    // Not evidence of absence: uploading would fail too, or tell us nothing.
    #[case(StatusCode::BAD_REQUEST, UNAVAILABLE)]
    #[case(StatusCode::UNAUTHORIZED, UNAVAILABLE)]
    #[case(StatusCode::FORBIDDEN, UNAVAILABLE)]
    #[case(StatusCode::TOO_MANY_REQUESTS, UNAVAILABLE)]
    #[case(StatusCode::INTERNAL_SERVER_ERROR, UNAVAILABLE)]
    #[case(StatusCode::BAD_GATEWAY, UNAVAILABLE)]
    #[case(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE)]
    fn classify_maps_status_to_query(#[case] status: StatusCode, #[case] expected: BackendQuery) {
        assert_eq!(classify(status), expected);
    }

    #[rstest]
    #[case(None, None)]
    #[case(Some("30"), Some(30))]
    #[case(Some("  30  "), Some(30))]
    #[case(Some("0"), Some(0))]
    #[case(Some(""), None)]
    #[case(Some("garbage"), None)]
    #[case(Some("-5"), None)]
    #[case(Some("1.5"), None)]
    // The HTTP-date form is deliberately unsupported.
    #[case(Some("Wed, 21 Oct 2015 07:28:00 GMT"), None)]
    #[case(Some("99999999"), Some(MAX_RETRY_AFTER_SECS))]
    fn parse_retry_after_accepts_only_delta_seconds(
        #[case] header: Option<&str>,
        #[case] expected: Option<u32>,
    ) {
        assert_eq!(parse_retry_after(header), expected);
    }
}

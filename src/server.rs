use std::io;
use std::path::{Path, PathBuf};

use axum::Router;
use axum::http::HeaderValue;
use axum::response::Html;
use axum::routing::get;
use reqwest::Method;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
use uuid::Uuid;

const FIREFOX_PROFILER_URL: &str = "https://profiler.firefox.com";
const PERFETTO_UI_URL: &str = "https://ui.perfetto.dev";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileFileFormat {
    Firefox,
    Perfetto,
}

impl ProfileFileFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Firefox),
            "pftrace" | "perfetto-trace" => Some(Self::Perfetto),
            _ => None,
        }
    }

    pub fn default_profile_name(self) -> &'static str {
        match self {
            Self::Firefox => "firefox-profiler.json",
            Self::Perfetto => "profile.pftrace",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Firefox => 3000,
            // Perfetto's official local trace helper uses this CSP-compatible port.
            Self::Perfetto => 9001,
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Firefox => "application/json",
            Self::Perfetto => "application/octet-stream",
        }
    }

    fn cors_origin(self) -> &'static str {
        match self {
            Self::Firefox => FIREFOX_PROFILER_URL,
            Self::Perfetto => PERFETTO_UI_URL,
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Firefox => "profile.json",
            Self::Perfetto => "trace.pftrace",
        }
    }

    fn viewer_name(self) -> &'static str {
        match self {
            Self::Firefox => "Firefox Profiler",
            Self::Perfetto => "Perfetto UI",
        }
    }

    fn viewer_url(self, profile_url: &str) -> String {
        let profile_url = urlencoding::encode(profile_url);
        match self {
            Self::Firefox => format!("{FIREFOX_PROFILER_URL}/from-url/{profile_url}"),
            Self::Perfetto => format!("{PERFETTO_UI_URL}/#!/?url={profile_url}"),
        }
    }
}

pub fn find_default_profile(dir: &Path) -> io::Result<PathBuf> {
    let profiles = [ProfileFileFormat::Firefox, ProfileFileFormat::Perfetto]
        .into_iter()
        .map(|format| dir.join(format.default_profile_name()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();

    match profiles.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no default profile found; use --profile",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple default profiles found; use --profile",
        )),
    }
}

pub fn start_profile_server(
    port: u16,
    profile_path: PathBuf,
    format: ProfileFileFormat,
) -> io::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async_start_server(port, profile_path, format))
}

async fn async_start_server(
    port: u16,
    profile_path: PathBuf,
    format: ProfileFileFormat,
) -> io::Result<()> {
    let token = Uuid::new_v4();
    let profile_route = format!("/{token}/{}", format.file_name());
    let profile_url = format!("http://127.0.0.1:{port}{profile_route}");
    let viewer_url = format.viewer_url(&profile_url);
    let index = format!(
        "<a href='{viewer_url}'>Open profile in the {}</a>",
        format.viewer_name()
    );
    let content_type = format
        .content_type()
        .parse()
        .expect("profile content type is valid");
    let profile = ServeFile::new_with_mime(profile_path, &content_type);
    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_static(format.cors_origin()))
        .allow_methods([Method::GET]);

    let app = Router::new()
        .route(
            "/",
            get(move || {
                let index = index.clone();
                async move { Html(index) }
            }),
        )
        .route_service(&profile_route, profile)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn infers_supported_profile_extensions() {
        assert_eq!(
            ProfileFileFormat::from_path(Path::new("profile.json")),
            Some(ProfileFileFormat::Firefox)
        );
        assert_eq!(
            ProfileFileFormat::from_path(Path::new("profile.pftrace")),
            Some(ProfileFileFormat::Perfetto)
        );
        assert_eq!(ProfileFileFormat::from_path(Path::new("profile.pb")), None);
    }

    #[test]
    fn finds_one_default_profile() {
        let dir = tempdir().unwrap();
        let profile = dir.path().join("profile.pftrace");
        std::fs::write(&profile, []).unwrap();
        assert_eq!(find_default_profile(dir.path()).unwrap(), profile);
    }

    #[test]
    fn rejects_missing_or_ambiguous_default_profiles() {
        let dir = tempdir().unwrap();
        assert_eq!(
            find_default_profile(dir.path()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        std::fs::write(dir.path().join("profile.pftrace"), []).unwrap();
        std::fs::write(dir.path().join("firefox-profiler.json"), []).unwrap();
        assert_eq!(
            find_default_profile(dir.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn selects_content_type_from_format() {
        assert_eq!(
            ProfileFileFormat::Firefox.content_type(),
            "application/json"
        );
        assert_eq!(
            ProfileFileFormat::Perfetto.content_type(),
            "application/octet-stream"
        );
    }

    #[test]
    fn builds_viewer_urls() {
        let profile_url = "http://127.0.0.1:9001/token/trace.pftrace";
        assert_eq!(
            ProfileFileFormat::Perfetto.viewer_url(profile_url),
            "https://ui.perfetto.dev/#!/?url=http%3A%2F%2F127.0.0.1%3A9001%2Ftoken%2Ftrace.pftrace"
        );
        assert_eq!(
            ProfileFileFormat::Firefox.viewer_url(profile_url),
            "https://profiler.firefox.com/from-url/http%3A%2F%2F127.0.0.1%3A9001%2Ftoken%2Ftrace.pftrace"
        );
    }
}

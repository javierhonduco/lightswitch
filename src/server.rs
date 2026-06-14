use axum::http::HeaderValue;
use axum::{body::Body, http::Response};
use axum::{http::header, response::Html, routing::get, Router};
use reqwest::Method;
use std::{fs::File, io::Read};

const FIREFOX_PROFILER_URL: &str = "https://profiler.firefox.com";

pub fn start_server(port: u16) {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async_start_server(port));
}

async fn async_start_server(port: u16) {
    use tower_http::cors::*;

    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_static(FIREFOX_PROFILER_URL))
        .allow_methods([Method::GET]);

    let app = Router::new()
        .route(
            "/",
            get(async || {
                Html(format!(
                    "<a href='{}/from-url/{}'>Open profile in the Firefox Profiler UI</a>",
                    FIREFOX_PROFILER_URL,
                    urlencoding::encode("http://localhost:3000/profile.json")
                ))
            }),
        )
        .route(
            "/profile.json",
            get(async || {
                let mut file = File::open("firefox-profiler.json").unwrap();
                let mut ff_profile = Vec::new();
                file.read_to_end(&mut ff_profile).unwrap();
                let response = str::from_utf8(&ff_profile).unwrap().to_string();

                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(response))
                    .unwrap()
            }),
        )
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

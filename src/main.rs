use axum::{
    extract::OriginalUri,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use bytes::Bytes;
use http::StatusCode;
use std::{net::SocketAddr};
use tokio_rusqlite::Connection;
use tower::limit::concurrency::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;

mod aka;
use crate::aka::constants::*;

#[tokio::main]
async fn main() -> Result<(), rusqlite::Error> {
    let conn = Connection::open("sqlite.db").await?;

    let app = Router::new()
        .route("/", get(index).post(aka::create_aka))
        .route("/favicon.ico", get(get_icon))
        .route("/info/:aka", get(aka::redirect_info_aka))
        .route("/list/", get(aka::list))
        .route("/:aka", get(aka::redirect_aka))
        .fallback(handler_404)
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(CorsLayer::permissive())
        .with_state(conn);

    // run it
    println!("Version: {}", VERSION);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9952));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

pub async fn index() -> impl IntoResponse {
    (StatusCode::OK, Html(include_str!("../assets/index.html")))
}

pub async fn handler_404(OriginalUri(original_uri): OriginalUri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Html(format!("404 {} Not Found", original_uri)),
    )
}

#[axum_macros::debug_handler]
pub async fn get_icon() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::response::AppendHeaders([(axum::http::header::CONTENT_TYPE, "image/x-icon")]),
        Bytes::from_static(include_bytes!("../assets/favicon.ico")),
    )
}

use axum::{routing::get, Router};
use rusqlite;
use std::net::SocketAddr;
use tokio_rusqlite::Connection;
use tower::limit::concurrency::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;

mod aka;
use crate::aka::constants::*;
use crate::aka::{create_aka, get_icon, handler_404, index, list, redirect_aka, redirect_info_aka};

#[tokio::main]
async fn main() -> Result<(), rusqlite::Error> {

    let conn = Connection::open("sqlite.db").await?;

    let app = Router::new()
        .route("/", get(index).post(create_aka))
        .route("/favicon.ico", get(get_icon))
        .route("/info/:aka", get(redirect_info_aka))
        .route("/list/", get(list))
        .route("/:aka", get(redirect_aka))
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

use axum::{routing::get, Router};
use chrono::{DateTime, Duration, Utc};
use rusqlite;
use serde_derive::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio_rusqlite::Connection;
use tower::limit::concurrency::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;

mod aka;
use crate::aka::constants::*;
use crate::aka::{create_aka, get_icon, handler_404, index, list, redirect_aka, redirect_info_aka};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(dead_code)]
#[serde(default)]
struct Aka {
    id: u64,                   // int [pk, increment]
    created_at: DateTime<Utc>, // datetime new Date()
    expire_at: DateTime<Utc>,  // datetime NULL or 2 years
    user: String,              // text uuid
    r#in: String,              // text  aka s.enokai.net/{in}
    out: String,               // text to https://www.amazon.it/dp/0000000001
    key: String,               // text https://crates.io/crates/argon2
}

impl Default for Aka {
    fn default() -> Self {
        Aka {
            id: 0,
            created_at: Utc::now(),
            expire_at: Utc::now() + Duration::hours(DEFAULT_EXPIRE),
            user: "".to_string(),
            r#in: "".to_string(),
            out: "".to_string(),
            key: "".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(dead_code)]
#[serde(default)]
struct AkaInput {
    expire_hours: i64, // datetime NULL or 2 years
    user: String,      // text uuid
    r#in: String,      // text  aka s.enokai.net/{in}
    out: String,       // text to https://www.amazon.it/dp/0000000001
    key: String,       // text https://crates.io/crates/argon2
}

impl Default for AkaInput {
    fn default() -> Self {
        AkaInput {
            expire_hours: DEFAULT_EXPIRE as i64,
            user: "".to_string(),
            r#in: "".to_string(),
            out: "".to_string(),
            key: "".to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), rusqlite::Error> {
    //let bbb = Aka {
    //    id: 5,
    //    ..Aka::default()
    //};
    //println!("{:#?}", bbb);

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
    let addr = SocketAddr::from(([0, 0, 0, 0], 9952));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

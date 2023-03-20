use crate::aka::constants::*;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::extract::{OriginalUri, Path, State};
use axum::response::{IntoResponse, Redirect};
use axum::{extract, http::StatusCode, Json};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use http::uri::Uri;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use rusqlite::{params, Result};
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_rusqlite::Connection;
use urlencoding::decode;
pub mod constants;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[allow(dead_code)]
#[serde(default)]
pub struct Aka {
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
pub struct AkaInput {
    expire_hours: i64, // datetime NULL or 2 years
    user: String,      // text uuid
    r#in: String,      // text  aka s.enokai.net/{in}
    out: String,       // text to https://www.amazon.it/dp/0000000001
    key: String,       // text https://crates.io/crates/argon2
}

impl Default for AkaInput {
    fn default() -> Self {
        AkaInput {
            expire_hours: (DEFAULT_EXPIRE as i64),
            user: "".to_string(),
            r#in: "".to_string(),
            out: "".to_string(),
            key: "".to_string(),
        }
    }
}

/// Convert from a sqlite date value to a Rust DateTime<Utc> value
/// 
/// # Example
/// ```
/// # use chrono::{DateTime, Utc};
/// let datTime = sqlite_to_datetime("2023-03-19 20:00:33.124 UTC");
/// ```
pub fn sqlite_to_datetime(date: String) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(
        NaiveDateTime::parse_from_str(date.as_str(), "%Y-%m-%d %H:%M:%S%.f UTC").unwrap(),
        Utc,
    )
}

#[axum::debug_handler]
pub async fn list(State(conn): State<Connection>) -> impl IntoResponse {
    match conn
        .call(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, created_at, expire_at, user, \"in\", out, \"key\" FROM Aka")
                .unwrap();
            let people: Result<Vec<Aka>, rusqlite::Error> = stmt
                .query_map([], |row| {
                    Ok(Aka {
                        id: row.get(0).unwrap(),
                        created_at: sqlite_to_datetime(row.get(1)?),
                        expire_at: sqlite_to_datetime(row.get(2)?),
                        user: row.get(3)?,
                        r#in: row.get(4)?,
                        out: row.get(5)?,
                        key: row.get(6)?
                    })
                })
                .unwrap()
                .collect();
            people
        })
        .await
    {
        Ok(aka_list) => {
            if aka_list.is_empty() {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"message": "NO ROWS FOUND"})),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(serde_json::to_value(aka_list).unwrap()),
                )
            }
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
            "status": "error",
            "error": 500,
            "message": format!("500 {}", err),
            "v" : VERSION
            })),
        ),
    }
}

/// Find the link info (Aka) from an id key
/// 
/// # Example
/// ```rust
/// find_aka_link(&conn, "PSdBK");
/// ```
/// 
pub async fn find_aka_link(conn: &Connection, in_url: String) -> Result<Aka> {
    match conn
        .call(|conn| -> Result<Aka, rusqlite::Error> {
            conn.query_row(
               	"SELECT id, created_at, expire_at, user, \"in\", out, \"key\" FROM Aka WHERE \"in\" = ?1",
				[in_url],
				|row| Ok(Aka {
                      id: row.get(0).unwrap(),
                      created_at: sqlite_to_datetime(row.get(1)?),
                      expire_at: sqlite_to_datetime(row.get(2)?),
                      user: row.get(3)?,
                      r#in: row.get(4)?,
                      out: row.get(5)?,
                      key: row.get(6)?
				})
           	) as Result<Aka>
       	}).await {
         	Ok(res) => Ok(res),
         	Err(e) => Err(e),
       	}
}

pub fn default_error_response(e: rusqlite::Error) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "status": "error",
            "error": 500,
            "message": format!("500 {}", e),
            "v" : VERSION
        })),
    )
}

pub fn extract_aka_url(original_uri: Uri, path: String) -> Result<String> {
    let mut result = path;
    if original_uri.query().is_some() {
        result = format!("{}?{}", result, original_uri.query().unwrap());
    }
    result = result
        .strip_prefix('/')
        .unwrap_or(result.as_str())
        .to_string();

    Ok(decode(result.as_str()).expect("UTF-8").to_string())
}

#[axum::debug_handler]
pub async fn redirect_aka(
    State(conn): State<Connection>,
    Path(path): Path<String>,
    OriginalUri(original_uri): OriginalUri,
) -> impl IntoResponse {
    let uri = extract_aka_url(original_uri, path).unwrap();

    log::info!("{:?}", uri);
    match find_aka_link(&conn, uri).await {
        Ok(aka) => Redirect::temporary(aka.out.as_str()).into_response(),
        Err(e) => default_error_response(e).into_response(),
    }
}

pub async fn redirect_info_aka(
    State(conn): State<Connection>,
    Path(path): Path<String>,
    OriginalUri(original_uri): OriginalUri,
) -> impl IntoResponse {
    let uri = extract_aka_url(original_uri, path).unwrap();

    log::info!("{:?}", uri);
    match find_aka_link(&conn, uri).await {
        Ok(aka_list) => {
            let export_data =  json!({
                "in": aka_list.r#in,
                "out": aka_list.out
            });
            (StatusCode::OK, Json(export_data))
        },
        Err(e) => default_error_response(e),
    }
}

// let parsed_hash = PasswordHash::new(&password_hash)?;
// assert!(Argon2::default().verify_password(password, &parsed_hash).is_ok());
pub async fn random_available_url(conn: &Connection) -> String {
    let mut result: String = (0..5)
        .map(|_| rand::thread_rng().sample(Alphanumeric) as char)
        .collect();

    while find_aka_link(conn, result.to_string()).await.is_ok() {
        result = format!("{}{}", result, rand::thread_rng().sample(Alphanumeric));
    }
    result
}

/// Check for valid input short url and replace invalid chars?
pub fn check_in(in_url: &str) -> String {
    let uri_match = Regex::new(r"[ \.&\?=\[\]{},:\(\)$\*@\+\w\p{L}-]+").unwrap();
    uri_match.replace_all(in_url, "").to_string()
}

// 2394871
// 461509
/// Insert an Aka in the database given a POST Json request
/// # Example
/// ```http
/// POST http://localhost/ HTTP/1.1
/// Accept: */*
/// Content-Type: application/json
/// 
/// {
///   "user": "UUID",
///   "in": "",
///   "out": "https://example.com"
/// }
/// ```
#[axum::debug_handler]
pub async fn create_aka(
    State(conn): State<Connection>,
    extract::Json(data): extract::Json<Value>,
) -> impl IntoResponse {
    let aka_inp: AkaInput = serde_json::from_value(data).unwrap();

    let mut expire: i64 = DEFAULT_EXPIRE;
    let mut password_hash = "".to_string();
    if !aka_inp.key.is_empty() {
        expire = aka_inp.expire_hours;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        password_hash = argon2
            .hash_password(aka_inp.key.as_bytes(), &salt)
            .unwrap()
            .to_string();
    }
    let mut in_url = aka_inp.r#in;
    if in_url.is_empty() {
        in_url = random_available_url(&conn).await;
    }

    let invalid_characters = check_in(&in_url);
    if !invalid_characters.is_empty() {
        // Doesn't pass the required standard
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "did not pass the check",
                "invalid_characters": invalid_characters
            })),
        );
    }

    if aka_inp.out.is_empty() {
        // Doesn't pass the required standard
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "out url may not be empty"
            })),
        );
    }

    let user_aka = Aka {
        expire_at: Utc::now() + Duration::hours(expire),
        user: aka_inp.user,
        r#in: in_url,
        out: aka_inp.out,
        key: password_hash,
        ..Aka::default()
    };
    let user_aka_cp: Aka = user_aka.clone();
    match conn
        .call(move |conn| {
            conn.execute(
                "INSERT INTO Aka (created_at, expire_at, user, \"in\", out, \"key\") VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![user_aka.created_at.to_string(), user_aka.expire_at.to_string(), user_aka.user, user_aka.r#in, user_aka.out, user_aka.key],
            )
        })
        .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(user_aka_cp).unwrap()),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        ),
    }
}

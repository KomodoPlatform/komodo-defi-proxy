use captcha::{gen, Difficulty};
use chrono::{prelude::*, Duration};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Method, StatusCode};
use hyper::{Body, Request, Response, Server};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lazy_static::lazy_static;
use serde::Serialize;
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;

const TOKEN_ISSUER: &str = "ATOMICDEX-AUTH";

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    iat: usize,
    nbf: usize,
    exp: usize,
    iss: &'a str,
}

impl JwtClaims<'_> {
    fn new() -> Self {
        let current_time = Utc::now();
        let current_ts = current_time.timestamp() as usize;

        Self {
            iat: current_ts,
            nbf: current_ts,
            exp: (current_time + Duration::seconds(*AUTH_TOKEN_EXP)).timestamp() as usize,
            iss: TOKEN_ISSUER,
        }
    }
}

lazy_static! {
    static ref AUTH_ENCODING_KEY: EncodingKey = generate_encoding_key();
    static ref AUTH_TOKEN_EXP: i64 = env::var("AUTH_TOKEN_EXP")
        .unwrap_or(String::from("3600"))
        .parse::<i64>()
        .expect("Couldn't parse AUTH_TOKEN_EXP as i64");
}

fn initialize_global_definitions() {
    lazy_static::initialize(&AUTH_ENCODING_KEY);
    lazy_static::initialize(&AUTH_ENCODING_KEY);
}

fn generate_encoding_key() -> EncodingKey {
    let private_key_path = env::var("AUTH_PK_PATH").expect("AUTH_PK_PATH must be defined.");

    let mut file = File::open(private_key_path).unwrap();
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    EncodingKey::from_rsa_pem(&buffer).unwrap()
}

fn generate_captcha() -> (String, String) {
    let captcha = gen(Difficulty::Medium);
    (captcha.chars_as_string(), captcha.as_base64().unwrap())
}

async fn generate_auth_token() -> Result<Response<Body>> {
    let token = encode(
        &Header::new(Algorithm::RS256),
        &JwtClaims::new(),
        &AUTH_ENCODING_KEY,
    )?;

    let json = json!({
        "token": token,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap())
}

async fn api_healthcheck() -> Result<Response<Body>> {
    let json = json!({
        "status": "healthy",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json.to_string()))
        .unwrap())
}

async fn method_not_allowed() -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn router(req: Request<Body>, _remote_addr: SocketAddr) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => api_healthcheck().await,
        (&Method::GET, "/generate-token") => generate_auth_token().await,
        _ => method_not_allowed().await,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    initialize_global_definitions();

    let port = env::var("AUTH_API_PORT").unwrap_or_else(|_| 5000.to_string());
    let addr = format!("0.0.0.0:{}", port).parse().unwrap();

    let router = make_service_fn(|c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move { Ok::<_, GenericError>(service_fn(move |req| router(req, remote_addr))) }
    });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    server.await?;

    Ok(())
}

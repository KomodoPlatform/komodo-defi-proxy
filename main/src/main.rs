use captcha::{gen, Difficulty};
use chrono::{prelude::*, Duration};
use hyper::header::AUTHORIZATION;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, HeaderMap, Method, StatusCode};
use hyper::{Body, Request, Response, Server};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;

const TOKEN_ISSUER: &str = "ATOMICDEX-AUTH";

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iat: usize,
    nbf: usize,
    exp: usize,
    iss: String,
}

impl JwtClaims {
    fn new() -> Self {
        let current_time = Utc::now();
        let current_ts = current_time.timestamp() as usize;

        Self {
            iat: current_ts,
            nbf: current_ts,
            exp: (current_time + Duration::seconds(*AUTH_TOKEN_EXP)).timestamp() as usize,
            iss: TOKEN_ISSUER.to_string(),
        }
    }
}

lazy_static! {
    static ref AUTH_DECODING_KEY: DecodingKey = generate_decoding_key();
    static ref AUTH_ENCODING_KEY: EncodingKey = generate_encoding_key();
    static ref AUTH_TOKEN_EXP: i64 = env::var("AUTH_TOKEN_EXP")
        .unwrap_or(String::from("3600"))
        .parse::<i64>()
        .expect("Couldn't parse AUTH_TOKEN_EXP as i64");
    static ref REDIS_CLIENT: redis::Client = connect_to_redis();
}

fn initialize_global_definitions() {
    lazy_static::initialize(&AUTH_ENCODING_KEY);
    lazy_static::initialize(&AUTH_DECODING_KEY);
    lazy_static::initialize(&AUTH_TOKEN_EXP);
    lazy_static::initialize(&REDIS_CLIENT);
}

fn read_file_buffer(path: &str) -> Vec<u8> {
    let mut file = File::open(path).expect(&format!("Couldn't open {}", path));
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer)
        .expect(&format!("Couldn't read {}", path));

    buffer
}

fn connect_to_redis() -> redis::Client {
    let cs = env::var("REDIS_CONNECTION_STRING").expect("REDIS_CONNECTION_STRING must be defined.");
    redis::Client::open(cs).expect("Couldn't connect to redis server.")
}

fn generate_decoding_key() -> DecodingKey {
    let public_key_path =
        env::var("AUTH_PUB_KEY_PATH").expect("AUTH_PUB_KEY_PATH must be defined.");
    let buffer = read_file_buffer(&public_key_path);
    DecodingKey::from_rsa_pem(&buffer).unwrap()
}

fn generate_encoding_key() -> EncodingKey {
    let private_key_path =
        env::var("AUTH_PRIV_KEY_PATH").expect("AUTH_PRIV_KEY_PATH must be defined.");
    let buffer = read_file_buffer(&private_key_path);
    EncodingKey::from_rsa_pem(&buffer).unwrap()
}

fn generate_captcha() -> (String, String) {
    let captcha = gen(Difficulty::Medium);
    (captcha.chars_as_string(), captcha.as_base64().unwrap())
}

fn parse_token_from_header(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers.get(AUTHORIZATION) {
        if token.is_empty() {
            return None;
        }

        if let Ok(token_str) = token.to_str() {
            return token_str.split_whitespace().last().map(|t| t.to_string());
        }
    }

    None
}

async fn get_redis_connection() -> MultiplexedConnection {
    REDIS_CLIENT
        .get_multiplexed_tokio_connection()
        .await
        .expect("Couldn't get connection from redis client.")
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

async fn validate_auth_token<'a>(req: Request<Body>) -> Result<Response<Body>> {
    if let Some(token) = parse_token_from_header(req.headers()) {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[TOKEN_ISSUER]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;

        if let Err(_) = decode::<JwtClaims>(&token, &AUTH_DECODING_KEY, &validation) {
            return response_by_status(StatusCode::UNAUTHORIZED);
        }

        return response_by_status(StatusCode::NO_CONTENT);
    }

    response_by_status(StatusCode::UNAUTHORIZED)
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
    response_by_status(StatusCode::METHOD_NOT_ALLOWED)
}

fn response_by_status(status: StatusCode) -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::from(Vec::new()))
        .unwrap())
}

async fn can_continue(ip_addr: String, r_connection: &mut MultiplexedConnection) -> bool {
    // TODO
    // implement the rate-limiting algorithm

    // match redis::cmd("SET")
    //     .arg(&ip_addr)
    //     .arg("")
    //     .query_async(r_connection)
    //     .await
    // {
    //     Ok(t) => t,
    //     Err(e) => println!("Failed writing {} into redis. {}", ip_addr, e),
    // };

    true
}

async fn router(
    req: Request<Body>,
    _remote_addr: SocketAddr,
    _r_connection: MultiplexedConnection,
) -> Result<Response<Body>> {
    // TODO
    // use and handle fn can_continue()

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => api_healthcheck().await,
        (&Method::GET, "/generate-token") => generate_auth_token().await,
        (&Method::GET, "/validate-token") => validate_auth_token(req).await,
        _ => method_not_allowed().await,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    initialize_global_definitions();

    let port = env::var("AUTH_API_PORT").unwrap_or_else(|_| 5000.to_string());
    let addr = format!("0.0.0.0:{}", port).parse().unwrap();

    let router = make_service_fn(move |c_stream: &AddrStream| {
        let remote_addr = c_stream.remote_addr();
        async move {
            let r_connection = get_redis_connection().await;
            Ok::<_, GenericError>(service_fn(move |req| {
                router(req, remote_addr, r_connection.clone())
            }))
        }
    });

    let server = Server::bind(&addr).serve(router);

    println!("AtomicDEX Auth API serving on http://{}", addr);

    server.await?;

    Ok(())
}

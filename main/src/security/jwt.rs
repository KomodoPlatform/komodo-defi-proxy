use super::*;

use ctx::AppConfig;
use jsonwebtoken::*;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

const TOKEN_ISSUER: &str = "ATOMICDEX-AUTH";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct JwtClaims {
    iat: u64,
    nbf: u64,
    exp: u64,
    iss: String,
}

impl JwtClaims {
    pub(crate) fn new(expiration: i64) -> Self {
        let current_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            iat: current_ts,
            nbf: current_ts,
            exp: current_ts + expiration as u64,
            iss: TOKEN_ISSUER.to_string(),
        }
    }
}

static AUTH_DECODING_KEY: OnceCell<DecodingKey> = OnceCell::new();
#[allow(dead_code)]
pub(crate) fn get_decoding_key(cfg: &AppConfig) -> &'static DecodingKey {
    let buffer_closure = || -> Vec<u8> { read_file_buffer(&cfg.pubkey_path) };

    AUTH_DECODING_KEY.get_or_init(|| {
        DecodingKey::from_rsa_pem(&buffer_closure()).expect("Error decoding public key")
    })
}

static AUTH_ENCODING_KEY: OnceCell<EncodingKey> = OnceCell::new();
pub(crate) fn get_encoding_key(cfg: &AppConfig) -> &'static EncodingKey {
    let buffer_closure = || -> Vec<u8> { read_file_buffer(&cfg.privkey_path) };

    AUTH_ENCODING_KEY.get_or_init(|| {
        EncodingKey::from_rsa_pem(&buffer_closure()).expect("Error encoding private key")
    })
}

fn read_file_buffer(path: &str) -> Vec<u8> {
    let mut file = File::open(path).unwrap_or_else(|_| panic!("Couldn't open {}", path));
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read {}", path));

    buffer
}

pub(crate) async fn generate_jwt(cfg: &AppConfig, claims: &JwtClaims) -> GenericResult<String> {
    Ok(encode(
        &Header::new(Algorithm::RS256),
        claims,
        get_encoding_key(cfg),
    )?)
}

pub(crate) async fn get_cached_token_or_generate_one(
    cfg: &AppConfig,
    claims: &JwtClaims,
) -> GenericResult<String> {
    let mut conn = get_redis_connection(cfg).await;

    let db_result: Option<String> = redis::cmd("GET")
        .arg("jwt-token")
        .query_async(&mut conn)
        .await?;

    match db_result {
        Some(token) => Ok(token),
        None => Ok(generate_jwt_and_cache_it(cfg, claims).await?),
    }
}

pub(crate) async fn generate_jwt_and_cache_it(
    cfg: &AppConfig,
    claims: &JwtClaims,
) -> GenericResult<String> {
    let token = generate_jwt(cfg, claims).await?;

    let mut conn = get_redis_connection(cfg).await;
    redis::cmd("SET")
        .arg(&["jwt-token", &token])
        .arg("EX")
        .arg(cfg.token_expiration_time() - 60) // expire 60 seconds before token's expiration
        .arg("NX")
        .query_async(&mut conn)
        .await?;

    Ok(token)
}

#[allow(dead_code)]
async fn validate_jwt(cfg: &AppConfig, token: String) -> bool {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 0;

    if decode::<JwtClaims>(&token, get_decoding_key(cfg), &validation).is_err() {
        return false;
    }

    true
}

#[test]
fn test_jwt_constants() {
    assert_eq!(TOKEN_ISSUER, "ATOMICDEX-AUTH");
}

#[test]
fn test_jwt_claims_serialzation_and_deserialization() {
    let json_jwt_claims = serde_json::json!({
        "iat": 0,
        "nbf": 0,
        "exp": 0,
        "iss": TOKEN_ISSUER.to_string()
    });

    let actual_jwt_claims: JwtClaims = serde_json::from_str(&json_jwt_claims.to_string()).unwrap();

    let expected_jwt_claims = JwtClaims {
        iat: 0,
        nbf: 0,
        exp: 0,
        iss: TOKEN_ISSUER.to_string(),
    };

    assert_eq!(actual_jwt_claims, expected_jwt_claims);

    // Backwards
    let json = serde_json::to_value(expected_jwt_claims).unwrap();
    assert_eq!(json_jwt_claims, json);
    assert_eq!(json_jwt_claims.to_string(), json.to_string());
}

#[tokio::test]
async fn test_read_file_buffer() {
    let bytes = read_file_buffer("../assets/.io_test");

    #[cfg(not(target_os = "windows"))]
    assert_eq!(
        bytes,
        [
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            10, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115,
            115, 115, 115, 115, 10, 10, 10, 32, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
            50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 10, 10, 10, 9, 9, 9, 10, 10,
            10, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 10
        ]
    );

    #[cfg(target_os = "windows")]
    assert_eq!(
        bytes,
        [
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            13, 10, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
            97, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115, 115,
            115, 115, 115, 115, 115, 13, 10, 13, 10, 13, 10, 32, 50, 50, 50, 50, 50, 50, 50, 50,
            50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 13, 10, 13,
            10, 13, 10, 9, 9, 9, 13, 10, 13, 10, 13, 10, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 13, 10
        ]
    );
}

#[tokio::test]
async fn test_generate_jwt() {
    let mut cfg = ctx::get_app_config_test_instance();
    cfg.privkey_path = String::from("../assets/.privkey_test");
    cfg.pubkey_path = String::from("../assets/.pubkey_test");

    let buffer = read_file_buffer(&cfg.privkey_path);
    AUTH_ENCODING_KEY.get_or_init(|| EncodingKey::from_rsa_pem(&buffer).unwrap());

    let buffer = read_file_buffer(&cfg.pubkey_path);
    AUTH_DECODING_KEY.get_or_init(|| DecodingKey::from_rsa_pem(&buffer).unwrap());

    // Test if generate_jwt works as expected
    let claims = JwtClaims {
        iat: u64::default(),
        nbf: u64::default(),
        exp: cfg.token_expiration_time() as u64,
        iss: String::from(TOKEN_ISSUER),
    };

    let token = generate_jwt(&cfg, &claims).await.unwrap();
    let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsIm5iZiI6MCwiZXhwIjozMDAsImlzcyI6IkFUT01JQ0RFWC1BVVRIIn0.Ro-wPvS0U5F5IlgyaY1-R9mgPQWLInSrVGXyKBULVvfzshib2ENef3GJRDYdp8raSs4y4y3FMbuv1bz7si08ayfOo1UgLNR1JqN831yMJdHzvSXIl7Ej-hykRDndobXxzWxjavdCNxu9zVWFvnHn5FFMj42PYjIZ34CXuMelQE99TnlfJYxPzelywRzwp_OKPQoadRgYjQJyCcACiueVm1n0CkT_SzxDfkKmQNc6J_IqAZvkBqL5g1qMSbz9o0YmTIkVI-_izP9v92Zir9Qrmdm9RN8QoGTgs7CXjUkUVs5I1OuqjvIHsSPA4Wu5cxMmWmf63Rgingw6CKni4VELBA";
    assert_eq!(token, expected_token);

    // Test if validate_jwt works as expected
    let claims = JwtClaims::new(cfg.token_expiration_time());
    let token = generate_jwt(&cfg, &claims).await.unwrap();
    assert!(validate_jwt(&cfg, String::from(token)).await);
}

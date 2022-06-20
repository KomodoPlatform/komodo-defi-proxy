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
    assert_eq!(
        bytes,
        [
            76, 111, 114, 101, 109, 32, 73, 112, 115, 117, 109, 32, 105, 115, 32, 115, 105, 109,
            112, 108, 121, 32, 100, 117, 109, 109, 121, 32, 116, 101, 120, 116, 32, 111, 102, 32,
            116, 104, 101, 32, 112, 114, 105, 110, 116, 105, 110, 103, 32, 97, 110, 100, 32, 116,
            121, 112, 101, 115, 101, 116, 116, 105, 110, 103, 32, 105, 110, 100, 117, 115, 116,
            114, 121, 46, 32, 76, 111, 114, 101, 109, 32, 73, 112, 115, 117, 109, 32, 104, 97, 115,
            32, 98, 101, 101, 110, 32, 116, 104, 101, 32, 105, 110, 100, 117, 115, 116, 114, 121,
            39, 115, 32, 115, 116, 97, 110, 100, 97, 114, 100, 32, 100, 117, 109, 109, 121, 32,
            116, 101, 120, 116, 32, 101, 118, 101, 114, 32, 115, 105, 110, 99, 101, 32, 116, 104,
            101, 32, 49, 53, 48, 48, 115, 44, 32, 119, 104, 101, 110, 32, 97, 110, 32, 117, 110,
            107, 110, 111, 119, 110, 32, 112, 114, 105, 110, 116, 101, 114, 32, 116, 111, 111, 107,
            32, 97, 32, 103, 97, 108, 108, 101, 121, 32, 111, 102, 32, 116, 121, 112, 101, 32, 97,
            110, 100, 32, 115, 99, 114, 97, 109, 98, 108, 101, 100, 32, 105, 116, 32, 116, 111, 32,
            109, 97, 107, 101, 32, 97, 32, 116, 121, 112, 101, 32, 115, 112, 101, 99, 105, 109,
            101, 110, 32, 98, 111, 111, 107, 46, 10
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
        exp: cfg.token_expiration_time.unwrap() as u64,
        iss: String::from(TOKEN_ISSUER),
    };

    let token = generate_jwt(&cfg, &claims).await.unwrap();
    let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjAsIm5iZiI6MCwiZXhwIjozMDAsImlzcyI6IkFUT01JQ0RFWC1BVVRIIn0.Ro-wPvS0U5F5IlgyaY1-R9mgPQWLInSrVGXyKBULVvfzshib2ENef3GJRDYdp8raSs4y4y3FMbuv1bz7si08ayfOo1UgLNR1JqN831yMJdHzvSXIl7Ej-hykRDndobXxzWxjavdCNxu9zVWFvnHn5FFMj42PYjIZ34CXuMelQE99TnlfJYxPzelywRzwp_OKPQoadRgYjQJyCcACiueVm1n0CkT_SzxDfkKmQNc6J_IqAZvkBqL5g1qMSbz9o0YmTIkVI-_izP9v92Zir9Qrmdm9RN8QoGTgs7CXjUkUVs5I1OuqjvIHsSPA4Wu5cxMmWmf63Rgingw6CKni4VELBA";
    assert_eq!(token, expected_token);

    // Test if validate_jwt works as expected
    let claims = JwtClaims::new(cfg.token_expiration_time.unwrap());
    let token = generate_jwt(&cfg, &claims).await.unwrap();
    assert!(validate_jwt(&cfg, String::from(token)).await);
}

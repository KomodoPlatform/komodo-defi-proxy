use super::*;
use chrono::{Duration, Utc};
use ctx::get_app_config;
use jsonwebtoken::*;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read};

const TOKEN_ISSUER: &str = "ATOMICDEX-AUTH";

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iat: usize,
    nbf: usize,
    exp: usize,
    iss: String,
}

impl JwtClaims {
    fn new(expiration: i64) -> Self {
        let current_time = Utc::now();
        let current_ts = current_time.timestamp() as usize;

        Self {
            iat: current_ts,
            nbf: current_ts,
            exp: (current_time + Duration::seconds(expiration)).timestamp() as usize,
            iss: TOKEN_ISSUER.to_string(),
        }
    }
}

static AUTH_DECODING_KEY: OnceCell<DecodingKey> = OnceCell::new();
#[allow(dead_code)]
pub fn get_decoding_key() -> &'static DecodingKey {
    let config = get_app_config();

    let buffer = read_file_buffer(&config.pubkey_path);

    AUTH_DECODING_KEY
        .get_or_init(|| DecodingKey::from_rsa_pem(&buffer).expect("Error decoding public key"))
}

static AUTH_ENCODING_KEY: OnceCell<EncodingKey> = OnceCell::new();
pub fn get_encoding_key() -> &'static EncodingKey {
    let config = get_app_config();

    let buffer = read_file_buffer(&config.privkey_path);

    AUTH_ENCODING_KEY
        .get_or_init(|| EncodingKey::from_rsa_pem(&buffer).expect("Error encoding private key"))
}

fn read_file_buffer(path: &str) -> Vec<u8> {
    let mut file = File::open(path).unwrap_or_else(|_| panic!("Couldn't open {}", path));
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read {}", path));

    buffer
}

pub async fn generate_jwt() -> GenericResult<String> {
    let config = get_app_config();

    Ok(encode(
        &Header::new(Algorithm::RS256),
        &JwtClaims::new(config.token_expiration_time.unwrap_or(3600)),
        get_encoding_key(),
    )?)
}

#[allow(dead_code)]
async fn validate_jwt(token: String) -> bool {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 0;

    if decode::<JwtClaims>(&token, get_decoding_key(), &validation).is_err() {
        return false;
    }

    true
}

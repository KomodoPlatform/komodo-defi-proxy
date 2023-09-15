use super::*;

use bitcrypto::keccak256;
use core::{convert::From, str::FromStr};
use ethereum_types::{Address, H256};
use ethkey::{sign, verify_address, Secret, Signature};
use serde::{Deserialize, Serialize};
use serialization::{CompactInteger, Serializable, Stream};
use sha3::{Digest, Keccak256};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) trait SignOps {
    fn sign_message_hash(&self) -> [u8; 32];
    fn checksum_address(&self) -> String;
    fn is_valid_checksum_addr(&self) -> bool;
    fn valid_addr_from_str(&self) -> Result<Address, String>;
    fn addr_from_str(&self) -> Result<Address, String>;
    fn sign_message(&mut self, secret: &Secret) -> GenericResult<()>;
    fn verify_message(&self) -> GenericResult<bool>;
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct SignedMessage {
    pub(crate) coin_ticker: String,
    pub(crate) address: String,
    pub(crate) timestamp_message: u64,
    pub(crate) signature: String,
}

impl SignOps for SignedMessage {
    fn sign_message_hash(&self) -> [u8; 32] {
        let prefix = "atomicDEX Auth Ethereum Signed Message:\n";
        let mut stream = Stream::new();
        let prefix_len = CompactInteger::from(prefix.len());
        prefix_len.serialize(&mut stream);
        stream.append_slice(prefix.as_bytes());
        stream.append_slice(
            self.timestamp_message
                .to_string()
                .len()
                .to_string()
                .as_bytes(),
        );
        stream.append_slice(self.timestamp_message.to_string().as_bytes());
        keccak256(&stream.out()).take()
    }

    /// Displays the address in mixed-case checksum form
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
    fn checksum_address(&self) -> String {
        let mut addr = self.address.to_lowercase();
        if addr.starts_with("0x") {
            addr.replace_range(..2, "");
        }

        let mut hasher = Keccak256::default();
        hasher.update(&addr);
        let hash = hasher.finalize();
        let mut result: String = "0x".into();
        for (i, c) in addr.chars().enumerate() {
            if c.is_digit(10) {
                result.push(c);
            } else {
                // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md#specification
                // Convert the address to hex, but if the ith digit is a letter (ie. it's one of abcdef)
                // print it in uppercase if the 4*ith bit of the hash of the lowercase hexadecimal
                // address is 1 otherwise print it in lowercase.
                if hash[i / 2] & (1 << (7 - 4 * (i % 2))) != 0 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            }
        }

        result
    }

    fn is_valid_checksum_addr(&self) -> bool {
        self.address == self.checksum_address()
    }

    fn valid_addr_from_str(&self) -> Result<Address, String> {
        let addr = self.addr_from_str()?;
        if !self.is_valid_checksum_addr() {
            return Err(String::from("Invalid address checksum"));
        }
        Ok(addr)
    }

    fn addr_from_str(&self) -> Result<Address, String> {
        if !self.address.starts_with("0x") {
            return Err(String::from("Address must be prefixed with 0x"));
        };

        Address::from_str(&self.address[2..]).map_err(|e| e.to_string())
    }

    fn sign_message(&mut self, secret: &Secret) -> GenericResult<()> {
        let signature = sign(secret, &H256::from(self.sign_message_hash()))?;
        self.signature = format!("0x{}", signature);

        Ok(())
    }

    fn verify_message(&self) -> GenericResult<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now > self.timestamp_message {
            return Ok(false);
        }

        let message_hash = self.sign_message_hash();
        let address = self.valid_addr_from_str()?;

        let signature =
            Signature::from_str(self.signature.strip_prefix("0x").unwrap_or(&self.signature))?;

        Ok(verify_address(
            &address,
            &signature,
            &H256::from(message_hash),
        )?)
    }
}

#[test]
fn test_signed_message_serialzation_and_deserialization() {
    let json_signed_message = serde_json::json!({
        "address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "timestamp_message": 0,
        "signature": "",
        "coin_ticker": "ETH"
    });

    let actual_signed_message: SignedMessage =
        serde_json::from_str(&json_signed_message.to_string()).unwrap();

    let expected_signed_message = SignedMessage {
        address: String::from("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        timestamp_message: u64::default(),
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };

    assert_eq!(actual_signed_message, expected_signed_message);

    // Backwards
    let json = serde_json::to_value(expected_signed_message).unwrap();
    assert_eq!(json_signed_message, json);
    assert_eq!(json_signed_message.to_string(), json.to_string());
}

#[test]
fn test_sign_message_hash() {
    let mut signed_message = SignedMessage {
        address: String::from("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        timestamp_message: u64::default(),
        signature: String::default(),
        coin_ticker: String::from("ETH"),
    };

    let msg = signed_message.sign_message_hash();
    assert_eq!(
        msg,
        [
            58, 69, 48, 53, 234, 107, 112, 243, 143, 137, 89, 208, 73, 115, 136, 31, 254, 255, 243,
            123, 197, 144, 241, 223, 80, 91, 195, 194, 192, 86, 180, 33
        ]
    );

    signed_message.timestamp_message = 1655376657;
    let msg = signed_message.sign_message_hash();
    assert_eq!(
        msg,
        [
            178, 222, 11, 225, 166, 231, 156, 50, 173, 22, 122, 90, 196, 182, 121, 168, 218, 27, 4,
            223, 95, 245, 64, 131, 181, 196, 108, 220, 13, 219, 36, 94
        ]
    );

    signed_message.coin_ticker = String::default();
    let msg = signed_message.sign_message_hash();
    assert_eq!(
        msg,
        [
            178, 222, 11, 225, 166, 231, 156, 50, 173, 22, 122, 90, 196, 182, 121, 168, 218, 27, 4,
            223, 95, 245, 64, 131, 181, 196, 108, 220, 13, 219, 36, 94
        ]
    );
}

#[test]
fn test_checksum_addr() {
    let mut signed_message = SignedMessage {
        address: String::from("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        timestamp_message: u64::default(),
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };

    assert_eq!(
        signed_message.checksum_address(),
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    );

    signed_message.address = String::from("0x52908400098527886E0F7030069857D2E4169EE7");
    assert_eq!(
        signed_message.checksum_address(),
        "0x52908400098527886E0F7030069857D2E4169EE7"
    );

    signed_message.address = String::from("0x8617e340b3d01fa5f11f306f4090fd50e238070d");
    assert_eq!(
        signed_message.checksum_address(),
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
    );

    signed_message.address = String::from("0xde709f2102306220921060314715629080e2fb77");
    assert_eq!(
        signed_message.checksum_address(),
        "0xde709f2102306220921060314715629080e2fb77"
    );

    signed_message.address = String::from("0x27b1fdb04752bbc536007a920d24acb045561c26");
    assert_eq!(
        signed_message.checksum_address(),
        "0x27b1fdb04752bbc536007a920d24acb045561c26"
    );

    signed_message.address = String::from("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    assert_eq!(
        signed_message.checksum_address(),
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
}

#[test]
fn test_is_valid_checksum_addr() {
    let mut signed_message = SignedMessage {
        address: String::from("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        timestamp_message: u64::default(),
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };
    assert!(signed_message.is_valid_checksum_addr());

    signed_message.address = String::from("0x52908400098527886E0F7030069857D2E4169EE7");
    assert!(signed_message.is_valid_checksum_addr());

    signed_message.address = String::from("0x8617e340B3D01FA5F11F306F4090FD50E238070D");
    assert!(!signed_message.is_valid_checksum_addr());

    signed_message.address = String::from("0xd1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
    assert!(!signed_message.is_valid_checksum_addr());
}

#[test]
fn test_addr_from_str_and_valid_addr_from_str() {
    let mut signed_message = SignedMessage {
        address: String::from("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        timestamp_message: u64::default(),
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };
    signed_message.addr_from_str().unwrap();
    signed_message.valid_addr_from_str().unwrap();

    signed_message.address = String::from("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
    signed_message.addr_from_str().unwrap();
    signed_message.valid_addr_from_str().unwrap();

    signed_message.address = String::from("0x52908400098527886E0F7030069857D2E4169EE7");
    signed_message.addr_from_str().unwrap();
    signed_message.valid_addr_from_str().unwrap();

    signed_message.address = String::from("0x709f2102306220921060314715629080e2fb77");
    signed_message.addr_from_str().unwrap_err();
    signed_message.valid_addr_from_str().unwrap_err();

    signed_message.address = String::from("0x27b1fdb04752bbc536007a920d2");
    signed_message.addr_from_str().unwrap_err();
    signed_message.valid_addr_from_str().unwrap_err();

    signed_message.address = String::from("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    signed_message.addr_from_str().unwrap_err();
    signed_message.valid_addr_from_str().unwrap_err();
}

#[test]
fn test_message_sign_and_verify() {
    let timestamp_message = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut signed_message = SignedMessage {
        address: String::from("0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29"),
        timestamp_message: timestamp_message - 5 * 60,
        signature: String::new(),
        coin_ticker: String::from("ETH"),
    };

    let key_pair = ethkey::KeyPair::from_secret_slice(
        &hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap(),
    )
    .unwrap();

    signed_message.sign_message(key_pair.secret()).unwrap();
    assert!(!signed_message.verify_message().unwrap());

    signed_message.timestamp_message = timestamp_message + 5 * 60;
    signed_message.sign_message(key_pair.secret()).unwrap();
    assert!(signed_message.verify_message().unwrap());
}

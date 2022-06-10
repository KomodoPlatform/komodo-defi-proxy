use super::*;
use bitcrypto::keccak256;
use chrono::{DateTime, Utc};
use core::{convert::From, str::FromStr};
use ethereum_types::{Address, H256};
use ethkey::{verify_address, Signature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

const VALIDATION_DATE_FORMAT: &str = "%Y-%m-%d %H:%M:%S %z";

pub trait SignOps {
    fn sign_message_hash(&self) -> [u8; 32];
    fn checksum_address(&self) -> String;
    fn is_valid_checksum_addr(&self) -> bool;
    fn valid_addr_from_str(&self) -> Result<Address, String>;
    fn addr_from_str(&self) -> Result<Address, String>;
    fn verify_message(&self) -> GenericResult<bool>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    pub address: String,
    pub message: String,
    pub signature: String,
    pub valid_until: String,
}

impl SignOps for SignedMessage {
    fn sign_message_hash(&self) -> [u8; 32] {
        *keccak256(
            format!(
                "{}{}{}",
                "\x19Ethereum Signed Message:\n",
                self.message.len(),
                self.message
            )
            .as_bytes(),
        )
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

    fn verify_message(&self) -> GenericResult<bool> {
        let now = Utc::now();
        let valid_until = DateTime::parse_from_str(&self.valid_until, VALIDATION_DATE_FORMAT)?;

        if now > valid_until {
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
fn test_message_verification() {
    let valid_until = Utc::now() + chrono::Duration::minutes(5);
    let message = SignedMessage {
        address: String::from("0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29"),
        message: String::from("test"),
        signature: String::from("0xcdf11a9c4591fb7334daa4b21494a2590d3f7de41c7d2b333a5b61ca59da9b311b492374cc0ba4fbae53933260fa4b1c18f15d95b694629a7b0620eec77a938600"),
        valid_until: valid_until.format(VALIDATION_DATE_FORMAT).to_string(),
    };

    assert_eq!(message.verify_message().unwrap(), true);
}

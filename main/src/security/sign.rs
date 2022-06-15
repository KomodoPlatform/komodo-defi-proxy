use super::*;
use bitcrypto::keccak256;
use core::{convert::From, str::FromStr};
use ethereum_types::{Address, H256};
use ethkey::{sign, verify_address, Secret, Signature};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SignedMessage {
    pub(crate) address: String,
    pub(crate) timestamp_message: u64,
    pub(crate) signature: String,
}

impl SignOps for SignedMessage {
    fn sign_message_hash(&self) -> [u8; 32] {
        *keccak256(
            format!(
                "{}{}{}",
                "\x19aDEX Auth Ethereum Signed Message:\n",
                self.timestamp_message.to_string().len(),
                self.timestamp_message
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
fn test_message_sign_and_verify() {
    let timestamp_message = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5 * 60;

    let mut signed_message = SignedMessage {
        address: String::from("0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29"),
        timestamp_message,
        signature: String::new(),
    };

    let key_pair = ethkey::KeyPair::from_secret_slice(
        &hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap(),
    )
    .unwrap();

    signed_message.sign_message(&key_pair.secret()).unwrap();

    assert_eq!(signed_message.verify_message().unwrap(), true);
}

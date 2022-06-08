use crate::crypto::keccak256;
use core::{convert::From, str::FromStr};
use ethereum_types::{Address, H256};
use ethkey::{verify_address, Signature};
use gstuff::{try_s, ERR, ERRL};

use serialization::{CompactInteger, Serializable, Stream};
use sha3::{Digest, Keccak256};

pub fn sign_message_hash(message: &str) -> Option<[u8; 32]> {
    let message_prefix = "test-prefix";
    let mut stream = Stream::new();
    let prefix_len = CompactInteger::from(message_prefix.len());
    prefix_len.serialize(&mut stream);
    stream.append_slice(message_prefix.as_bytes());
    stream.append_slice(message.len().to_string().as_bytes());
    stream.append_slice(message.as_bytes());
    Some(keccak256(&stream.out()).take())
}

/// Displays the address in mixed-case checksum form
/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
fn checksum_address(addr: &str) -> String {
    let mut addr = addr.to_lowercase();
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

fn is_valid_checksum_addr(addr: &str) -> bool {
    addr == checksum_address(addr)
}

fn valid_addr_from_str(addr_str: &str) -> Result<Address, String> {
    let addr = try_s!(addr_from_str(addr_str));
    if !is_valid_checksum_addr(addr_str) {
        return ERR!("Invalid address checksum");
    }
    Ok(addr)
}

pub fn addr_from_str(addr_str: &str) -> Result<Address, String> {
    if !addr_str.starts_with("0x") {
        return ERR!("Address must be prefixed with 0x");
    };

    Ok(try_s!(Address::from_str(&addr_str[2..])))
}

fn verify_message(signature: &str, message: &str, address: &str) -> bool {
    let message_hash = sign_message_hash(message).unwrap();
    let address = valid_addr_from_str(address).unwrap();

    let signature = Signature::from_str(signature.strip_prefix("0x").unwrap_or(signature)).unwrap();
    let is_verified = verify_address(&address, &signature, &H256::from(message_hash)).unwrap();

    is_verified
}

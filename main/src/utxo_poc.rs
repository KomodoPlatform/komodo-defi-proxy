use bitcrypto::dhash256;
use keys::{CompactSignature, Public, Address};
use primitives::hash::H256;
use serialization::{CompactInteger, Serializable, Stream};

/// Hash message for signature using Bitcoin's message signing format.
/// sha256(sha256(PREFIX_LENGTH + PREFIX + MESSAGE_LENGTH + MESSAGE))
pub fn sign_message_hash(message: &str) -> Option<[u8; 32]> {
    let message_prefix = "test-prefix";
    let mut stream = Stream::new();
    let prefix_len = CompactInteger::from(message_prefix.len());
    prefix_len.serialize(&mut stream);
    stream.append_slice(message_prefix.as_bytes());
    let msg_len = CompactInteger::from(message.len());
    msg_len.serialize(&mut stream);
    stream.append_slice(message.as_bytes());
    Some(dhash256(&stream.out()).take())
}

// pub fn checked_address_from_str<T: UtxoCommonOps>(
//     coin: &T,
//     address: &str,
// ) -> Result<Address, String> {
//     let addr = try_s!(address_from_str_unchecked(coin.as_ref(), address));
//     try_s!(check_withdraw_address_supported(coin, &addr));
//     Ok(addr)
// }

pub fn verify_message(signature_base64: &str, message: &str, address: &str) -> bool {
    let message_hash = sign_message_hash(message).unwrap();
    let signature = CompactSignature::from(base64::decode(signature_base64).unwrap());
    let recovered_pubkey = Public::recover_compact(&H256::from(message_hash), &signature).unwrap();
    // let received_address = checked_address_from_str(coin, address).unwrap();
    // Ok(AddressHashEnum::from(recovered_pubkey.address_hash()) == received_address.hash)

    false
}

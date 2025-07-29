extern crate core;

#[cfg(target_os = "zkvm")]
use openvm_k256 as k256;

use hkdf::Hkdf;
use k256::{
    AffinePoint, EncodedPoint, Scalar,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    elliptic_curve, Secp256k1,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha256::Sha256;

mod sha256;

pub type PublicKey = elliptic_curve::PublicKey<Secp256k1>;

/// secp256k1 (K-256) secret key.
pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExecMode {
    Baseline,
    All,
}

pub const PUBLIC_KEY_SIZE: usize = 33; // Compressed public key size
pub const ADDRESS_SIZE: usize = 20; // Ethereum address size
pub const HMAC_TAG_SIZE: usize = 32; // HMAC tag size

pub const MESSAGE_SIZE: usize = PUBLIC_KEY_SIZE + ADDRESS_SIZE + HMAC_TAG_SIZE;
pub type Message = [u8; MESSAGE_SIZE];


#[cfg(target_os = "zkvm")]
#[inline(always)]
fn public_mul_tweak(pk: &PublicKey, tweak: &Scalar) -> PublicKey {
    PublicKey::from_affine(pk.as_affine() * tweak).unwrap()
}

#[cfg(not(target_os = "zkvm"))]
#[inline(always)]
fn public_mul_tweak(pk: &PublicKey, tweak: &Scalar) -> PublicKey {
    PublicKey::from_affine((k256::ProjectivePoint::from(pk.as_ref()) * tweak).to_affine()).unwrap()
}

#[derive(Default)]
struct SharedKey {
    xor_key: [u8; ADDRESS_SIZE],
    hmac_key: [u8; HMAC_TAG_SIZE],
}

#[inline(always)]
fn get_shared_secret(sender_point: &PublicKey, shared_point: &PublicKey) -> SharedKey {
    let mut master = [0u8; PUBLIC_KEY_SIZE * 2];
    let sender_point = sender_point.to_encoded_point(true);
    let shared_point = shared_point.to_encoded_point(true);
    master[..PUBLIC_KEY_SIZE].copy_from_slice(sender_point.as_ref());
    master[PUBLIC_KEY_SIZE..].copy_from_slice(shared_point.as_ref());

    let h = Hkdf::<Sha256>::new(None, &master);
    let mut shared_key = SharedKey::default();
    h.expand(b"ECIES-XOR", &mut shared_key.xor_key).unwrap();
    h.expand(b"ECIES-HMAC", &mut shared_key.hmac_key).unwrap();
    shared_key
}

#[inline(always)]
fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> SharedKey {
    let shared_point = public_mul_tweak(peer_pk, sk.to_nonzero_scalar().as_ref());
    let sender_point = sk.public_key();
    get_shared_secret(&sender_point, &shared_point)
}

#[inline(always)]
fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> SharedKey {
    let shared_point = public_mul_tweak(pk, peer_sk.to_nonzero_scalar().as_ref());
    get_shared_secret(pk, &shared_point)
}

#[inline(always)]
fn xor_address(address: &[u8; ADDRESS_SIZE], key: &[u8; ADDRESS_SIZE]) -> [u8; ADDRESS_SIZE] {
    let mut result = [0u8; ADDRESS_SIZE];
    for i in 0..ADDRESS_SIZE {
        result[i] = address[i] ^ key[i];
    }
    result
}

#[inline(always)]
fn hmac_sha256(key: &[u8; HMAC_TAG_SIZE], data: &[u8; ADDRESS_SIZE]) -> [u8; HMAC_TAG_SIZE] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().as_slice().try_into().unwrap()
}

#[inline(always)]
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

pub fn encrypt(receiver_pk: &PublicKey, address: &[u8; ADDRESS_SIZE]) -> Message {
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();
    let ephemeral_pk = ephemeral_pk.to_encoded_point(true);

    let mut ciphertext = [0u8; MESSAGE_SIZE];
    ciphertext[..PUBLIC_KEY_SIZE].copy_from_slice(ephemeral_pk.as_ref());

    let shared_key = encapsulate(&ephemeral_sk, &receiver_pk);

    // EtM (Encrypt then MAC)
    let encrypted_address = xor_address(address, &shared_key.xor_key);
    let tag = hmac_sha256(&shared_key.hmac_key, &encrypted_address);

    ciphertext[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + ADDRESS_SIZE].copy_from_slice(&encrypted_address);
    ciphertext[PUBLIC_KEY_SIZE + ADDRESS_SIZE..].copy_from_slice(&tag);
    println!("{ciphertext:?}");

    ciphertext
}

pub fn decrypt(receiver_sk: &SecretKey, ciphertext: &Message) -> [u8; ADDRESS_SIZE] {
    assert_eq!(ciphertext.len(), MESSAGE_SIZE);

    let ephemeral_pk = PublicKey::from_affine(
        AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&ciphertext[..PUBLIC_KEY_SIZE]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let shared_key = decapsulate(&ephemeral_pk, receiver_sk);

    let encrypted_address: &[u8; ADDRESS_SIZE] = &ciphertext
        [PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + ADDRESS_SIZE]
        .try_into()
        .unwrap();

    let hmac_tag = hmac_sha256(&shared_key.hmac_key, &encrypted_address);
    let address = xor_address(encrypted_address, &shared_key.xor_key);

    assert_eq!(hmac_tag, ciphertext[PUBLIC_KEY_SIZE + ADDRESS_SIZE..]);
    address
}

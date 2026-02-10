use anyhow::{Context, Result};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub const KEY_SIZE: usize = 32;

pub const NONCE_SIZE: usize = 24;

pub struct SpakeState {
    state: Spake2<Ed25519Group>,
}

impl SpakeState {
    pub fn new(password: &str, app_id: &str) -> (Self, Vec<u8>) {
        let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(password.as_bytes()),
            &Identity::new(app_id.as_bytes()),
        );

        (Self { state }, outbound)
    }

    pub fn finish(self, inbound: &[u8]) -> Result<Vec<u8>> {
        self.state
            .finish(inbound)
            .map_err(|_| anyhow::anyhow!("SPAKE2 key exchange failed"))
    }
}

pub fn generate_side_id() -> String {
    let mut bytes = [0u8; 5];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

pub fn random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::rng().fill(&mut bytes[..]);
    hex::encode(bytes)
}

pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill(&mut nonce);
    nonce
}

pub fn derive_key(secret: &[u8], purpose: &str) -> [u8; KEY_SIZE] {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    let mut output = [0u8; KEY_SIZE];
    hkdf.expand(purpose.as_bytes(), &mut output)
        .expect("HKDF expand failed");
    output
}

pub fn derive_phase_key(shared_key: &[u8], side: &str, phase: &str) -> [u8; KEY_SIZE] {
    use sha2::Digest;

    let side_hash = Sha256::digest(side.as_bytes());
    let phase_hash = Sha256::digest(phase.as_bytes());

    let mut purpose = Vec::with_capacity(14 + 64);
    purpose.extend_from_slice(b"wormhole:phase:");
    purpose.extend_from_slice(&side_hash);
    purpose.extend_from_slice(&phase_hash);

    derive_key(shared_key, &String::from_utf8_lossy(&purpose))
}

pub fn derive_transit_key(shared_key: &[u8], app_id: &str) -> [u8; KEY_SIZE] {
    let purpose = format!("{}/transit-key", app_id);
    derive_key(shared_key, &purpose)
}

pub fn derive_verifier(shared_key: &[u8]) -> [u8; KEY_SIZE] {
    derive_key(shared_key, "wormhole:verifier")
}

pub fn secretbox_seal(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let key = Key::from_slice(key);

    let cipher = XSalsa20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn secretbox_open(key: &[u8; KEY_SIZE], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_SIZE {
        anyhow::bail!("Sealed message too short");
    }

    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = Key::from_slice(key);

    let cipher = XSalsa20Poly1305::new(key);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

pub fn encrypt_message(
    shared_key: &[u8],
    side: &str,
    phase: &str,
    plaintext: &[u8],
) -> Result<String> {
    let phase_key = derive_phase_key(shared_key, side, phase);
    let sealed = secretbox_seal(&phase_key, plaintext)?;
    Ok(hex::encode(sealed))
}

pub fn decrypt_message(
    shared_key: &[u8],
    side: &str,
    phase: &str,
    hex_sealed: &str,
) -> Result<Vec<u8>> {
    let sealed = hex::decode(hex_sealed).context("Invalid hex encoding")?;
    let phase_key = derive_phase_key(shared_key, side, phase);
    secretbox_open(&phase_key, &sealed)
}

pub fn derive_record_key_sender(transit_key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    derive_key(transit_key, "transit_record_sender_key")
}

pub fn derive_record_key_receiver(transit_key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    derive_key(transit_key, "transit_record_receiver_key")
}

pub fn derive_transit_sender_handshake(transit_key: &[u8; KEY_SIZE]) -> Vec<u8> {
    let key = derive_key(transit_key, "transit_sender");
    format!("transit sender {} ready\n\n", hex::encode(key)).into_bytes()
}

pub fn derive_transit_receiver_handshake(transit_key: &[u8; KEY_SIZE]) -> Vec<u8> {
    let key = derive_key(transit_key, "transit_receiver");
    format!("transit receiver {} ready\n\n", hex::encode(key)).into_bytes()
}

pub fn derive_relay_handshake(transit_key: &[u8; KEY_SIZE]) -> Vec<u8> {
    let key = derive_key(transit_key, "transit_relay_token");
    let side_id = random_hex(8);
    format!("please relay {} for side {}\n", hex::encode(key), side_id).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_side_id() {
        let side1 = generate_side_id();
        let side2 = generate_side_id();

        assert_eq!(side1.len(), 10); // 5 bytes = 10 hex chars
        assert_ne!(side1, side2);
    }

    #[test]
    fn test_random_hex() {
        let hex1 = random_hex(16);
        let hex2 = random_hex(16);

        assert_eq!(hex1.len(), 32);
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn test_derive_key() {
        let secret = b"shared secret";
        let key1 = derive_key(secret, "purpose1");
        let key2 = derive_key(secret, "purpose2");

        assert_eq!(key1.len(), KEY_SIZE);
        assert_ne!(key1, key2);

        let key1_again = derive_key(secret, "purpose1");
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_secretbox_roundtrip() {
        let key = [0u8; KEY_SIZE];
        let plaintext = b"Hello, World!";

        let sealed = secretbox_seal(&key, plaintext).unwrap();
        let opened = secretbox_open(&key, &sealed).unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_secretbox_wrong_key() {
        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        let plaintext = b"Hello, World!";

        let sealed = secretbox_seal(&key1, plaintext).unwrap();
        let result = secretbox_open(&key2, &sealed);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let shared_key = b"0123456789abcdef0123456789abcdef";
        let side = "sender_side";
        let phase = "0";
        let plaintext = b"test message";

        let encrypted = encrypt_message(shared_key, side, phase, plaintext).unwrap();
        let decrypted = decrypt_message(shared_key, side, phase, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_spake2_exchange() {
        let password = "7-guitarist-revenge";
        let app_id = "lothar.com/wormhole/text-or-file-xfer";

        let (state1, msg1) = SpakeState::new(password, app_id);
        let (state2, msg2) = SpakeState::new(password, app_id);

        let key1 = state1.finish(&msg2).unwrap();
        let key2 = state2.finish(&msg1).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_spake2_wrong_password() {
        let app_id = "lothar.com/wormhole/text-or-file-xfer";

        let (state1, _msg1) = SpakeState::new("password1", app_id);
        let (_state2, msg2) = SpakeState::new("password2", app_id);

        let key1 = state1.finish(&msg2).unwrap();

        let (state3, _msg3) = SpakeState::new("password1", app_id);
        let (_state4, msg4) = SpakeState::new("password1", app_id);

        let key3 = state3.finish(&msg4).unwrap();

        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_verifier() {
        let key1 = b"0123456789abcdef0123456789abcdef";
        let key2 = b"fedcba9876543210fedcba9876543210";

        let v1 = derive_verifier(key1);
        let v2 = derive_verifier(key2);

        assert_ne!(v1, v2);

        let v1_again = derive_verifier(key1);
        assert_eq!(v1, v1_again);
    }

    #[test]
    fn test_transit_handshakes() {
        let transit_key = [42u8; KEY_SIZE];

        let sender = derive_transit_sender_handshake(&transit_key);
        let receiver = derive_transit_receiver_handshake(&transit_key);

        assert!(sender.starts_with(b"transit sender "));
        assert!(sender.ends_with(b" ready\n\n"));
        assert!(receiver.starts_with(b"transit receiver "));
        assert!(receiver.ends_with(b" ready\n\n"));
    }
}

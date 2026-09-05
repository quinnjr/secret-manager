//! Transport encryption for secrets crossing the bus.

pub mod dh;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroizing;

pub const ALGORITHM_PLAIN: &str = "plain";
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("bad IV length {0}, expected 16")]
    BadIv(usize),
    #[error("secret decryption failed")]
    Decrypt,
    #[error(transparent)]
    Dh(#[from] dh::DhError),
}

pub enum SessionCipher {
    Plain,
    Aes { key: Zeroizing<[u8; 16]> },
}

impl SessionCipher {
    pub fn plain() -> Self {
        SessionCipher::Plain
    }

    pub fn from_dh(pair: &dh::KeyPair, peer_public: &[u8]) -> Result<Self, SessionError> {
        Ok(SessionCipher::Aes {
            key: pair.derive_aes_key(peer_public)?,
        })
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            SessionCipher::Plain => ALGORITHM_PLAIN,
            SessionCipher::Aes { .. } => ALGORITHM_DH,
        }
    }

    /// Returns `(parameters, value)` for the `(oayays)` secret struct.
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            SessionCipher::Plain => (Vec::new(), plaintext.to_vec()),
            SessionCipher::Aes { key } => {
                let iv = crate::vault::crypto::random_bytes::<16>();
                let enc = Aes128CbcEnc::new(
                    GenericArray::from_slice(&key[..]),
                    GenericArray::from_slice(&iv),
                );
                (iv.to_vec(), enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            }
        }
    }

    pub fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            SessionCipher::Plain => Ok(Zeroizing::new(value.to_vec())),
            SessionCipher::Aes { key } => {
                if parameters.len() != 16 {
                    return Err(SessionError::BadIv(parameters.len()));
                }
                let dec = Aes128CbcDec::new(
                    GenericArray::from_slice(&key[..]),
                    GenericArray::from_slice(parameters),
                );
                dec.decrypt_padded_vec_mut::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| SessionError::Decrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_passes_through() {
        let c = SessionCipher::plain();
        let (params, value) = c.encrypt(b"pw");
        assert!(params.is_empty());
        assert_eq!(value, b"pw");
        assert_eq!(c.decrypt(&params, &value).unwrap().as_slice(), b"pw");
        assert_eq!(c.algorithm(), ALGORITHM_PLAIN);
    }

    #[test]
    fn aes_round_trip_between_peers() {
        let client = dh::KeyPair::generate();
        let server = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&client, server.public_bytes()).unwrap();
        let s = SessionCipher::from_dh(&server, client.public_bytes()).unwrap();
        let (iv, ct) = c.encrypt(b"correct horse battery staple");
        assert_eq!(iv.len(), 16);
        assert_eq!(ct.len() % 16, 0);
        assert_ne!(&ct[..], b"correct horse battery staple");
        assert_eq!(
            s.decrypt(&iv, &ct).unwrap().as_slice(),
            b"correct horse battery staple"
        );
        assert_eq!(c.algorithm(), ALGORITHM_DH);
        let (iv2, _) = c.encrypt(b"x");
        assert_ne!(iv, iv2);
    }

    #[test]
    fn aes_rejects_bad_iv_and_truncated_ciphertext() {
        let a = dh::KeyPair::generate();
        let b = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&a, b.public_bytes()).unwrap();
        let (iv, ct) = c.encrypt(b"hello");
        assert!(matches!(
            c.decrypt(&iv[..8], &ct),
            Err(SessionError::BadIv(8))
        ));
        assert!(matches!(
            c.decrypt(&iv, &ct[..ct.len() - 1]),
            Err(SessionError::Decrypt)
        ));
    }
}

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const MASTER_KEY_LABEL: &[u8] = b"devault-master-key-v1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn new() -> Self {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self, crate::error::DevaultError> {
        let argon2 = Argon2::default();
        let mut key = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| crate::error::DevaultError::Crypto(e.to_string()))?;
        Ok(Self(key))
    }

    pub fn derive_data_key(&self, context: &[u8]) -> Result<DataKey, crate::error::DevaultError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut key = [0u8; KEY_LEN];
        hkdf.expand(context, &mut key)
            .map_err(|_| crate::error::DevaultError::Crypto("HKDF expand failed".into()))?;
        Ok(DataKey(key))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn clone_key(&self) -> Self {
        Self(self.0)
    }
}

impl ConstantTimeEq for MasterKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; KEY_LEN]);

impl DataKey {
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, crate::error::DevaultError> {
        let cipher = Aes256Gcm::new((&self.0).into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| crate::error::DevaultError::Crypto(e.to_string()))?;
        Ok(EncryptedData {
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    pub fn decrypt(&self, data: &EncryptedData) -> Result<Vec<u8>, crate::error::DevaultError> {
        let cipher = Aes256Gcm::new((&self.0).into());
        let nonce = Nonce::from_slice(&data.nonce);
        cipher
            .decrypt(nonce, data.ciphertext.as_ref())
            .map_err(|e| crate::error::DevaultError::Crypto(e.to_string()))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct VaultHeader {
    pub version: u32,
    pub salt: Vec<u8>,
    pub master_key_encrypted: EncryptedData,
    pub master_key_hash: Vec<u8>,
}

impl VaultHeader {
    pub fn new(master_key: &MasterKey, password: &str) -> Result<Self, crate::error::DevaultError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let argon2 = Argon2::default();
        let mut master_key_hash = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut master_key_hash)
            .map_err(|e| crate::error::DevaultError::Crypto(e.to_string()))?;

        let data_key = {
            let hkdf = Hkdf::<Sha256>::new(None, &master_key_hash);
            let mut key = [0u8; KEY_LEN];
            hkdf.expand(MASTER_KEY_LABEL, &mut key)
                .map_err(|_| crate::error::DevaultError::Crypto("HKDF expand failed".into()))?;
            DataKey(key)
        };
        let master_key_encrypted = data_key.encrypt(&master_key.0)?;

        Ok(Self {
            version: 1,
            salt: salt.to_vec(),
            master_key_encrypted,
            master_key_hash: master_key_hash.to_vec(),
        })
    }

    pub fn verify_password(&self, password: &str) -> Result<MasterKey, crate::error::DevaultError> {
        let argon2 = Argon2::default();
        let mut master_key_hash = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password.as_bytes(), &self.salt, &mut master_key_hash)
            .map_err(|e| crate::error::DevaultError::Crypto(e.to_string()))?;

        if master_key_hash.ct_eq(&self.master_key_hash[..]).unwrap_u8() == 0 {
            return Err(crate::error::DevaultError::InvalidPassword);
        }

        let data_key = {
            let hkdf = Hkdf::<Sha256>::new(None, &master_key_hash);
            let mut key = [0u8; KEY_LEN];
            hkdf.expand(MASTER_KEY_LABEL, &mut key)
                .map_err(|_| crate::error::DevaultError::Crypto("HKDF expand failed".into()))?;
            DataKey(key)
        };

        let master_key_bytes = data_key.decrypt(&self.master_key_encrypted)?;
        let mut master_key = [0u8; KEY_LEN];
        master_key.copy_from_slice(&master_key_bytes);
        Ok(MasterKey(master_key))
    }
}

pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
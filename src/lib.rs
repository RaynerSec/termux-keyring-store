use std::any::Any;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::aead::{Aead, KeyInit, OsRng};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use argon2::{Argon2, Params};
use data_encoding::BASE64;
use directories::ProjectDirs;
use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{Credential, CredentialStore, Entry, Error, Result};

const FILENAME: &str = "credentials.enc";

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    key: Key<Aes256GcmSiv>,
    salt: String,
    lock: Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FileHeader {
    salt: String,
    nonce: String,
    ciphertext: String,
}

struct TermuxCredential {
    store: Store,
    service: String,
    user: String,
}

fn platform_error<E: std::fmt::Display>(e: E) -> Error {
    Error::PlatformFailure(Box::new(io::Error::new(
        io::ErrorKind::Other,
        e.to_string(),
    )))
}

impl Store {
    pub fn new() -> Result<Arc<CredentialStore>> {
        let dirs = ProjectDirs::from("", "termux", "komac")
            .ok_or_else(|| platform_error("no project directory"))?;
        let path = dirs.data_local_dir().join(FILENAME);
        fs::create_dir_all(dirs.data_local_dir())
            .map_err(platform_error)?;

        let (salt, key) = if path.exists() {
            let contents = fs::read_to_string(&path)
                .map_err(platform_error)?;
            let header: FileHeader = serde_json::from_str(&contents)
                .map_err(platform_error)?;
            let key = derive_key(&header.salt)?;
            (header.salt, key)
        } else {
            let mut salt_bytes = [0u8; 16];
            OsRng.fill_bytes(&mut salt_bytes);
            let salt = BASE64.encode(&salt_bytes);
            let key = derive_key(&salt)?;
            let header = FileHeader {
                salt: salt.clone(),
                nonce: String::new(),
                ciphertext: String::new(),
            };
            let contents = serde_json::to_string(&header)
                .map_err(platform_error)?;
            fs::write(&path, contents)
                .map_err(platform_error)?;
            (salt, key)
        };

        let store = Store {
            inner: Arc::new(Inner {
                path,
                key,
                salt,
                lock: Mutex::new(()),
            }),
        };
        Ok(Arc::new(store))
    }

    fn load(&self) -> Result<HashMap<String, Vec<u8>>> {
        let _guard = self.inner.lock.lock().unwrap();
        let contents = fs::read_to_string(&self.inner.path)
            .map_err(platform_error)?;
        let header: FileHeader = serde_json::from_str(&contents)
            .map_err(platform_error)?;
        if header.ciphertext.is_empty() {
            return Ok(HashMap::new());
        }
        let nonce = decode(&header.nonce)?;
        let ciphertext = decode(&header.ciphertext)?;
        let cipher = Aes256GcmSiv::new(&self.inner.key);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(platform_error)?;
        serde_json::from_slice(&plaintext)
            .map_err(platform_error)
    }

    fn save(&self, entries: &HashMap<String, Vec<u8>>) -> Result<()> {
        let _guard = self.inner.lock.lock().unwrap();
        let plaintext = serde_json::to_vec(entries)
            .map_err(platform_error)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes256GcmSiv::new(&self.inner.key);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(platform_error)?;
        let header = FileHeader {
            salt: self.inner.salt.clone(),
            nonce: BASE64.encode(&nonce_bytes),
            ciphertext: BASE64.encode(&ciphertext),
        };
        let contents = serde_json::to_string(&header)
            .map_err(platform_error)?;
        fs::write(&self.inner.path, contents)
            .map_err(platform_error)
    }
}

fn derive_key(salt_b64: &str) -> Result<Key<Aes256GcmSiv>> {
    let salt = decode(salt_b64)?;
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(platform_error)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut okm = [0u8; 32];
    argon2
        .hash_password_into(b"", &salt, &mut okm)
        .map_err(platform_error)?;
    Ok(*Key::<Aes256GcmSiv>::from_slice(&okm))
}

fn decode(b64: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(b64.as_bytes())
        .map_err(platform_error)
}

fn entry_key(service: &str, user: &str) -> String {
    format!("{service}\0{user}")
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "termux-keyring-store (https://github.com/rc-chuah/termux-keyring-store)".into()
    }

    fn id(&self) -> String {
        format!(
            "{} v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let credential: Arc<Credential> = Arc::new(TermuxCredential {
            store: self.clone(),
            service: service.into(),
            user: user.into(),
        });
        Ok(Entry::new_with_credential(credential))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CredentialApi for TermuxCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut entries = self.store.load()?;
        entries.insert(entry_key(&self.service, &self.user), secret.into());
        self.store.save(&entries)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let entries = self.store.load()?;
        entries
            .get(&entry_key(&self.service, &self.user))
            .cloned()
            .ok_or(Error::NoEntry)
    }

    fn delete_credential(&self) -> Result<()> {
        let mut entries = self.store.load()?;
        let key = entry_key(&self.service, &self.user);
        if entries.remove(&key).is_none() {
            return Err(Error::NoEntry);
        }
        self.store.save(&entries)
    }

    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

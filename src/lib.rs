use std::any::Any;
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aes_gcm_siv::aead::{Aead, AeadCore, Generate, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use data_encoding::BASE64;
use directories::ProjectDirs;
use hkdf::Hkdf;
use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{Credential, CredentialStore, Entry, Error, Result};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const FILENAME: &str = "credentials.enc";
const PASSPHRASE_ENV: &str = "TERMUX_KEYRING_PASSPHRASE";
const VAULT_VERSION: u8 = 2;
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    salt: String,
    lock: Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultFileV2 {
    version: u8,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    salt: String,
    counter: u64,
    nonce: String,
    ciphertext: String,
    mac: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedEntry {
    nonce: String,
    ciphertext: String,
}

struct TermuxCredential {
    store: Store,
    service: String,
    user: String,
}

fn platform_error<E: std::fmt::Display>(e: E) -> Error {
    Error::PlatformFailure(Box::new(io::Error::other(e.to_string())))
}

fn generate_random_32() -> [u8; 32] {
    Key::<Aes256GcmSiv>::generate().into()
}

fn generate_random_nonce() -> [u8; 12] {
    Nonce::generate().into()
}

fn resolve_default_passphrase() -> Zeroizing<String> {
    Zeroizing::new(env::var(PASSPHRASE_ENV).unwrap_or_default())
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(platform_error("refusing to operate on symbolic link"))
        }
        _ => Ok(()),
    }
}

fn ensure_secure_dir(dir: &Path) -> Result<()> {
    reject_symlink(dir)?;
    fs::create_dir_all(dir).map_err(platform_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(platform_error)?;
    }
    Ok(())
}

fn atomic_write_secure(path: &Path, data: &[u8]) -> Result<()> {
    reject_symlink(path)?;
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    reject_symlink(&tmp_path)?;

    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp_path).map_err(platform_error)?;
    file.write_all(data).map_err(platform_error)?;
    file.sync_all().map_err(platform_error)?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(platform_error)?;
    }

    fs::rename(&tmp_path, path).map_err(platform_error)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(platform_error)?;
    }

    Ok(())
}

impl Store {
    pub fn new() -> Result<Arc<CredentialStore>> {
        let passphrase = resolve_default_passphrase();
        Self::with_passphrase(&passphrase)
    }

    pub fn with_passphrase(passphrase: &str) -> Result<Arc<CredentialStore>> {
        let dirs = ProjectDirs::from("", "termux", "komac")
            .ok_or_else(|| platform_error("no project directory"))?;
        let path = dirs.data_local_dir().join(FILENAME);
        Self::with_path_and_passphrase(path, passphrase)
    }

    pub fn with_path<P: Into<PathBuf>>(path: P) -> Result<Arc<CredentialStore>> {
        let passphrase = resolve_default_passphrase();
        Self::with_path_and_passphrase(path, &passphrase)
    }

    pub fn with_path_and_passphrase<P: Into<PathBuf>>(
        path: P,
        passphrase: &str,
    ) -> Result<Arc<CredentialStore>> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                ensure_secure_dir(parent)?;
            }
        }
        reject_symlink(&path)?;

        let (salt, enc_key, mac_key) = if path.exists() {
            let contents = fs::read_to_string(&path).map_err(platform_error)?;
            let vault: VaultFileV2 = serde_json::from_str(&contents).map_err(platform_error)?;
            validate_vault_params(&vault)?;
            let (enc_key, mac_key) = derive_subkeys(
                passphrase.as_bytes(),
                &vault.salt,
                vault.argon2_m_cost,
                vault.argon2_t_cost,
                vault.argon2_p_cost,
            )?;
            verify_vault_mac(&vault, &mac_key)?;
            (vault.salt, enc_key, mac_key)
        } else {
            let salt_bytes = Zeroizing::new(generate_random_32());
            let salt = BASE64.encode(salt_bytes.as_ref());
            let (enc_key, mac_key) = derive_subkeys(
                passphrase.as_bytes(),
                &salt,
                ARGON2_M_COST,
                ARGON2_T_COST,
                ARGON2_P_COST,
            )?;
            let mut vault = VaultFileV2 {
                version: VAULT_VERSION,
                argon2_m_cost: ARGON2_M_COST,
                argon2_t_cost: ARGON2_T_COST,
                argon2_p_cost: ARGON2_P_COST,
                salt: salt.clone(),
                counter: 0,
                nonce: String::new(),
                ciphertext: String::new(),
                mac: String::new(),
            };
            vault.mac = compute_vault_mac(&vault, &mac_key);
            let contents = serde_json::to_string(&vault).map_err(platform_error)?;
            atomic_write_secure(&path, contents.as_bytes())?;
            (salt, enc_key, mac_key)
        };

        let store = Store {
            inner: Arc::new(Inner {
                path,
                enc_key,
                mac_key,
                salt,
                lock: Mutex::new(()),
            }),
        };
        Ok(Arc::new(store))
    }

    fn load_vault(&self) -> Result<(u64, HashMap<String, EncryptedEntry>)> {
        reject_symlink(&self.inner.path)?;
        let contents = fs::read_to_string(&self.inner.path).map_err(platform_error)?;
        let vault: VaultFileV2 = serde_json::from_str(&contents).map_err(platform_error)?;
        validate_vault_params(&vault)?;
        verify_vault_mac(&vault, &self.inner.mac_key)?;

        if vault.ciphertext.is_empty() {
            return Ok((vault.counter, HashMap::new()));
        }

        let nonce_bytes = decode(&vault.nonce)?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| platform_error("invalid outer nonce length"))?;
        let ciphertext = decode(&vault.ciphertext)?;
        let outer_aad = vault_outer_aad(&vault);

        let key = Key::<Aes256GcmSiv>::try_from(self.inner.enc_key.as_ref())
            .map_err(|_| platform_error("invalid encryption key length"))?;
        let cipher = Aes256GcmSiv::new(&key);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext.as_ref(),
                        aad: &outer_aad,
                    },
                )
                .map_err(platform_error)?,
        );

        let entries: HashMap<String, EncryptedEntry> =
            serde_json::from_slice(&plaintext).map_err(platform_error)?;
        Ok((vault.counter, entries))
    }

    fn save_vault(
        &self,
        expected_counter: u64,
        entries: &HashMap<String, EncryptedEntry>,
    ) -> Result<()> {
        reject_symlink(&self.inner.path)?;
        if self.inner.path.exists() {
            let existing_contents =
                fs::read_to_string(&self.inner.path).map_err(platform_error)?;
            let existing: VaultFileV2 =
                serde_json::from_str(&existing_contents).map_err(platform_error)?;
            verify_vault_mac(&existing, &self.inner.mac_key)?;
            if existing.counter < expected_counter {
                return Err(platform_error("rollback detected: vault counter decreased"));
            }
        }

        let next_counter = expected_counter
            .checked_add(1)
            .ok_or_else(|| platform_error("vault counter overflow"))?;

        let plaintext = Zeroizing::new(serde_json::to_vec(entries).map_err(platform_error)?);
        let nonce_bytes = generate_random_nonce();

        let mut vault = VaultFileV2 {
            version: VAULT_VERSION,
            argon2_m_cost: ARGON2_M_COST,
            argon2_t_cost: ARGON2_T_COST,
            argon2_p_cost: ARGON2_P_COST,
            salt: self.inner.salt.clone(),
            counter: next_counter,
            nonce: BASE64.encode(&nonce_bytes),
            ciphertext: String::new(),
            mac: String::new(),
        };

        let outer_aad = vault_outer_aad(&vault);
        let key = Key::<Aes256GcmSiv>::try_from(self.inner.enc_key.as_ref())
            .map_err(|_| platform_error("invalid encryption key length"))?;
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| platform_error("invalid outer nonce length"))?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &outer_aad,
                },
            )
            .map_err(platform_error)?;

        vault.ciphertext = BASE64.encode(&ciphertext);
        vault.mac = compute_vault_mac(&vault, &self.inner.mac_key);

        let contents = Zeroizing::new(serde_json::to_string(&vault).map_err(platform_error)?);
        atomic_write_secure(&self.inner.path, contents.as_bytes())
    }

    fn encrypt_entry(&self, key_id: &str, secret: &[u8]) -> Result<EncryptedEntry> {
        let nonce_bytes = generate_random_nonce();
        let key = Key::<Aes256GcmSiv>::try_from(self.inner.enc_key.as_ref())
            .map_err(|_| platform_error("invalid encryption key length"))?;
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| platform_error("invalid entry nonce length"))?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret,
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(platform_error)?;
        Ok(EncryptedEntry {
            nonce: BASE64.encode(&nonce_bytes),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    fn decrypt_entry(&self, key_id: &str, entry: &EncryptedEntry) -> Result<Vec<u8>> {
        let nonce_bytes = decode(&entry.nonce)?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|_| platform_error("invalid entry nonce length"))?;
        let ciphertext = decode(&entry.ciphertext)?;
        let key = Key::<Aes256GcmSiv>::try_from(self.inner.enc_key.as_ref())
            .map_err(|_| platform_error("invalid encryption key length"))?;
        let cipher = Aes256GcmSiv::new(&key);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(platform_error)
    }
}

fn validate_vault_params(vault: &VaultFileV2) -> Result<()> {
    if vault.version != VAULT_VERSION {
        return Err(platform_error(format!(
            "unsupported vault version: {}",
            vault.version
        )));
    }
    if vault.argon2_m_cost < 16 * 1024 || vault.argon2_t_cost < 2 || vault.argon2_p_cost == 0 {
        return Err(platform_error("weak Argon2 parameters rejected"));
    }
    Ok(())
}

fn derive_subkeys(
    passphrase: &[u8],
    salt_b64: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let salt = decode(salt_b64)?;
    if salt.len() < 16 {
        return Err(platform_error("salt length below minimum 16 bytes"));
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(platform_error)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master_okm = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, &salt, master_okm.as_mut())
        .map_err(platform_error)?;

    let hk = Hkdf::<Sha256>::new(Some(&salt), master_okm.as_ref());
    let mut enc_key = Zeroizing::new([0u8; 32]);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"termux-keyring-store:v2:aes-gcm-siv", enc_key.as_mut())
        .map_err(platform_error)?;
    hk.expand(b"termux-keyring-store:v2:blake3-mac", mac_key.as_mut())
        .map_err(platform_error)?;

    Ok((enc_key, mac_key))
}

fn vault_outer_aad(vault: &VaultFileV2) -> Vec<u8> {
    format!(
        "termux-keyring-store:v{}:m={}:t={}:p={}:salt={}:counter={}",
        vault.version,
        vault.argon2_m_cost,
        vault.argon2_t_cost,
        vault.argon2_p_cost,
        vault.salt,
        vault.counter
    )
    .into_bytes()
}

fn compute_vault_mac(vault: &VaultFileV2, mac_key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(&vault_outer_aad(vault));
    hasher.update(b":nonce:");
    hasher.update(vault.nonce.as_bytes());
    hasher.update(b":ciphertext:");
    hasher.update(vault.ciphertext.as_bytes());
    let tag = hasher.finalize();
    BASE64.encode(tag.as_bytes())
}

fn verify_vault_mac(vault: &VaultFileV2, mac_key: &[u8; 32]) -> Result<()> {
    let expected = decode(&vault.mac)?;
    let computed_b64 = compute_vault_mac(vault, mac_key);
    let computed = decode(&computed_b64)?;
    if expected.len() == computed.len() && bool::from(expected.ct_eq(&computed)) {
        Ok(())
    } else {
        Err(platform_error(
            "vault header MAC verification failed (tampered file or wrong passphrase)",
        ))
    }
}

fn decode(b64: &str) -> Result<Vec<u8>> {
    BASE64.decode(b64.as_bytes()).map_err(platform_error)
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
        let _guard = self.store.inner.lock.lock().unwrap();
        let (counter, mut entries) = self.store.load_vault()?;
        let key_id = entry_key(&self.service, &self.user);
        let encrypted = self.store.encrypt_entry(&key_id, secret)?;
        entries.insert(key_id, encrypted);
        self.store.save_vault(counter, &entries)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let _guard = self.store.inner.lock.lock().unwrap();
        let (_counter, entries) = self.store.load_vault()?;
        let key_id = entry_key(&self.service, &self.user);
        let encrypted = entries.get(&key_id).ok_or(Error::NoEntry)?;
        let mut secret = self.store.decrypt_entry(&key_id, encrypted)?;
        let out = secret.clone();
        secret.zeroize();
        Ok(out)
    }

    fn delete_credential(&self) -> Result<()> {
        let _guard = self.store.inner.lock.lock().unwrap();
        let (counter, mut entries) = self.store.load_vault()?;
        let key_id = entry_key(&self.service, &self.user);
        if entries.remove(&key_id).is_none() {
            return Err(Error::NoEntry);
        }
        self.store.save_vault(counter, &entries)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_vault_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
            .join(FILENAME)
    }

    #[test]
    fn test_round_trip_and_persistence() {
        let path = temp_vault_path("tks_roundtrip");
        let store = Store::with_path(&path).unwrap();
        let entry = store.build("github.com", "rc-chuah", None).unwrap();

        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        entry.set_password("super-secret-token").unwrap();
        assert_eq!(entry.get_password().unwrap(), "super-secret-token");

        let reopened = Store::with_path(&path).unwrap();
        let entry2 = reopened.build("github.com", "rc-chuah", None).unwrap();
        assert_eq!(entry2.get_password().unwrap(), "super-secret-token");

        entry2.delete_credential().unwrap();
        assert!(matches!(entry2.get_password(), Err(Error::NoEntry)));

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_passphrase_isolation() {
        let path = temp_vault_path("tks_passphrase");
        let store = Store::with_path_and_passphrase(&path, "correct-horse-battery-staple").unwrap();
        let entry = store.build("crates.io", "token", None).unwrap();
        entry.set_password("cio-secret").unwrap();

        let wrong_pass = Store::with_path_and_passphrase(&path, "wrong-password");
        assert!(wrong_pass.is_err());

        let right_pass =
            Store::with_path_and_passphrase(&path, "correct-horse-battery-staple").unwrap();
        let entry_ok = right_pass.build("crates.io", "token", None).unwrap();
        assert_eq!(entry_ok.get_password().unwrap(), "cio-secret");

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_header_mac_tampering_rejected() {
        let path = temp_vault_path("tks_mac_tamper");
        let store = Store::with_path(&path).unwrap();
        let entry = store.build("svc", "usr", None).unwrap();
        entry.set_password("secret").unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let mut vault: VaultFileV2 = serde_json::from_str(&raw).unwrap();
        vault.counter = 999;
        fs::write(&path, serde_json::to_string(&vault).unwrap()).unwrap();

        assert!(entry.get_password().is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_aad_entry_swap_rejected() {
        let path = temp_vault_path("tks_aad_swap");
        let store = Store::with_path_and_passphrase(&path, "pass").unwrap();
        let a = store.build("svc", "alice", None).unwrap();
        let b = store.build("svc", "bob", None).unwrap();
        a.set_password("alice-secret").unwrap();
        b.set_password("bob-secret").unwrap();

        let typed_store = Store {
            inner: Arc::new(Inner {
                path: path.clone(),
                enc_key: {
                    let raw = fs::read_to_string(&path).unwrap();
                    let v: VaultFileV2 = serde_json::from_str(&raw).unwrap();
                    derive_subkeys(
                        b"pass",
                        &v.salt,
                        v.argon2_m_cost,
                        v.argon2_t_cost,
                        v.argon2_p_cost,
                    )
                    .unwrap()
                    .0
                },
                mac_key: {
                    let raw = fs::read_to_string(&path).unwrap();
                    let v: VaultFileV2 = serde_json::from_str(&raw).unwrap();
                    derive_subkeys(
                        b"pass",
                        &v.salt,
                        v.argon2_m_cost,
                        v.argon2_t_cost,
                        v.argon2_p_cost,
                    )
                    .unwrap()
                    .1
                },
                salt: {
                    let raw = fs::read_to_string(&path).unwrap();
                    let v: VaultFileV2 = serde_json::from_str(&raw).unwrap();
                    v.salt
                },
                lock: Mutex::new(()),
            }),
        };

        let (counter, mut entries) = typed_store.load_vault().unwrap();
        let alice_entry = entries.remove(&entry_key("svc", "alice")).unwrap();
        entries.insert(entry_key("svc", "bob"), alice_entry);
        typed_store.save_vault(counter, &entries).unwrap();

        assert!(b.get_password().is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_rollback_rejected() {
        let path = temp_vault_path("tks_rollback");
        let store = Store::with_path(&path).unwrap();
        let entry = store.build("svc", "usr", None).unwrap();
        entry.set_password("v1").unwrap();
        let snapshot_v1 = fs::read_to_string(&path).unwrap();

        entry.set_password("v2").unwrap();
        fs::write(&path, snapshot_v1).unwrap();

        let reopened = Store::with_path(&path).unwrap();
        let entry_reopened = reopened.build("svc", "usr", None).unwrap();
        assert_eq!(entry_reopened.get_password().unwrap(), "v1");

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_vault_path("tks_perms");
        let store = Store::with_path(&path).unwrap();
        let entry = store.build("svc", "usr", None).unwrap();
        entry.set_password("secret").unwrap();

        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);

        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}

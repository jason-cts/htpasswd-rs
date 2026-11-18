use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypt3_rs::{HashSetup, crypt};
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Bcrypt,
    Apr1,
    Sha256,
    Sha512,
    Des,
    Sha1,
    Plaintext,
}

pub fn hash_password(
    password: &str,
    algorithm: Algorithm,
    bcrypt_cost: u32,
    rounds: u32,
) -> Result<String, HashError> {
    let password = password.as_bytes();
    let result = match algorithm {
        Algorithm::Bcrypt => {
            use crypt::bcrypt::{BcryptSetup, BcryptVariant};
            let salt_bytes = random_bytes::<16>()?;
            let salt = bcrypt_base64(&salt_bytes);
            crypt::bcrypt::hash_with(
                BcryptSetup::default()
                    .salt(&salt)
                    .cost(bcrypt_cost)
                    .variant(BcryptVariant::V2y),
                password,
            )
        }
        Algorithm::Apr1 => {
            let salt = random_salt(8)?;
            #[allow(deprecated)]
            {
                crypt::apr1::hash_with(HashSetup::default().salt(&salt), password)
            }
        }
        Algorithm::Sha256 => {
            let salt = random_salt(16)?;
            #[allow(deprecated)]
            {
                crypt::sha256::hash_with(HashSetup::default().salt(&salt).rounds(rounds), password)
            }
        }
        Algorithm::Sha512 => {
            let salt = random_salt(16)?;
            #[allow(deprecated)]
            {
                crypt::sha512::hash_with(HashSetup::default().salt(&salt).rounds(rounds), password)
            }
        }
        Algorithm::Des => {
            let salt = random_salt(2)?;
            #[allow(deprecated)]
            {
                crypt::unix::hash_with(&salt, password)
            }
        }
        Algorithm::Sha1 => {
            let digest = Sha1::digest(password);
            return Ok(format!("{{SHA}}{}", STANDARD.encode(digest)));
        }
        Algorithm::Plaintext => return Ok(String::from_utf8_lossy(password).into_owned()),
    };

    result
        .map(|hash| hash.as_str().to_owned())
        .map_err(|error| match error {
            crypt3_rs::error::Error::RandomError(message) => HashError::new(8, message),
            other => HashError::new(9, other.to_string()),
        })
}

fn random_bytes<const N: usize>() -> Result<[u8; N], HashError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| HashError::new(8, error.to_string()))?;
    Ok(bytes)
}

fn random_salt(length: usize) -> Result<String, HashError> {
    const SALT: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let bytes = random_bytes::<16>()?;
    Ok(bytes
        .iter()
        .take(length)
        .map(|byte| SALT[usize::from(*byte) & 63] as char)
        .collect())
}

fn bcrypt_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut encoded = String::with_capacity(22);
    let mut offset = 0;
    while offset < bytes.len() {
        let first = bytes[offset];
        offset += 1;
        encoded.push(ALPHABET[usize::from(first >> 2)] as char);
        let mut bits = (first & 0x03) << 4;
        if offset >= bytes.len() {
            encoded.push(ALPHABET[usize::from(bits)] as char);
            break;
        }

        let second = bytes[offset];
        offset += 1;
        bits |= second >> 4;
        encoded.push(ALPHABET[usize::from(bits)] as char);
        bits = (second & 0x0f) << 2;
        if offset >= bytes.len() {
            encoded.push(ALPHABET[usize::from(bits)] as char);
            break;
        }

        let third = bytes[offset];
        offset += 1;
        bits |= third >> 6;
        encoded.push(ALPHABET[usize::from(bits)] as char);
        encoded.push(ALPHABET[usize::from(third & 0x3f)] as char);
    }
    encoded
}

#[derive(Debug)]
pub struct HashError {
    pub exit_code: u8,
    pub message: String,
}

impl HashError {
    fn new(exit_code: u8, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }
}

pub fn verify_password(password: &str, stored: &str, plaintext: bool) -> Result<bool, String> {
    let password = password.as_bytes();
    if plaintext {
        return Ok(constant_time_eq(password, stored.as_bytes()));
    }

    let matches = if stored.starts_with("$apr1$") {
        crypt::apr1::verify(password, stored)
    } else if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$")
    {
        crypt::bcrypt::verify(password, stored)
    } else if stored.starts_with("$5$") {
        crypt::sha256::verify(password, stored)
    } else if stored.starts_with("$6$") {
        crypt::sha512::verify(password, stored)
    } else if let Some(encoded) = stored.strip_prefix("{SHA}") {
        let digest = STANDARD
            .decode(encoded)
            .map_err(|_| "invalid SHA-1 password record".to_owned())?;
        constant_time_eq(&Sha1::digest(password), &digest)
    } else if stored.len() == 13 && stored.is_ascii() {
        #[allow(deprecated)]
        {
            crypt::unix::verify(password, stored)
        }
    } else {
        return Err("unrecognized password hash format".to_owned());
    };

    Ok(matches)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, hash_password, verify_password};

    #[test]
    fn apache_bcrypt_round_trips_and_uses_2y_format() {
        let hash = hash_password("secret", Algorithm::Bcrypt, 4, 5_000).unwrap();
        assert!(hash.starts_with("$2y$04$"));
        assert!(verify_password("secret", &hash, false).unwrap());
        assert!(!verify_password("wrong", &hash, false).unwrap());
    }

    #[test]
    fn bcrypt_truncates_at_72_bytes() {
        let long = format!("{}different-tail", "x".repeat(72));
        let hash = hash_password(&long, Algorithm::Bcrypt, 4, 5_000).unwrap();
        assert!(verify_password(&"x".repeat(72), &hash, false).unwrap());
    }

    #[test]
    fn all_legacy_formats_round_trip() {
        for algorithm in [
            Algorithm::Apr1,
            Algorithm::Sha256,
            Algorithm::Sha512,
            Algorithm::Des,
            Algorithm::Sha1,
        ] {
            let hash = hash_password("pāssword", algorithm, 4, 1_000).unwrap();
            assert!(
                verify_password("pāssword", &hash, false).unwrap(),
                "{algorithm:?}"
            );
            assert!(
                !verify_password("wrong", &hash, false).unwrap(),
                "{algorithm:?}"
            );
        }
    }

    #[test]
    fn sha1_uses_apache_compatible_sha_format() {
        let hash = hash_password("test", Algorithm::Sha1, 4, 5_000).unwrap();
        assert_eq!(hash, "{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=");
    }

    #[test]
    fn plaintext_is_only_checked_when_requested() {
        assert!(verify_password("secret", "secret", true).unwrap());
        assert!(verify_password("secret", "secret", false).is_err());
    }
}

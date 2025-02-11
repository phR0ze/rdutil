//! Simple utility to encrypt and decrypt RustDesk passwords.
//!
//! This utility can be used to generate the permanent RustDesk password that can then be stored in
//! the ~/.config/rustdeskt/RustDeskt2.toml configuration file for automated deployments.
//!
//! ### Platform support
//! - NixOS is the only tested platform, but this could easily be extended to support others
//!
//! ### Usage
//! RustDesk stores its configuration in ~/.config/rustdesk/RustDesk.toml
//! ```toml
//! password = '00ZHkEf5C0rqwam5C0KgPAMKmINg8GgUE='
//! ```
use sodiumoxide::base64;
use std::error::Error;
use std::fs;

// Maximum length allowed for original unecrypted data
const ENCRYPT_MAX_LEN: usize = 128;

/// Supported RustDesk password encryption version
const PASSWORD_VERSION_LEN: usize = 2; // 2 characters for version
const PASSWORD_ENC_VER_00: &str = "00"; // default version is 00

fn main() {
    let mut args = std::env::args().collect::<Vec<String>>();
    if args.len() < 3 {
        println!("Usage: {} [COMMAND] <password> [OPTIONS]", args[0]);
        println!("Options:");
        println!("  --key <key>                 Alternate key to use for encryption");
        println!("Commands:");
        println!("  encrypt <plaintext>         Encrypt the given password");
        println!("  decrypt <encrypted>         Decrypt the given password");
        std::process::exit(1);
    }

    // Extract id from the args if given
    let key = match args.iter().position(|x| *x == "--key") {
        Some(i) => {
            if args.len() > i + 1 {
                args.remove(i);
                Some(args.remove(i))
            } else {
                None
            }
        }
        None => None,
    };

    // Process the given command
    let target = &args[1];
    if target == "encrypt" {
        match encrypt(&args[2], PASSWORD_ENC_VER_00, key) {
            Ok(result) => print!("{result}"),
            Err(e) => {
                eprintln!("Failed to encrypt: {e}");
                std::process::exit(1);
            }
        }
    } else if target == "decrypt" {
        match decrypt(&args[2], PASSWORD_ENC_VER_00, key) {
            Ok(result) => print!("{result}"),
            Err(e) => {
                eprintln!("Failed to decrypt: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Unknown command: {target}");
        std::process::exit(1);
    }
}

/// Encrypt the given plaintext string using a RustDesk version 00 algorithm.
///
/// returns: Result<encrypted string, error>
fn encrypt(plaintext: &str, version: &str, key: Option<String>) -> Result<String, Box<dyn Error>> {
    // Plaintext is too long and cannot be encrypted
    if plaintext.chars().count() > ENCRYPT_MAX_LEN {
        Err("Plaintext is too long and cannot be encrypted")?;
    }

    // Encrypt the data using the version 00 algorithm
    if version == PASSWORD_ENC_VER_00 {
        // First encrypt the data then append the version to it
        let encrypted = symmetric(plaintext.as_bytes(), true, key)?;

        // Now base64 encode the result using sodiumoxide's custom base64 encoder
        let encoded = base64::encode(&encrypted, base64::Variant::Original);

        // Now prefix it with the version and return it
        return Ok(version.to_owned() + &encoded);
    } else {
        Err(format!(
            "Unsupported RustDesk password version: {}",
            version
        ))?
    }
}

/// Decrypt the given encrypted string using a RustDesk version 00 algorithm.
///
/// returns: Result<decrypted string, error>
pub fn decrypt(encrypted: &str, version: &str, key: Option<String>) -> Result<String, Box<dyn Error>> {
    if encrypted.len() > PASSWORD_VERSION_LEN {
        // Extract the version from the encrypted data
        let version = String::from_utf8_lossy(&encrypted[..PASSWORD_VERSION_LEN].as_bytes());

        // Choose the decryption algorithm based on the version
        if version == PASSWORD_ENC_VER_00 {
            // Trim off the version and base64 decode the rest
            let encrypted = base64::decode(
                &encrypted[PASSWORD_VERSION_LEN..],
                base64::Variant::Original,
            )
            .map_err(|_| "Failed to base64 decode the password")?;
            return symmetric(&encrypted, false, key).map(|x| String::from_utf8_lossy(&x).to_string());
        } else {
            Err(format!(
                "Unsupported RustDesk password version: {}",
                version
            ))?
        }
    }

    Err(format!("Nothing to decrypt: {}", version))?
}

pub fn symmetric(data: &[u8], encrypt: bool, key: Option<String>) -> Result<Vec<u8>, Box<dyn Error>> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    // Use the machine id as the key base
    let mut keybuf: Vec<u8> = match key {
        Some(x) => x.as_bytes().to_vec(),
        None => fs::read_to_string("/etc/machine-id")?.into(),
    };

    // Ensure the keybuf is 32 bytes, trimming or filling with 0
    keybuf.resize(secretbox::KEYBYTES, 0);

    // Now convert the 32 bytes into a usize 32
    let key = secretbox::Key(
        keybuf
            .try_into()
            .map_err(|_| "Failed to convert keybuf to key")?,
    );

    // Grab a nonce to use
    let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

    // Now encrypt or decrypt as directed
    if encrypt {
        return Ok(secretbox::seal(data, &nonce, &key));
    } else {
        let decrypted =
            secretbox::open(data, &nonce, &key).map_err(|_| "Failed to decrypt data")?;
        return Ok(decrypted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let data = "1ü1111";
        let key = "foobar".to_string();
        let encrypted = encrypt(data, PASSWORD_ENC_VER_00, Some(key.clone())).unwrap();
        let decrypted = decrypt(&encrypted, PASSWORD_ENC_VER_00, Some(key)).unwrap();

        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(PASSWORD_ENC_VER_00, &encrypted[..2]);
    }
}

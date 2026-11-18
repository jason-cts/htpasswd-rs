use std::{ffi::OsString, path::PathBuf};

use clap::Parser;

use crate::{AppError, hash::Algorithm};

#[derive(Debug, Parser)]
#[command(
    name = "htpasswd-rs",
    version,
    about = "Manage Apache-compatible password files",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Create or replace the password file.
    #[arg(short = 'c', group = "mode")]
    create: bool,

    /// Write the password record to stdout instead of a file.
    #[arg(short = 'n', group = "mode")]
    no_file: bool,

    /// Delete the user from the password file.
    #[arg(short = 'D', group = "mode")]
    delete: bool,

    /// Verify the user's password.
    #[arg(short = 'v', group = "mode")]
    verify: bool,

    /// Read the password from the command line.
    #[arg(short = 'b', conflicts_with = "stdin")]
    batch: bool,

    /// Read the password from stdin without a confirmation prompt.
    #[arg(short = 'i', conflicts_with = "batch")]
    stdin: bool,

    /// Use bcrypt (the default).
    #[arg(short = 'B', group = "algorithm")]
    bcrypt: bool,

    /// Set bcrypt cost (4–17; default: 12).
    #[arg(short = 'C', value_name = "COST", requires = "bcrypt")]
    cost: Option<u32>,

    /// Use Apache APR1-MD5.
    #[arg(short = 'm', group = "algorithm")]
    md5: bool,

    /// Use SHA-256-crypt.
    #[arg(short = '2', group = "algorithm", group = "sha2")]
    sha256: bool,

    /// Use SHA-512-crypt.
    #[arg(short = '5', group = "algorithm", group = "sha2")]
    sha512: bool,

    /// Set SHA-crypt rounds (1,000–999,999,999; default: 5,000).
    #[arg(short = 'r', value_name = "ROUNDS", requires = "sha2")]
    rounds: Option<u32>,

    /// Use traditional DES-crypt.
    #[arg(short = 'd', group = "algorithm")]
    des: bool,

    /// Use unsalted SHA-1.
    #[arg(short = 's', group = "algorithm")]
    sha1: bool,

    /// Store or verify a plaintext password (insecure).
    #[arg(short = 'p', group = "algorithm")]
    plaintext: bool,

    /// Password file and username, or username with -n.
    #[arg(value_name = "ARGS", num_args = 1..)]
    args: Vec<OsString>,
}

impl Cli {
    pub fn into_request(self) -> Result<Request, AppError> {
        let mode = if self.create {
            Mode::Create
        } else if self.no_file {
            Mode::Print
        } else if self.delete {
            Mode::Delete
        } else if self.verify {
            Mode::Verify
        } else {
            Mode::AddOrUpdate
        };

        let algorithm = if self.md5 {
            Algorithm::Apr1
        } else if self.sha256 {
            Algorithm::Sha256
        } else if self.sha512 {
            Algorithm::Sha512
        } else if self.des {
            Algorithm::Des
        } else if self.sha1 {
            Algorithm::Sha1
        } else if self.plaintext {
            Algorithm::Plaintext
        } else {
            Algorithm::Bcrypt
        };

        if self.cost.is_some_and(|cost| !(4..=17).contains(&cost)) {
            return Err(AppError::new(2, "bcrypt cost must be between 4 and 17"));
        }
        if self
            .rounds
            .is_some_and(|rounds| !(1_000..=999_999_999).contains(&rounds))
        {
            return Err(AppError::new(
                2,
                "SHA-crypt rounds must be between 1,000 and 999,999,999",
            ));
        }
        if matches!(mode, Mode::Delete) && (self.batch || self.stdin) {
            return Err(AppError::new(2, "-D cannot be combined with -b or -i"));
        }

        let mut args = self.args.into_iter();
        let (path, username_arg) = if mode == Mode::Print {
            (None, args.next())
        } else {
            let path = args.next().map(PathBuf::from);
            (path, args.next())
        };
        let username_arg = username_arg.ok_or_else(|| AppError::new(2, "username is required"))?;
        let username = username_arg
            .into_string()
            .map_err(|_| AppError::new(2, "username must be valid UTF-8"))?;

        if username.len() > 255 {
            return Err(AppError::new(5, "username too long (maximum 255 bytes)"));
        }
        if username
            .bytes()
            .any(|byte| matches!(byte, b':' | b'\r' | b'\n' | 0))
        {
            return Err(AppError::new(
                6,
                "username contains a colon, line break, or NUL byte",
            ));
        }

        let password_source = if self.batch {
            let value = args
                .next()
                .ok_or_else(|| AppError::new(2, "-b requires a password argument"))?;
            let value = value
                .into_string()
                .map_err(|_| AppError::new(2, "password must be valid UTF-8"))?;
            PasswordSource::Batch(zeroize::Zeroizing::new(value))
        } else if self.stdin {
            PasswordSource::Stdin
        } else {
            PasswordSource::Prompt
        };

        if args.next().is_some() {
            return Err(AppError::new(2, "too many arguments"));
        }

        Ok(Request {
            mode,
            path,
            username,
            password_source,
            algorithm,
            bcrypt_cost: self.cost.unwrap_or(12),
            rounds: self.rounds.unwrap_or(5_000),
            plaintext_verify: self.plaintext,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    AddOrUpdate,
    Create,
    Print,
    Delete,
    Verify,
}

pub enum PasswordSource {
    Batch(zeroize::Zeroizing<String>),
    Stdin,
    Prompt,
}

pub struct Request {
    pub mode: Mode,
    pub path: Option<PathBuf>,
    pub username: String,
    pub password_source: PasswordSource,
    pub algorithm: Algorithm,
    pub bcrypt_cost: u32,
    pub rounds: u32,
    pub plaintext_verify: bool,
}

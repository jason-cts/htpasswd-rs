mod cli;
mod hash;
mod password_file;

use std::{
    io::Write,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
};

use clap::{Parser, error::ErrorKind};
use cli::{Cli, Mode, PasswordSource};
use password_file::PasswordFile;
use zeroize::Zeroizing;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    if let Err(error) = ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst)) {
        eprintln!("htpasswd-rs: cannot install interrupt handler: {error}");
        return ExitCode::from(9);
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let exit = match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
            let _ = error.print();
            return ExitCode::from(exit);
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("htpasswd-rs: {}", error.message);
            ExitCode::from(error.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    check_interrupted()?;
    let parsed = cli.into_request()?;
    match parsed.mode {
        Mode::Print => {
            let password = read_password(parsed.password_source, false)?;
            let record = Zeroizing::new(
                hash::hash_password(
                    &password,
                    parsed.algorithm,
                    parsed.bcrypt_cost,
                    parsed.rounds,
                )
                .map_err(|error| AppError::new(error.exit_code, error.message))?,
            );
            check_interrupted()?;
            writeln!(
                std::io::stdout().lock(),
                "{}:{}",
                parsed.username,
                record.as_str()
            )
            .map_err(|error| AppError::new(1, format!("cannot write record: {error}")))?;
        }
        Mode::AddOrUpdate | Mode::Create | Mode::Delete | Mode::Verify => {
            let path = parsed
                .path
                .as_deref()
                .ok_or_else(|| AppError::new(2, "password file is required"))?;
            let password_file = PasswordFile::open(path, parsed.mode != Mode::Create)?;
            check_interrupted()?;

            match parsed.mode {
                Mode::AddOrUpdate | Mode::Create => {
                    let password = read_password(parsed.password_source, false)?;
                    let record = Zeroizing::new(
                        hash::hash_password(
                            &password,
                            parsed.algorithm,
                            parsed.bcrypt_cost,
                            parsed.rounds,
                        )
                        .map_err(|error| AppError::new(error.exit_code, error.message))?,
                    );
                    check_interrupted()?;
                    let outcome = password_file.add_or_update(
                        &parsed.username,
                        &record,
                        parsed.mode == Mode::Create,
                    )?;
                    eprintln!("{} password for user {}", outcome, parsed.username);
                }
                Mode::Delete => {
                    let deleted = password_file.delete(&parsed.username)?;
                    if deleted {
                        eprintln!("Deleted password for user {}", parsed.username);
                    } else {
                        eprintln!("User {} not found", parsed.username);
                    }
                }
                Mode::Verify => {
                    let stored_hash = password_file.lookup_all(&parsed.username)?;
                    if stored_hash.is_empty() {
                        return Err(AppError::new(
                            6,
                            format!("user {} not found", parsed.username),
                        ));
                    }
                    let password = read_password(parsed.password_source, true)?;
                    for hash in stored_hash {
                        if !hash::verify_password(&password, &hash, parsed.plaintext_verify)
                            .map_err(|message| AppError::new(7, message))?
                        {
                            return Err(AppError::new(3, "password verification failed"));
                        }
                    }
                    eprintln!("Password for user {} correct.", parsed.username);
                }
                Mode::Print => unreachable!(),
            }
        }
    }
    Ok(())
}

fn read_password(source: PasswordSource, verify: bool) -> Result<Zeroizing<String>, AppError> {
    let password = match source {
        PasswordSource::Batch(password) => password,
        PasswordSource::Stdin => {
            use std::io::{BufRead, Read};
            let mut input = Vec::with_capacity(257);
            std::io::stdin()
                .lock()
                .take(257)
                .read_until(b'\n', &mut input)
                .map_err(input_error)?;
            if input.last() == Some(&b'\n') {
                input.pop();
                if input.last() == Some(&b'\r') {
                    input.pop();
                }
            }
            if input.len() > 255 {
                return Err(AppError::new(5, "password too long (maximum 255 bytes)"));
            }
            let input = String::from_utf8(input)
                .map_err(|_| AppError::new(1, "password from stdin is not valid UTF-8"))?;
            Zeroizing::new(input)
        }
        PasswordSource::Prompt => {
            let prompt = if verify {
                "Password: "
            } else {
                "New password: "
            };
            let first = rpassword::prompt_password(prompt).map_err(input_error)?;
            let first = Zeroizing::new(first);
            if !verify {
                let second = Zeroizing::new(
                    rpassword::prompt_password("Re-type new password: ").map_err(input_error)?,
                );
                if first.as_str() != second.as_str() {
                    return Err(AppError::new(
                        3,
                        "password verification entries did not match",
                    ));
                }
            }
            first
        }
    };

    check_interrupted()?;

    if password.len() > 255 {
        return Err(AppError::new(5, "password too long (maximum 255 bytes)"));
    }
    Ok(password)
}

fn check_interrupted() -> Result<(), AppError> {
    if INTERRUPTED.load(Ordering::SeqCst) {
        Err(AppError::new(4, "operation interrupted"))
    } else {
        Ok(())
    }
}

fn input_error(error: std::io::Error) -> AppError {
    if INTERRUPTED.load(Ordering::SeqCst) {
        AppError::new(4, "operation interrupted")
    } else {
        AppError::new(1, format!("cannot read password: {error}"))
    }
}

#[derive(Debug)]
struct AppError {
    exit_code: u8,
    message: String,
}

impl AppError {
    fn new(exit_code: u8, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }
}

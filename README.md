# htpasswd-rs

`htpasswd-rs` is a Rust command-line implementation for creating and managing Apache-compatible `htpasswd` files. It runs on Linux, macOS, and Windows.

## Install

From a checkout, install the executable into Cargo's binary directory with:

```sh
cargo install --path .
```

## Usage

```text
htpasswd-rs [-c | -n | -D | -v] [-b | -i] [-B | -m | -2 | -5 | -d | -s | -p]
            [-C cost] [-r rounds] password-file username [password]
```

Without `-b` or `-i`, the program asks for the password without echoing it. When adding or changing a password interactively, it asks twice to catch typing mistakes.

```sh
# Create a file and add a user. Bcrypt cost defaults to 12.
htpasswd-rs -c users.htpasswd alice

# Update a user, taking the password from stdin.
printf '%s\n' 'correct horse battery staple' | htpasswd-rs -i users.htpasswd alice

# Print a record for another service to store.
htpasswd-rs -n alice

# Verify a password, or remove a user.
htpasswd-rs -v users.htpasswd alice
htpasswd-rs -D users.htpasswd alice
```

`-b` reads the password from the command line and exposes it to process listings. Prefer the hidden prompt or `-i` in scripts.

## Hash formats

The default is bcrypt with cost 12, encoded with the Apache-compatible `$2y$` identifier. Use `-C` to select a cost from 4 to 17. Passwords longer than bcrypt's 72-byte input limit are truncated, matching Apache's behavior.

The compatibility options are `-m` for Apache APR1-MD5, `-2` for SHA-256-crypt, `-5` for SHA-512-crypt, `-d` for DES-crypt, `-s` for SHA-1, and `-p` for plaintext. SHA-crypt uses 5,000 rounds by default; `-r` changes the rounds from 1,000 to 999,999,999. DES-crypt, SHA-1, and plaintext are legacy formats and should only be selected when compatibility requires them.

Plaintext verification is explicit: use `-p` with `-v` to verify a plaintext record. Other supported formats are detected from the stored hash.

## Exit status

The command returns 0 on success; 1 for file access errors; 2 for invalid arguments; 3 for a password mismatch; 4 for an interrupted operation; 5 for an overlong value; 6 for an invalid or missing username; and 7 for an invalid password file or hash. Randomness and hashing failures return 8 and 9.


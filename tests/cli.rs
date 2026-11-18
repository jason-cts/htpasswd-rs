#[cfg(unix)]
use std::time::Duration;
use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
};

use tempfile::tempdir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_htpasswd-rs"))
}

fn run(args: &[&str]) -> Output {
    binary().args(args).output().unwrap()
}

#[test]
fn supports_create_update_verify_delete_and_print() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let path = path.to_str().unwrap();

    let created = run(&["-cbB", "-C", "4", path, "alice", "first"]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(
        fs::read_to_string(path)
            .unwrap()
            .starts_with("alice:$2y$04$")
    );

    let updated = run(&["-b", "-B", "-C", "4", path, "alice", "second"]);
    assert!(
        updated.status.success(),
        "{}",
        String::from_utf8_lossy(&updated.stderr)
    );

    let verified = run(&["-v", "-b", path, "alice", "second"]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let rejected = run(&["-v", "-b", path, "alice", "wrong"]);
    assert_eq!(rejected.status.code(), Some(3));

    let deleted = run(&["-D", path, "alice"]);
    assert!(deleted.status.success());
    assert!(fs::read_to_string(path).unwrap().is_empty());

    let printed = run(&["-n", "-b", "-m", "alice", "secret"]);
    assert!(printed.status.success());
    assert_eq!(
        printed.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    assert!(String::from_utf8_lossy(&printed.stdout).starts_with("alice:$apr1$"));

    let missing = run(&["-v", "-b", path, "missing", "secret"]);
    assert_eq!(missing.status.code(), Some(6));
}

#[test]
fn default_bcrypt_cost_is_12() {
    let output = run(&["-n", "-b", "alice", "secret"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("alice:$2y$12$"));
}

#[test]
fn reads_first_password_line_from_stdin() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let mut child = binary()
        .args(["-c", "-i", "-B", "-C", "4"])
        .arg(&path)
        .arg("alice")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"secret\nignored\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let record = fs::read_to_string(&path).unwrap();
    assert!(record.starts_with("alice:$2y$04$"));
    let path_str = path.to_str().unwrap();
    let verified = run(&["-v", "-b", path_str, "alice", "secret"]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn rejects_stdin_passwords_over_255_bytes_without_creating_the_file() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let mut child = binary()
        .args(["-c", "-i"])
        .arg(&path)
        .arg("alice")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[vec![b'x'; 256], vec![b'\n']].concat())
        .unwrap();
    let output = child.wait().unwrap();
    assert_eq!(output.code(), Some(5));
    assert!(!path.exists());
}

#[test]
fn plaintext_records_require_explicit_plaintext_verification() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let path = path.to_str().unwrap();

    let created = run(&["-c", "-b", "-p", path, "alice", "secret"]);
    assert!(created.status.success());
    let verified = run(&["-v", "-b", "-p", path, "alice", "secret"]);
    assert!(verified.status.success());
    let autodetect = run(&["-v", "-b", path, "alice", "secret"]);
    assert_eq!(autodetect.status.code(), Some(7));
}

#[cfg(unix)]
#[test]
fn ctrl_c_returns_the_interrupted_exit_status() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let mut child = binary()
        .args(["-c", "-i"])
        .arg(&path)
        .arg("alice")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let signal = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    drop(child.stdin.take());
    let output = child.wait().unwrap();
    assert_eq!(output.code(), Some(4));
}

#[test]
fn interoperates_with_apache_htpasswd_when_available() {
    if Command::new("htpasswd").arg("-h").output().is_err() {
        return;
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("users.htpasswd");
    let path_str = path.to_str().unwrap();
    let formats: &[&[&str]] = &[
        &["-B", "-C", "4"],
        &["-m"],
        &["-2", "-r", "1000"],
        &["-5", "-r", "1000"],
        &["-d"],
        &["-s"],
    ];

    for format in formats {
        let mut rust_args = vec!["-n", "-b"];
        rust_args.extend_from_slice(format);
        rust_args.extend_from_slice(&["alice", "secret"]);
        let rust_record = run(&rust_args);
        assert!(
            rust_record.status.success(),
            "Rust hash failed for {format:?}: {}",
            String::from_utf8_lossy(&rust_record.stderr)
        );
        fs::write(&path, &rust_record.stdout).unwrap();

        let apache_verify = Command::new("htpasswd")
            .args(["-v", "-b", path_str, "alice", "secret"])
            .output()
            .unwrap();
        assert!(
            apache_verify.status.success(),
            "Apache rejected {format:?}: {}",
            String::from_utf8_lossy(&apache_verify.stderr)
        );

        let mut apache_args = vec!["-n", "-b"];
        apache_args.extend_from_slice(format);
        apache_args.extend_from_slice(&["alice", "secret"]);
        let apache_record = Command::new("htpasswd")
            .args(&apache_args)
            .output()
            .unwrap();
        assert!(apache_record.status.success());
        let apache_record = apache_record
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap();
        fs::write(&path, [apache_record, b"\n"].concat()).unwrap();

        let rust_verify = run(&["-v", "-b", path_str, "alice", "secret"]);
        assert!(
            rust_verify.status.success(),
            "Rust rejected Apache {format:?}: {}",
            String::from_utf8_lossy(&rust_verify.stderr)
        );
    }
}

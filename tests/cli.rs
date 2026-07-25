use assert_cmd::Command;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a unique temporary directory populated with the given files
/// (relative path -> contents) and return its path.
fn make_repo(files: &[(&str, &str)]) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secret-scan-test-{}", nanos));
    fs::create_dir_all(&dir).unwrap();
    for (rel, contents) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }
    dir
}

fn run(args: &[&str]) -> String {
    let output = Command::cargo_bin("securekit")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "process failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn detects_aws_and_github_secrets() {
    let dir = make_repo(&[(
        "config.txt",
        "aws=AKIA1234567890ABCDEF\ntoken=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
    )]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json", "--show-raw-secrets"]);

    assert!(out.contains("\"has_leak\": true"), "output: {}", out);
    assert!(out.contains("aws_access_key"), "output: {}", out);
    assert!(out.contains("github_token"), "output: {}", out);
    assert!(out.contains("AKIA1234567890ABCDEF"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn redacts_secrets_by_default() {
    let dir = make_repo(&[("secrets.env", "AWS_KEY=AKIA1234567890ABCDEF\n")]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("aws_access_key"), "output: {}", out);
    // Raw value must not appear when redaction is on (the default).
    assert!(
        !out.contains("AKIA1234567890ABCDEF"),
        "raw secret leaked: {}",
        out
    );
    // Fingerprint is always present so leaks stay trackable.
    assert!(out.contains("sha256:"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn default_ignores_filter_examples() {
    // The literal "example" placeholder should be ignored by default rules.
    let dir = make_repo(&[(
        "readme.md",
        "example token: ghp_exampleabcdefghijklmnopqrstuvwxyz012\n",
    )]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("\"has_leak\": false"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn clean_repo_reports_no_leak() {
    let dir = make_repo(&[("main.rs", "fn main() { println!(\"hello\"); }\n")]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("\"has_leak\": false"), "output: {}", out);
    assert!(
        out.contains("\"repositories_with_likely_leaked_secrets\": 0"),
        "output: {}",
        out
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn detects_private_key_and_jwt() {
    let dir = make_repo(&[(
        "keys.txt",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n\
         jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKL\n",
    )]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("private_key"), "output: {}", out);
    assert!(out.contains("jwt"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

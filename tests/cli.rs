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

/// Test secrets are assembled at runtime so the fixture literals don't trip
/// external secret scanners (push protection, gitleaks); our own scanner still
/// sees identical bytes and detects them.
fn fake_aws_key() -> String {
    format!("AKIA{}", "1234567890ABCDEF")
}

fn fake_github_pat() -> String {
    format!("ghp_{}", "0123456789abcdefghijklmnopqrstuvwxyz")
}

#[test]
fn detects_aws_and_github_secrets() {
    let aws_key = fake_aws_key();
    let gh_token = fake_github_pat();
    let content = format!("aws={}\ntoken={}\n", aws_key, gh_token);
    let dir = make_repo(&[("config.txt", content.as_str())]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json", "--show-raw-secrets"]);

    assert!(out.contains("\"has_leak\": true"), "output: {}", out);
    assert!(out.contains("aws_access_key"), "output: {}", out);
    assert!(out.contains("github_token"), "output: {}", out);
    assert!(out.contains(&aws_key), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn redacts_secrets_by_default() {
    let aws_key = fake_aws_key();
    let content = format!("AWS_KEY={}\n", aws_key);
    let dir = make_repo(&[("secrets.env", content.as_str())]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("aws_access_key"), "output: {}", out);
    // Raw value must not appear when redaction is on (the default).
    assert!(!out.contains(&aws_key), "raw secret leaked: {}", out);
    // Fingerprint is always present so leaks stay trackable.
    assert!(out.contains("sha256:"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn default_ignores_filter_examples() {
    // The literal "example" placeholder should be ignored by default rules.
    let example_token = format!("ghp_{}", "exampleabcdefghijklmnopqrstuvwxyz012");
    let content = format!("example token: {}\n", example_token);
    let dir = make_repo(&[("readme.md", content.as_str())]);
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
    let private_key = format!(
        "-----BEGIN RSA PRIVATE {k}-----\nMIIabc\n-----END RSA PRIVATE {k}-----",
        k = "KEY"
    );
    let jwt = format!(
        "{}.{}.{}",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "abcDEFghiJKL"
    );
    let content = format!("{}\njwt={}\n", private_key, jwt);
    let dir = make_repo(&[("keys.txt", content.as_str())]);
    let dir_str = dir.to_str().unwrap();

    let out = run(&[dir_str, "--output", "json"]);

    assert!(out.contains("private_key"), "output: {}", out);
    assert!(out.contains("jwt"), "output: {}", out);

    fs::remove_dir_all(&dir).ok();
}

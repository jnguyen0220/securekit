# Secret repository scanner

This workspace contains the Rust implementation of the secret scanner as the primary application.

It supports:

- parallel repository scanning
- JSON and CSV output
- configurable ignore rules for common false positives

## Dev container

If you use VS Code, you can open the workspace in a container via the Dev Containers extension. The repository includes a Rust devcontainer configuration in [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json).

## Install Rust

If Cargo is not installed yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

```bash
cd /home/ubuntu/project/sec
cargo build --release
```

## Run examples

Text output:

```bash
./target/release/secret_repo_scanner --repo-file repos.txt
```

JSON output:

```bash
./target/release/secret_repo_scanner --repo-file repos.txt --output json
```

CSV output:

```bash
./target/release/secret_repo_scanner --repo-file repos.txt --output csv --output-file results.csv
```

Ignore rules:

```bash
./target/release/secret_repo_scanner --repo-file repos.txt --ignore-pattern 'example' --ignore-pattern 'placeholder'
```

Ignore file:

```bash
./target/release/secret_repo_scanner --repo-file repos.txt --ignore-file ignores.txt
```

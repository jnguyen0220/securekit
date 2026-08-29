# Secret repository scanner

This workspace contains the Rust implementation of the secret scanner as the primary application.

It supports:

- parallel repository scanning
- JSON, CSV, and text output
- configurable ignore rules for common false positives
- a broad set of secret patterns (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, SendGrid, Twilio, npm, private keys, JWTs, ...)
- **secret redaction by default** plus SHA-256 fingerprints, so runs never accumulate live credentials
- GitHub search, presets, and **public-repo enumeration** (with sharding) for research/disclosure
- automated **responsible-disclosure reports**
- a **distributed server/client mode** to spread scanning across many workers

## Dev container

If you use VS Code, you can open the workspace in a container via the Dev Containers extension. The repository includes a Rust devcontainer configuration in [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json).

## Install Rust

If Cargo is not installed yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

```bash
cargo build --release
```

## Quick start (helper scripts)

The repository ships three convenience scripts that build and run the scanner
for you.

### One-off scan

```bash
# Passes any arguments straight through to the binary.
./scripts/start.sh --repo-file repos.txt --output json
```

### Distributed public-repo crawl

This is the easiest way to run a coordinated crawl: the **server** enumerates
public repositories from GitHub and hands them out; one or more **clients**
(bots) claim, scan, and report back only redacted findings.

1. Start the server. On first run it enumerates public repositories from the
   GitHub `List public repositories` API and writes their clone URLs into the
   shared target list (`repos.txt`), then serves them:

   ```bash
   ./scripts/start-server.sh
   ```

   Tune the enumeration with environment variables:

   ```bash
   SECUREKIT_ENUM_COUNT=5000 \   # how many public repos to enumerate
   SECUREKIT_SINCE=1000000 \     # start after this numeric repo id (cursor)
   SECUREKIT_FORCE_ENUM=1 \      # rebuild the list even if one exists
   ./scripts/start-server.sh
   ```

   Provide a `GITHUB_TOKEN` (in the environment or `.env`) for real
   enumeration; anonymous access is capped at 60 requests/hour.

2. In another terminal, start one or more scanning bots pointing at the server.
   Give each a distinct worker id so the server can lease each repo to a single
   bot at a time:

   ```bash
   ./scripts/start-client.sh http://127.0.0.1:8080 bot-1
   ./scripts/start-client.sh http://127.0.0.1:8080 bot-2   # optional, run in parallel
   ```

   Adjust the claim batch size via the environment:

   ```bash
   CLAIM_BATCH=8 ./scripts/start-client.sh http://127.0.0.1:8080 bot-1
   ```

Redacted findings are appended to `results.jsonl` (`SECUREKIT_RESULTS_FILE`).
Bots exit automatically once the server has no more work to hand out.

## Run examples

Text output:

```bash
./target/release/securekit --repo-file repos.txt
```

JSON output:

```bash
./target/release/securekit --repo-file repos.txt --output json
```

CSV output:

```bash
./target/release/securekit --repo-file repos.txt --output csv --output-file results.csv
```

Ignore rules:

```bash
./target/release/securekit --repo-file repos.txt --ignore-pattern 'example' --ignore-pattern 'placeholder'
```

Ignore file:

```bash
./target/release/securekit --repo-file repos.txt --ignore-file ignores.txt
```

## Secret redaction

By default, secret values are **redacted** in all output (only the first/last 4
characters are shown) and each finding carries a `sha256:` fingerprint. This
keeps your logs, results files, and databases from becoming a store of live
credentials while still letting you track and de-duplicate leaks.

To show raw values (not recommended):

```bash
./target/release/securekit ./my-repo --output json --show-raw-secrets
```

## Configuration (.env)

On startup the scanner loads simple `KEY=VALUE` pairs from a `.env` file in the
current directory (existing environment variables win). This is the easiest way
to supply a GitHub token and configure server mode. See
[.env.example](.env.example) for a fully documented template.

```dotenv
# GitHub auth (either variable works)
GITHUB_TOKEN=ghp_your_token_here

# Optional request identity for long-running API clients
# SECUREKIT_USER_AGENT=securekit/1.0 (+https://example.org/security)
# SECUREKIT_USER_AGENT_CONTACT=security@example.org

# Optional GitHub API retry tuning (default: 3 retries for 5xx)
# SECUREKIT_GITHUB_5XX_RETRIES=3

# Server mode
SECUREKIT_BIND=127.0.0.1:8080
SECUREKIT_LIST_FILE=repos.txt
SECUREKIT_RESULTS_FILE=results.jsonl
SECUREKIT_LEASE_SECS=300
```

## GitHub authentication (PAT or App)

The scanner resolves the best available credential automatically, in this
priority order:

1. **GitHub App installation token** — used when `GITHUB_APP_ID`,
   `GITHUB_APP_INSTALLATION_ID`, and a private key
   (`GITHUB_APP_PRIVATE_KEY_PATH` or inline `GITHUB_APP_PRIVATE_KEY`) are all
   set. The scanner mints a short-lived RS256 JWT, exchanges it for an
   installation access token, and uses that for API calls **and** authenticated
   `git clone`. App tokens have much higher rate limits than a PAT and rotate
   automatically.
2. **Personal access token** — `GITHUB_TOKEN`, then `GH_TOKEN`.
3. **Anonymous** — capped at 60 requests/hour.

If App auth fails for any reason, it logs a warning and falls back to the PAT,
then to anonymous. Example App configuration in `.env`:

```dotenv
GITHUB_APP_ID=123456
GITHUB_APP_INSTALLATION_ID=98765432
GITHUB_APP_PRIVATE_KEY_PATH=./securekit-app.private-key.pem
```

Installation tokens are **auto-refreshed**: the scanner re-mints the token as it
nears its ~1 hour expiry (and immediately on a `401 Unauthorized`), so
long-running crawls, enumeration, and client bots keep authenticating without
restarts.

For long-running automation, set a clear request identity using
`SECUREKIT_USER_AGENT` (or `SECUREKIT_USER_AGENT_CONTACT` with the default
`securekit/<version>` format). GitHub API requests also retry transient `5xx`
responses with exponential backoff and jitter; tune retry count with
`SECUREKIT_GITHUB_5XX_RETRIES`.

When a token is available (App or PAT), clones of `https://github.com/...`
repositories are authenticated, which raises rate limits and allows cloning
private repositories the token/installation can access.

## GitHub search & enumeration

Search GitHub for repositories to scan:

```bash
./target/release/securekit --github-search 'stars:10..500 language:python' --github-limit 20
```

Use a preset query instead of writing one:

```bash
./target/release/securekit --github-preset active-python --github-limit 20
```

Enumerate public repositories via the GitHub API (for research / responsible
disclosure). Work can be sharded across a fleet of workers with
`--shard-count`/`--shard-index` (a worker processes repos where
`id % shard_count == shard_index`) and bounded with `--since`/`--until`:

```bash
./target/release/securekit \
  --enumerate-public --since 1000000 --until 2000000 \
  --shard-count 4 --shard-index 0 --enumerate-limit 500
```

A `GITHUB_TOKEN` is strongly recommended; anonymous access is capped at 60
requests/hour. Rate limits are honored automatically with backoff.

## Responsible-disclosure reports

Write one Markdown report per repository that has findings. Secrets in these
reports are **always redacted**, and each report includes maintainer contact
channels (security policy / advisory links):

```bash
./target/release/securekit --repo-file repos.txt --disclosure-dir ./disclosures
```

## Distributed server/client mode

For large scans you can run a coordination **server** that hands out work and
collects results, and any number of **clients** that scan locally and report
back **only redacted** findings (raw secrets never leave the client machine).

The quickest path is the helper scripts described in
[Quick start](#quick-start-helper-scripts): `./scripts/start-server.sh` enumerates
public repositories and serves them, and `./scripts/start-client.sh` runs a scanning
bot. The steps below show the equivalent raw commands.

Start the server (reads its target list and bind address from `.env`):

```bash
# uses SECUREKIT_LIST_FILE / SECUREKIT_BIND / SECUREKIT_RESULTS_FILE from .env
./target/release/securekit-server
```

The server exposes:

| Method | Path      | Purpose                    |
|--------|-----------|----------------------------|
| GET    | `/health` | liveness probe             |
| POST   | `/claim`  | lease work items           |
| POST   | `/report` | submit redacted findings   |
| GET    | `/stats`  | queue snapshot + perf summary |

Run one or more clients pointing at the server:

```bash
./target/release/securekit-client http://127.0.0.1:8080 --worker-id worker-a
```

A client needs **only the server URL** — no credential and no scan settings.
It registers, then claims batches of public-repo URLs from the server's queue
and scans them **anonymously** in parallel (the batch size and scan-thread count
are configured on the server via `SECUREKIT_CLAIM_BATCH` / `SECUREKIT_SCAN_WORKERS`
and handed out on `/register`). Run multiple clients with distinct
`--worker-id`s to scale out further.

Claimed items are leased for `SECUREKIT_LEASE_SECS`; if a client crashes, its
leases expire and the items are automatically re-queued. Results are appended as
JSON Lines to `SECUREKIT_RESULTS_FILE`.

The server depends only on the `TargetStore` trait, so an alternative backend
(e.g. a database) can be added later by implementing that trait.

//! Git operations backed by [`gix`] (gitoxide) so the binaries carry their own
//! git implementation and do not shell out to a system `git` executable.
//!
//! Three operations are needed across the client and server:
//! * shallow (depth-1) clone of a repository for scanning,
//! * resolving the HEAD commit of a local checkout, and
//! * resolving the HEAD commit of a remote URL without cloning (the `ls-remote`
//!   equivalent), optionally bounded by a timeout.

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

/// Perform a depth-1 clone of `clone_url` into `dest` (which must not yet
/// exist as a populated repo), checking out the work tree.
pub(crate) fn shallow_clone(clone_url: &str, dest: &Path) -> Result<()> {
    let url = gix::url::parse(gix::bstr::BStr::new(clone_url)).context("invalid clone URL")?;

    let mut prepare = gix::prepare_clone(url, dest)
        .context("prepare clone failed")?
        .with_shallow(gix::remote::fetch::Shallow::DepthAtRemote(
            NonZeroU32::new(1).expect("1 is non-zero"),
        ));

    let (mut checkout, _) = prepare
        .fetch_then_checkout(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .context("fetch failed")?;

    checkout
        .main_worktree(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
        .context("checkout failed")?;

    Ok(())
}

/// Resolve the HEAD commit SHA of a local checkout at `dir`.
///
/// Returns `Ok(None)` when HEAD is unborn (e.g. a freshly-initialized repo with
/// no commits).
pub(crate) fn local_head_sha(dir: &Path) -> Result<Option<String>> {
    let repo = gix::open(dir).with_context(|| format!("open repo {}", dir.display()))?;
    let head = repo
        .head()
        .with_context(|| format!("read HEAD for {}", dir.display()))?;
    Ok(head.id().map(|id| id.to_hex().to_string()))
}

/// Resolve the HEAD commit SHA of a remote repository `remote_url` without
/// cloning it (equivalent to `git ls-remote <url> HEAD`).
///
/// Returns `Ok(None)` when the remote advertises no HEAD (e.g. an empty repo).
pub(crate) fn remote_head_sha(remote_url: &str) -> Result<Option<String>> {
    // A remote handle needs a repository context; a throwaway bare repo is
    // enough since we only read advertised refs and fetch no objects.
    let scratch = std::env::temp_dir().join(format!(
        "securekit-gix-{}-{}",
        std::process::id(),
        scratch_counter()
    ));
    let repo = gix::init_bare(&scratch)
        .with_context(|| format!("init scratch repo at {}", scratch.display()))?;

    let result = remote_head_sha_in(&repo, remote_url);
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn remote_head_sha_in(repo: &gix::Repository, remote_url: &str) -> Result<Option<String>> {
    let url = gix::url::parse(gix::bstr::BStr::new(remote_url)).context("invalid remote URL")?;
    let remote = repo
        .remote_at(url)
        .with_context(|| format!("configure remote for {}", remote_url))?;

    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .with_context(|| format!("connect to {}", remote_url))?;

    // The anonymous remote has no refspecs, so leave the remote's ref
    // advertisement unfiltered; otherwise gix maps zero refs and HEAD is lost.
    let options = gix::remote::ref_map::Options {
        prefix_from_spec_as_filter_on_remote: false,
        ..Default::default()
    };
    let (ref_map, _handshake) = connection
        .ref_map(gix::progress::Discard, options)
        .with_context(|| format!("list refs for {}", remote_url))?;

    for r in ref_map.remote_refs.iter() {
        let (name, target, peeled) = r.unpack();
        if name == "HEAD" {
            if let Some(oid) = peeled.or(target) {
                return Ok(Some(oid.to_hex().to_string()));
            }
        }
    }
    Ok(None)
}

/// Monotonic counter so concurrent remote checks get distinct scratch dirs.
fn scratch_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Like [`remote_head_sha`] but aborts with an error if it does not finish
/// within `timeout`.
pub(crate) fn remote_head_sha_timed(remote_url: &str, timeout: Duration) -> Result<Option<String>> {
    let (tx, rx) = mpsc::channel();
    let url = remote_url.to_string();
    thread::spawn(move || {
        let _ = tx.send(remote_head_sha(&url));
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!(
                "read remote HEAD for {} timed out after {}s",
                remote_url,
                timeout.as_secs()
            )
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("remote HEAD check for {} failed unexpectedly", remote_url)
        }
    }
}

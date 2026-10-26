use std::{path::PathBuf, process::Command, str};
fn main() -> anyhow::Result<()> {
    // The official native image has Git 1.8.3.1: it echoes unsupported
    // `rev-parse --git-path` with exit 0 instead of resolving a path. Use the
    // older --git-dir and the linked-worktree commondir file explicitly.
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "cannot resolve Agent Git directory"
    );
    let git_dir = PathBuf::from(str::from_utf8(&output.stdout)?.trim()).canonicalize()?;
    let common_file = git_dir.join("commondir");
    let common_dir = if common_file.exists() {
        git_dir
            .join(std::fs::read_to_string(&common_file)?.trim())
            .canonicalize()?
    } else {
        git_dir.clone()
    };
    for path in [
        git_dir.join("HEAD"),
        common_file,
        common_dir.join("refs/heads"),
        common_dir.join("packed-refs"),
    ] {
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

Ok(())
}

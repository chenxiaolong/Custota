// SPDX-FileCopyrightText: 2025 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};

fn run_and_get_output(mut command: Command) -> Result<String> {
    let mut output = command.output()?;

    if !output.status.success() {
        bail!(
            "{command:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let last_char = output.stdout.pop();
    if last_char != Some(b'\n') {
        bail!("{command:?} output did not end in newline");
    }

    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("{command:?} output is not UTF-8"))?;

    Ok(stdout)
}

fn git_root_dir() -> Result<String> {
    let mut command = Command::new("git");
    command.arg("rev-parse");
    command.arg("--show-toplevel");

    run_and_get_output(command)
}

fn git_describe(path: &Path) -> Result<String> {
    let mut command = Command::new("git");
    command.arg("describe");
    command.arg("--long");
    command.current_dir(path);

    run_and_get_output(command)
}

fn git_commit_count(path: &Path) -> Result<u32> {
    let mut command = Command::new("git");
    command.arg("rev-list");
    command.arg("--count");
    command.arg("HEAD");
    command.current_dir(path);

    let output = run_and_get_output(command)?;

    output
        .parse()
        .with_context(|| format!("Failed to parse git commit count: {output:?}"))
}

fn git_short_sha(path: &Path) -> Result<String> {
    let mut command = Command::new("git");
    command.arg("rev-parse");
    command.arg("--short");
    command.arg("HEAD");
    command.current_dir(path);

    run_and_get_output(command)
}

#[derive(Debug)]
struct VersionInfo {
    tag: Option<String>,
    // Since tag if tag is present. Otherwise, since beginning.
    commit_count: u32,
    short_sha: String,
}

// Keep in sync with how we compute the version in app/build.gradle.kts.
impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag.as_deref().unwrap_or("NONE"))?;

        if self.commit_count > 0 {
            write!(f, ".r{}.g{}", self.commit_count, self.short_sha)?;
        }

        Ok(())
    }
}

// Keep in sync with how we compute the version in app/build.gradle.kts.
fn get_version_info() -> Result<VersionInfo> {
    let git_root_dir = git_root_dir()
        .map(PathBuf::from)
        .context("Failed to find git repo root")?;
    let mut head_path = git_root_dir.join(".git");
    head_path.push("HEAD");

    if !head_path.exists() {
        bail!("{head_path:?} does not exist");
    }

    println!("cargo:rerun-if-changed={}", head_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let version_info = if let Ok(describe) = git_describe(&git_root_dir) {
        let mut iter = describe.rsplitn(3, "-");
        let short_sha = iter
            .next()
            .and_then(|s| s.strip_prefix("g"))
            .ok_or_else(|| anyhow!("Missing short commit SHA: {describe}"))?;
        let commit_count = iter
            .next()
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| anyhow!("Missing commit count: {describe}"))?;
        let tag = iter
            .next()
            .ok_or_else(|| anyhow!("Missing tag: {describe}"))?;

        VersionInfo {
            tag: Some(tag.to_owned()),
            commit_count,
            short_sha: short_sha.to_owned(),
        }
    } else {
        VersionInfo {
            tag: None,
            commit_count: git_commit_count(&git_root_dir)?,
            short_sha: git_short_sha(&git_root_dir)?,
        }
    };

    Ok(version_info)
}

fn main() {
    let version_info = get_version_info().unwrap();
    println!("cargo:rustc-env=GIT_VERSION={version_info}");
}

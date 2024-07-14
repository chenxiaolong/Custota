// SPDX-FileCopyrightText: 2024 Andrew Gunnerson
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser};

use sepatch::PolicyDb;

pub fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut pdb = {
        let path = cli.source.as_path();
        let file =
            File::open(path).with_context(|| format!("Failed to open for reading: {path:?}"))?;

        let mut warnings = vec![];
        let pdb = PolicyDb::from_reader(file, &mut warnings)
            .with_context(|| format!("Failed to read sepolicy: {path:?}"))?;

        if !warnings.is_empty() {
            eprintln!("Warnings when loading sepolicy:");
            for warning in warnings {
                eprintln!("- {warning}");
            }
        }

        pdb
    };

    let n_source_type = "untrusted_app";
    let n_source_uffd_type = "untrusted_app_userfaultfd";
    let n_target_type = "custota_app";
    let n_target_uffd_type = "custota_app_userfaultfd";

    macro_rules! t {
        ($name:expr) => {{
            let name = $name;
            pdb.get_type_id(name)
                .ok_or_else(|| anyhow!("Type not found: {name}"))?
        }};
    }
    macro_rules! c {
        ($name:expr) => {{
            let name = $name;
            pdb.get_class_id(name)
                .ok_or_else(|| anyhow!("Class not found: {name}"))?
        }};
    }
    macro_rules! p {
        ($class_id:expr, $name:expr) => {{
            let class_id = $class_id;
            let name = $name;
            pdb.get_perm_id(class_id, name)
                .ok_or_else(|| anyhow!("Permission not found in {class_id:?}: {name}"))?
        }};
    }

    let t_source = t!(n_source_type);
    let t_source_uffd = t!(n_source_uffd_type);
    let t_target = pdb.create_type(&n_target_type, false)?.0;
    let t_target_uffd = pdb.create_type(&n_target_uffd_type, false)?.0;

    pdb.copy_roles(t_source, t_target)?;
    pdb.copy_roles(t_source_uffd, t_target_uffd)?;

    pdb.copy_attributes(t_source, t_target)?;
    pdb.copy_attributes(t_source_uffd, t_target_uffd)?;

    pdb.copy_constraints(t_source, t_target);
    pdb.copy_constraints(t_source_uffd, t_target_uffd);

    pdb.copy_avtab_rules(Box::new(move |source_type, target_type, class| {
        let mut new_source_type = None;
        let mut new_target_type = None;

        if source_type == t_source {
            new_source_type = Some(t_target);
        } else if source_type == t_source_uffd {
            new_source_type = Some(t_target_uffd);
        }

        if target_type == t_source {
            new_target_type = Some(t_target);
        } else if target_type == t_source_uffd {
            new_target_type = Some(t_target_uffd);
        }

        if new_source_type.is_none() && new_target_type.is_none() {
            None
        } else {
            Some((
                new_source_type.unwrap_or(source_type),
                new_target_type.unwrap_or(target_type),
                class,
            ))
        }
    }))?;

    // At this point, custota_app should be identical to untrusted_app. Now, add
    // the actual additional rules we need.

    let t_fuse = t!("fuse");
    let t_mediaprovider_app = t!("mediaprovider_app");
    let t_oem_lock_service = t!("oem_lock_service");
    let t_ota_package_file = t!("ota_package_file");
    let t_update_engine = t!("update_engine");
    let t_update_engine_service = t!("update_engine_service");

    let c_binder = c!("binder");
    let p_binder_call = p!(c_binder, "call");
    let p_binder_transfer = p!(c_binder, "transfer");

    let c_dir = c!("dir");
    let p_dir_add_name = p!(c_dir, "add_name");
    let p_dir_getattr = p!(c_dir, "getattr");
    let p_dir_ioctl = p!(c_dir, "ioctl");
    let p_dir_lock = p!(c_dir, "lock");
    let p_dir_open = p!(c_dir, "open");
    let p_dir_read = p!(c_dir, "read");
    let p_dir_remove_name = p!(c_dir, "remove_name");
    let p_dir_search = p!(c_dir, "search");
    let p_dir_watch = p!(c_dir, "watch");
    let p_dir_watch_reads = p!(c_dir, "watch_reads");
    let p_dir_write = p!(c_dir, "write");

    let c_fd = c!("fd");
    let p_fd_use = p!(c_fd, "use");

    let c_file = c!("file");
    let p_file_append = p!(c_file, "append");
    let p_file_create = p!(c_file, "create");
    let p_file_getattr = p!(c_file, "getattr");
    let p_file_ioctl = p!(c_file, "ioctl");
    let p_file_lock = p!(c_file, "lock");
    let p_file_map = p!(c_file, "map");
    let p_file_open = p!(c_file, "open");
    let p_file_read = p!(c_file, "read");
    let p_file_rename = p!(c_file, "rename");
    let p_file_setattr = p!(c_file, "setattr");
    let p_file_unlink = p!(c_file, "unlink");
    let p_file_watch = p!(c_file, "watch");
    let p_file_watch_reads = p!(c_file, "watch_reads");
    let p_file_write = p!(c_file, "write");

    let c_service_manager = c!("service_manager");
    let p_service_manager_find = p!(c_service_manager, "find");

    // allow custota_app ota_package_file:dir rw_dir_perms;
    for perm in [
        p_dir_add_name,
        p_dir_getattr,
        p_dir_ioctl,
        p_dir_lock,
        p_dir_open,
        p_dir_read,
        p_dir_remove_name,
        p_dir_search,
        p_dir_watch,
        p_dir_watch_reads,
        p_dir_write,
    ] {
        pdb.set_allow(t_target, t_ota_package_file, c_dir, perm, true);
    }

    // allow custota_app ota_package_file:file create_file_perms;
    for perm in [
        p_file_append,
        p_file_create,
        p_file_getattr,
        p_file_ioctl,
        p_file_lock,
        p_file_map,
        p_file_open,
        p_file_read,
        p_file_rename,
        p_file_setattr,
        p_file_unlink,
        p_file_watch,
        p_file_watch_reads,
        p_file_write,
    ] {
        pdb.set_allow(t_target, t_ota_package_file, c_file, perm, true);
    }

    // binder_call(custota_app, update_engine)
    // binder_call(update_engine, custota_app)
    for perm in [p_binder_call, p_binder_transfer] {
        pdb.set_allow(t_target, t_update_engine, c_binder, perm, true);
        pdb.set_allow(t_update_engine, t_target, c_binder, perm, true);
    }
    pdb.set_allow(t_target, t_update_engine, c_fd, p_fd_use, true);
    pdb.set_allow(t_update_engine, t_target, c_fd, p_fd_use, true);

    // allow custota_app update_engine_service:service_manager find;
    pdb.set_allow(
        t_target,
        t_update_engine_service,
        c_service_manager,
        p_service_manager_find,
        true,
    );

    // allow custota_app oem_lock_service:service_manager find;
    pdb.set_allow(
        t_target,
        t_oem_lock_service,
        c_service_manager,
        p_service_manager_find,
        true,
    );

    // Now, allow update_engine to access the file descriptor we pass to it via
    // binder for a file opened from local storage.

    // allow update_engine mediaprovider_app:fd use;
    pdb.set_allow(t_update_engine, t_mediaprovider_app, c_fd, p_fd_use, true);

    // allow update_engine fuse:file getattr;
    // allow update_engine fuse:file read;
    for perm in [p_file_getattr, p_file_read] {
        pdb.set_allow(t_update_engine, t_fuse, c_file, perm, true);
    }

    if cli.strip_no_audit {
        pdb.strip_no_audit();
    }

    {
        let path = cli.target.as_path();
        let file =
            File::create(path).with_context(|| format!("Failed to open for writing: {path:?}"))?;

        let mut warnings = vec![];

        pdb.to_writer(file, &mut warnings)
            .with_context(|| format!("Failed to write sepolicy: {path:?}"))?;

        if !warnings.is_empty() {
            eprintln!("Warnings when saving sepolicy:");
            for warning in warnings {
                eprintln!("- {warning}");
            }
        }
    }

    Ok(())
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct SourceGroup {
    /// Source policy file.
    #[arg(short, long, value_parser, value_name = "FILE")]
    source: Option<PathBuf>,

    /// Use currently loaded policy as source.
    #[arg(short = 'S', long)]
    source_kernel: bool,
}

impl SourceGroup {
    fn as_path(&self) -> &Path {
        if let Some(path) = &self.source {
            path
        } else if self.source_kernel {
            Path::new("/sys/fs/selinux/policy")
        } else {
            unreachable!()
        }
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct TargetGroup {
    /// Target policy file.
    #[arg(short, long, value_parser, value_name = "FILE")]
    target: Option<PathBuf>,

    /// Load patched policy into kernel.
    #[arg(short = 'T', long)]
    target_kernel: bool,
}

impl TargetGroup {
    fn as_path(&self) -> &Path {
        if let Some(path) = &self.target {
            path
        } else if self.target_kernel {
            Path::new("/sys/fs/selinux/load")
        } else {
            unreachable!()
        }
    }
}

/// Patch SELinux policy file.
#[derive(Debug, Parser)]
pub struct Cli {
    #[command(flatten)]
    source: SourceGroup,

    #[command(flatten)]
    target: TargetGroup,

    /// Remove dontaudit/dontauditxperm rules.
    #[arg(short = 'd', long)]
    strip_no_audit: bool,
}

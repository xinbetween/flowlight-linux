//! What has been mounted and can be taken away again, from `/proc/mounts` and `/sys/block`.
//!
//! A filesystem on something removable — a stick, a drive, a card. Not every mount: this machine's own root is
//! not news, and neither are the dozen pseudo-filesystems the kernel mounts on itself.
//!
//! # Why removability is asked of the disk and not guessed from the path
//!
//! `/media` and `/run/media` are where desktops mount removable things, and plenty of people mount them
//! elsewhere. The kernel already knows: `/sys/block/<disk>/removable` is the answer, and it is the answer for a
//! drive mounted at `/opt/data` as much as for one mounted where a desktop put it.

use crate::{Channel, Device, read};
use std::path::Path;

/// Filesystems the kernel mounts on itself, which nobody plugged in.
const PSEUDO: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "securityfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "efivarfs",
    "bpf",
    "autofs",
    "hugetlbfs",
    "mqueue",
    "debugfs",
    "tracefs",
    "fusectl",
    "configfs",
    "ramfs",
    "binfmt_misc",
    "rpc_pipefs",
    "nsfs",
    "overlay",
    "squashfs",
    "fuse.portal",
    "fuse.gvfsd-fuse",
    "fuse.snapfuse",
];

/// Every mounted filesystem that is on something removable.
pub fn mounted(sys: &Path, proc: &Path) -> Vec<Device> {
    let Ok(text) = std::fs::read_to_string(proc.join("mounts")) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(source), Some(at), Some(kind)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if PSEUDO.contains(&kind) || !source.starts_with("/dev/") {
            continue;
        }
        let Some(disk) = disk_of(source) else {
            continue;
        };
        if read(&sys.join("block").join(&disk).join("removable")).as_deref() != Some("1") {
            continue;
        }
        found.push(Device {
            channel: Channel::Volume,
            // The device node, because a volume unmounted and mounted again somewhere else is the same volume.
            id: format!("volume:{source}"),
            name: unescaped(at),
            detail: Some(format!("{source}, {kind}")),
        });
    }
    found
}

/// The disk a partition is on: `/dev/sda2` is on `sda`, `/dev/mmcblk0p1` is on `mmcblk0`.
///
/// Removability is a property of the disk and not of the partition, so the partition number has to come off —
/// and the two families spell a partition differently, which is why this is not one `trim_end_matches`.
pub fn disk_of(source: &str) -> Option<String> {
    let node = source.strip_prefix("/dev/")?;
    if node.is_empty() {
        return None;
    }
    // `mmcblk0p1`, `nvme0n1p2`, `loop0p1`: the partition is after a `p` that follows a digit.
    if let Some(at) = node.rfind('p')
        && at > 0
        && node
            .get(at + 1..)
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        && node
            .get(..at)
            .and_then(|before| before.chars().last())
            .is_some_and(|last| last.is_ascii_digit())
    {
        return node.get(..at).map(str::to_owned);
    }
    // `sda2`, `vdb1`: the trailing digits are the partition.
    Some(
        node.trim_end_matches(|c: char| c.is_ascii_digit())
            .to_owned(),
    )
}

/// A mount point as it reads, with the escapes `/proc/mounts` uses put back.
fn unescaped(at: &str) -> String {
    at.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Removability belongs to the disk, and the two families spell a partition differently.
    #[test]
    fn a_partition_is_traced_back_to_its_disk() {
        assert_eq!(disk_of("/dev/sda2").as_deref(), Some("sda"));
        assert_eq!(disk_of("/dev/sdb").as_deref(), Some("sdb"));
        assert_eq!(disk_of("/dev/mmcblk0p1").as_deref(), Some("mmcblk0"));
        assert_eq!(disk_of("/dev/nvme0n1p2").as_deref(), Some("nvme0n1"));
        // Not a device node at all.
        assert_eq!(disk_of("tmpfs"), None);
        assert_eq!(disk_of("/dev/"), None);
    }

    /// `/proc/mounts` escapes the characters that would otherwise end a field.
    #[test]
    fn a_mount_point_with_a_space_in_it_reads_back() {
        assert_eq!(unescaped("/media/me/My\\040Drive"), "/media/me/My Drive");
        assert_eq!(unescaped("/mnt/plain"), "/mnt/plain");
    }

    #[test]
    fn only_what_is_removable_is_reported() {
        let root = std::env::temp_dir().join(format!("flowlight-vol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (sys, proc) = (root.join("sys"), root.join("proc"));
        std::fs::create_dir_all(&proc).unwrap();

        // The machine's own disk, and a stick somebody plugged in.
        for (disk, removable) in [("sda", "0"), ("sdb", "1")] {
            let block = sys.join("block").join(disk);
            std::fs::create_dir_all(&block).unwrap();
            std::fs::write(block.join("removable"), format!("{removable}\n")).unwrap();
        }
        std::fs::write(
            proc.join("mounts"),
            "sysfs /sys sysfs rw 0 0\n\
             proc /proc proc rw 0 0\n\
             tmpfs /run tmpfs rw 0 0\n\
             /dev/sda2 / ext4 rw 0 0\n\
             /dev/sdb1 /media/me/My\\040Drive vfat rw 0 0\n",
        )
        .unwrap();

        let found = mounted(&sys, &proc);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "/media/me/My Drive");
        assert_eq!(found[0].id, "volume:/dev/sdb1");
        assert_eq!(found[0].detail.as_deref(), Some("/dev/sdb1, vfat"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_machine_with_no_mounts_file_reports_nothing() {
        assert!(mounted(Path::new("/nonexistent"), Path::new("/nonexistent")).is_empty());
    }
}

//! What is plugged in, from `/sys/bus/usb/devices`.
//!
//! The kernel publishes one directory per device and one per *interface*, and telling them apart is the whole
//! of the reading: `1-2` is a thing somebody plugged in, `1-2:1.0` is one of the functions it offers, and
//! `usb1` is a root hub that is part of the machine. Listing all three would report a keyboard three times and
//! a motherboard as a device.

use crate::{Channel, Device, read};
use std::path::Path;

/// Everything plugged in.
pub fn attached(sys: &Path) -> Vec<Device> {
    let root = sys.join("bus/usb/devices");
    let Ok(listing) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in listing.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_a_device(&name) {
            continue;
        }
        let path = entry.path();
        // A device with no vendor is not a device the kernel has finished with.
        let Some(vendor) = read(&path.join("idVendor")) else {
            continue;
        };
        let product = read(&path.join("idProduct")).unwrap_or_else(|| "0000".to_owned());
        found.push(Device {
            channel: Channel::Usb,
            // Vendor and product rather than the bus path, because a device moved to another port is the same
            // device and a bus path is not.
            id: format!(
                "usb:{vendor}:{product}:{}",
                read(&path.join("serial")).unwrap_or_default()
            ),
            name: described(&path).unwrap_or_else(|| format!("{vendor}:{product}")),
            detail: Some(match read(&path.join("manufacturer")) {
                Some(maker) => format!("{maker}, {vendor}:{product}"),
                None => format!("{vendor}:{product}"),
            }),
        });
    }
    found
}

/// Whether a directory name is a device rather than an interface or a root hub.
///
/// `1-2` and `1-2.3` are devices. `1-2:1.0` is an interface — one of the functions a device offers, and there
/// are several per device. `usb1` is a root hub, which is part of the machine rather than something plugged
/// into it.
pub fn is_a_device(name: &str) -> bool {
    !name.contains(':') && !name.starts_with("usb") && name.contains('-')
}

/// What a person would call it.
fn described(path: &Path) -> Option<String> {
    let product = read(&path.join("product"))?;
    Some(product)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Listing interfaces would report a keyboard three times; listing root hubs would report a motherboard
    /// as something somebody plugged in.
    #[test]
    fn an_interface_and_a_root_hub_are_not_devices() {
        assert!(is_a_device("1-2"));
        assert!(is_a_device("1-2.3"));
        assert!(is_a_device("3-1.4.2"));
        assert!(!is_a_device("1-2:1.0"), "an interface");
        assert!(!is_a_device("usb1"), "a root hub");
        assert!(!is_a_device("usb3"), "a root hub");
    }

    #[test]
    fn a_device_is_read_out_of_the_files_the_kernel_wrote() {
        let sys = std::env::temp_dir().join(format!("flowlight-usb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        let devices = sys.join("bus/usb/devices");
        // A keyboard, with everything filled in.
        let keyboard = devices.join("1-2");
        std::fs::create_dir_all(&keyboard).unwrap();
        for (name, value) in [
            ("idVendor", "05ac"),
            ("idProduct", "024f"),
            ("manufacturer", "Keychron"),
            ("product", "K2 Keyboard"),
            ("serial", "ABC123"),
        ] {
            std::fs::write(keyboard.join(name), format!("{value}\n")).unwrap();
        }
        // One of its interfaces, which must not be listed as a second device.
        let interface = devices.join("1-2:1.0");
        std::fs::create_dir_all(&interface).unwrap();
        std::fs::write(interface.join("idVendor"), "05ac\n").unwrap();
        // A root hub, which is part of the machine.
        let hub = devices.join("usb1");
        std::fs::create_dir_all(&hub).unwrap();
        std::fs::write(hub.join("idVendor"), "1d6b\n").unwrap();
        // Something the kernel has not finished with: no vendor yet.
        let half = devices.join("2-1");
        std::fs::create_dir_all(&half).unwrap();

        let found = attached(&sys);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "K2 Keyboard");
        assert_eq!(found[0].detail.as_deref(), Some("Keychron, 05ac:024f"));
        // Keyed on what it is rather than where it is plugged in: the same device in another port is the same
        // device.
        assert_eq!(found[0].id, "usb:05ac:024f:ABC123");

        let _ = std::fs::remove_dir_all(&sys);
    }

    #[test]
    fn a_machine_with_no_usb_directory_reports_nothing() {
        assert!(attached(Path::new("/nonexistent")).is_empty());
    }
}

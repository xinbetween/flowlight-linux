//! What is paired, from `/sys/class/bluetooth`.
//!
//! The kernel publishes the adapters and the devices that have connected through them. It does not publish a
//! byte count for either, and nothing else on the machine does per process, so this says what is there and when
//! it appeared.
//!
//! # Why not BlueZ
//!
//! Asking BlueZ over D-Bus gives more — a friendly name, whether a device is paired as opposed to merely seen —
//! and costs a D-Bus client and a connection to a system service, for a feature that lists what is connected.
//! What the kernel already publishes is enough to say a thing is there, which is the honest scope of this
//! channel anyway.

use crate::{Channel, Device, read};
use std::path::Path;

/// Every adapter, and every device connected through one.
pub fn attached(sys: &Path) -> Vec<Device> {
    let root = sys.join("class/bluetooth");
    let Ok(listing) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in listing.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let path = entry.path();
        // `hci0` is an adapter; `hci0:12` is a connection through it.
        let address = read(&path.join("address"));
        if is_an_adapter(&name) {
            found.push(Device {
                channel: Channel::Bluetooth,
                id: format!("bt-adapter:{name}"),
                name: format!("{name}, this machine's Bluetooth"),
                detail: address,
            });
            continue;
        }
        found.push(Device {
            channel: Channel::Bluetooth,
            // The address, because that is what makes it the same peripheral twice.
            id: format!("bt:{}", address.clone().unwrap_or_else(|| name.clone())),
            name: read(&path.join("name")).unwrap_or_else(|| name.clone()),
            detail: address,
        });
    }
    found
}

/// Whether a name is an adapter rather than something connected through one.
pub fn is_an_adapter(name: &str) -> bool {
    !name.contains(':') && name.starts_with("hci")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_adapter_is_not_a_peripheral() {
        assert!(is_an_adapter("hci0"));
        assert!(!is_an_adapter("hci0:256"));
        assert!(!is_an_adapter("something"));
    }

    #[test]
    fn adapters_and_what_is_connected_through_them_are_both_read() {
        let sys = std::env::temp_dir().join(format!("flowlight-bt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sys);
        let root = sys.join("class/bluetooth");

        let adapter = root.join("hci0");
        std::fs::create_dir_all(&adapter).unwrap();
        std::fs::write(adapter.join("address"), "AA:BB:CC:DD:EE:FF\n").unwrap();

        let peripheral = root.join("hci0:256");
        std::fs::create_dir_all(&peripheral).unwrap();
        std::fs::write(peripheral.join("address"), "11:22:33:44:55:66\n").unwrap();
        std::fs::write(peripheral.join("name"), "Somebody's Headphones\n").unwrap();

        let mut found = attached(&sys);
        found.sort();
        assert_eq!(found.len(), 2);
        let names: Vec<&str> = found.iter().map(|device| device.name.as_str()).collect();
        assert!(names.contains(&"Somebody's Headphones"), "{names:?}");
        assert!(
            names
                .iter()
                .any(|name| name.contains("this machine's Bluetooth")),
            "{names:?}"
        );
        // A peripheral is keyed on its address, which is what makes it the same one twice.
        assert!(
            found
                .iter()
                .any(|device| device.id == "bt:11:22:33:44:55:66"),
            "{found:?}"
        );

        let _ = std::fs::remove_dir_all(&sys);
    }

    #[test]
    fn a_machine_with_no_bluetooth_reports_nothing() {
        assert!(attached(Path::new("/nonexistent")).is_empty());
    }
}

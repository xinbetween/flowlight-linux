//! The channels that are not the network.
//!
//! What is attached over USB, what is paired over Bluetooth, and which removable volumes are mounted — and
//! when any of that changed.
//!
//! # What is not here, and why
//!
//! How much went through any of it. Linux accounts for bytes per socket, which is what makes the network half
//! of Flowlight possible; it does not account for them per USB device or per Bluetooth peripheral in any way a
//! process can be attributed. So this reports what is connected and when it appeared, and says nothing about
//! throughput rather than implying a number it does not have.
//!
//! # Why everything is read from `/sys` and `/proc`
//!
//! Because the alternative is a D-Bus client for BlueZ and a udev library, which is a runtime dependency and a
//! connection to a system service for a feature that lists what is plugged in. The kernel already publishes all
//! of this as files. Reading files is testable against a directory written by hand, which is how every
//! judgement here is tested.

pub mod bluetooth;
pub mod usb;
pub mod volumes;

use std::path::Path;

/// What sort of channel a thing is attached by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Channel {
    /// Plugged in.
    Usb,
    /// Paired, or an adapter.
    Bluetooth,
    /// A filesystem that was mounted and can be taken away again.
    Volume,
}

impl Channel {
    /// The name this is written down and shown under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Bluetooth => "bluetooth",
            Self::Volume => "volume",
        }
    }

    /// Reads one back, or nothing if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Usb, Self::Bluetooth, Self::Volume]
            .into_iter()
            .find(|channel| channel.as_str() == text.trim().to_lowercase())
    }
}

/// One thing attached by something other than the network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Device {
    /// How it is attached.
    pub channel: Channel,
    /// What the kernel calls it, which is what makes it the same thing twice.
    pub id: String,
    /// What a person would call it.
    pub name: String,
    /// What else is known: a manufacturer, a mount point, an address.
    pub detail: Option<String>,
}

/// Everything attached right now, read from the kernel's own files.
///
/// The roots are parameters so that every judgement here can be tested against a directory written by hand
/// rather than against whatever happens to be plugged into the machine running the tests.
pub fn attached(sys: &Path, proc: &Path) -> Vec<Device> {
    let mut found = usb::attached(sys);
    found.extend(bluetooth::attached(sys));
    found.extend(volumes::mounted(sys, proc));
    found.sort();
    found.dedup();
    found
}

/// What changed between two readings.
///
/// Arrivals and departures, which is the whole of what this channel can honestly report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changed {
    /// What is here now and was not before.
    pub arrived: Vec<Device>,
    /// What was here before and is not now.
    pub departed: Vec<Device>,
}

impl Changed {
    /// Whether anything happened.
    pub fn is_quiet(&self) -> bool {
        self.arrived.is_empty() && self.departed.is_empty()
    }
}

/// What changed between two readings.
pub fn changed(before: &[Device], now: &[Device]) -> Changed {
    Changed {
        arrived: now
            .iter()
            .filter(|device| !before.iter().any(|old| old.id == device.id))
            .cloned()
            .collect(),
        departed: before
            .iter()
            .filter(|device| !now.iter().any(|new| new.id == device.id))
            .cloned()
            .collect(),
    }
}

/// The contents of a file in `/sys`, trimmed, or nothing.
///
/// Every one of these is a short line the kernel wrote. A missing one is the ordinary case — not every device
/// declares a manufacturer — so it is nothing rather than an error.
pub(crate) fn read(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str) -> Device {
        Device {
            channel: Channel::Usb,
            id: id.to_owned(),
            name: id.to_owned(),
            detail: None,
        }
    }

    #[test]
    fn what_arrived_and_what_went_away() {
        let before = vec![device("a"), device("b")];
        let now = vec![device("b"), device("c")];
        let changed = changed(&before, &now);
        assert_eq!(changed.arrived.len(), 1);
        assert_eq!(changed.arrived[0].id, "c");
        assert_eq!(changed.departed.len(), 1);
        assert_eq!(changed.departed[0].id, "a");
        assert!(!changed.is_quiet());
    }

    #[test]
    fn nothing_changing_is_quiet() {
        let same = vec![device("a")];
        assert!(changed(&same, &same).is_quiet());
        assert!(changed(&[], &[]).is_quiet());
    }

    #[test]
    fn a_channel_reads_back_from_what_it_is_written_as() {
        for channel in [Channel::Usb, Channel::Bluetooth, Channel::Volume] {
            assert_eq!(Channel::parse(channel.as_str()), Some(channel));
        }
        assert_eq!(Channel::parse("thunderbolt"), None);
    }

    /// A missing file is the ordinary case — not every device declares a manufacturer — so it is nothing
    /// rather than an error.
    #[test]
    fn a_missing_or_empty_file_is_nothing() {
        let directory = std::env::temp_dir().join(format!("flowlight-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(read(&directory.join("absent")), None);
        std::fs::write(directory.join("empty"), "   \n").unwrap();
        assert_eq!(read(&directory.join("empty")), None);
        std::fs::write(directory.join("there"), "  a value \n").unwrap();
        assert_eq!(read(&directory.join("there")).as_deref(), Some("a value"));
        let _ = std::fs::remove_dir_all(&directory);
    }
}

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-03

### Added

- Link a tracker to a device of another integration, for example a Chromecast that was added without a MAC address. Use **Link a tracker to a device** in the options, or the new `cisco_ios_tracker.link_device` and `cisco_ios_tracker.unlink_device` actions. A link replaces the device Home Assistant picks automatically from the MAC address, and linking a disabled tracker enables it.
- An IP address sensor for each tracker, with the client's last known IPv4 address. It sits on the same device as its tracker and is enabled and disabled together with it.

### Changed

- The options are now a menu: **Settings** holds Consider home and Maximum ARP age.

## [1.0.0] - 2026-10-02

The first release: a config entry based replacement for the core `cisco_ios` device tracker.

### Added

- Set up from the UI, with a config flow for host, port and username.
- Three login methods: password, pasted private key, or private key file. Encrypted keys with a passphrase are supported, and key files can use paths relative to the configuration directory.
- RSA, ECDSA and ed25519 user keys, depending on what the device supports.
- SSH host key pinning on first use. A changed host key makes the entities unavailable and creates a repair issue that explains how to verify the new key. The repair issue is removed when the entry is unloaded or deleted.
- Automatic detection of devices that only offer legacy SSH algorithms.
- Reauthentication, including switching to a different login method. A key file that can no longer be read also starts reauthentication.
- Reconfiguration of host and port. The host key is checked before any credentials are sent, and a changed key must be confirmed first. The device serial number is checked so you can't switch to a different device by mistake.
- A device tracker (`ScannerEntity`) for each client MAC address, with an `interface` attribute. The last seen time is kept across restarts, so a client that was home stays home for the rest of its Consider home time. Entity IDs match the core integration (`device_tracker.<mac_address_with_underscores>`), so you can migrate without changing automations.
- A Connected clients sensor on the router device.
- Options for Consider home (0 to 900 seconds, default 180; 0 means home only while the latest poll sees the client) and Maximum ARP age (0 to 240 minutes, default 0).
- Diagnostics with credentials and personal data redacted.
- Errors such as AAA command authorization denials are reported instead of being read as an empty ARP table.
- Brand icon for the Home Assistant UI.

### Changed compared to the core Cisco IOS integration

- Works with privilege level 1 users and the `>` prompt; privileged EXEC is no longer needed.
- Logs out after every poll instead of leaving VTY sessions open.
- Polls every 30 seconds instead of every 12 seconds.
- Uses asyncssh instead of pexpect, so it no longer needs the `ssh` command on the host or a worker thread for every scan.
- ARP entries without an interface column and banners or MOTD text no longer break parsing.

[1.1.0]: https://github.com/Simeon26/ha-cisco-ios-tracker/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Simeon26/ha-cisco-ios-tracker/releases/tag/v1.0.0

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-02

The first release: a config entry based replacement for the core `cisco_ios` device tracker.

### Added

- Set up from the UI, with a config flow for host, port and username.
- Three login methods: password, pasted private key, or private key file. Encrypted keys with a passphrase are supported, and key files can use paths relative to the configuration directory.
- RSA, ECDSA and ed25519 user keys, depending on what the device supports.
- SSH host key pinning on first use. A changed host key makes the entities unavailable and creates a repair issue that explains how to verify the new key.
- Automatic detection of devices that only offer legacy SSH algorithms.
- Reauthentication, including switching to a different login method.
- Reconfiguration of host and port, which also lets you confirm a new host key. The device serial number is checked so you can't switch to a different device by mistake.
- A device tracker (`ScannerEntity`) for each client MAC address, with `interface` and `last_time_reachable` attributes. Entity IDs match the core integration (`device_tracker.<mac_address_with_underscores>`), so you can migrate without changing automations.
- A Connected clients sensor on the router device.
- Options for Consider home (0 to 900 seconds, default 180) and Maximum ARP age (0 to 240 minutes, default 0).
- Diagnostics with credentials and personal data redacted.
- Brand icon for the Home Assistant UI.

### Changed compared to the core Cisco IOS integration

- Works with privilege level 1 users and the `>` prompt; privileged EXEC is no longer needed.
- Logs out after every poll instead of leaving VTY sessions open.
- Polls every 30 seconds instead of every 12 seconds.
- Uses asyncssh instead of pexpect, so it no longer needs the `ssh` command on the host or a worker thread for every scan.
- ARP entries without an interface column and banners or MOTD text no longer break parsing.

[Unreleased]: https://github.com/Simeon26/ha-cisco-ios-tracker/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Simeon26/ha-cisco-ios-tracker/releases/tag/v1.0.0

# Cisco IOS Tracker

[![Validate](https://github.com/Simeon26/ha-cisco-ios-tracker/actions/workflows/validate.yml/badge.svg)](https://github.com/Simeon26/ha-cisco-ios-tracker/actions/workflows/validate.yml)
[![Tests](https://github.com/Simeon26/ha-cisco-ios-tracker/actions/workflows/tests.yml/badge.svg)](https://github.com/Simeon26/ha-cisco-ios-tracker/actions/workflows/tests.yml)
[![HACS custom repository](https://img.shields.io/badge/HACS-custom-orange.svg)](https://hacs.xyz/docs/faq/custom_repositories/)

Presence detection for Home Assistant, based on the ARP table of a Cisco IOS or IOS-XE router or Layer 3 switch.

Every 30 seconds the integration logs in to your Cisco device over SSH, runs `show ip arp`, and marks each client as home or away. It is a modern replacement for the core [Cisco IOS](https://www.home-assistant.io/integrations/cisco_ios/) integration:

- You set it up from the UI. There is no YAML and no `known_devices.yaml`.
- You can log in with a password or an SSH key. The key can be pasted in or read from a file, and encrypted keys with a passphrase are supported.
- The device's SSH host key is pinned when you add it, so a changed key is reported instead of silently accepted.
- Older devices that only offer legacy SSH algorithms are detected automatically.
- A read-only, privilege level 1 account is enough.
- Every poll logs out cleanly, so no VTY sessions are left open.

It was built for and tested against the Cisco C1111-8PE (ISR 1100, IOS-XE 16.x and 17.x), and it also works with classic IOS 12.x and 15.x.

> [!NOTE]
> This is a community project. It is not affiliated with, endorsed by, or supported by Cisco Systems. Cisco and IOS are trademarks of Cisco Systems, Inc.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Preparing your Cisco device](#preparing-your-cisco-device)
- [Adding the integration](#adding-the-integration)
- [Options](#options)
- [What you get](#what-you-get)
- [Why new trackers may be disabled](#why-new-trackers-may-be-disabled)
- [Host key pinning](#host-key-pinning)
- [Legacy SSH algorithms](#legacy-ssh-algorithms)
- [Migrating from the core Cisco IOS integration](#migrating-from-the-core-cisco-ios-integration)
- [Polling interval](#polling-interval)
- [Diagnostics](#diagnostics)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Requirements

- Home Assistant 2026.3.0 or later.
- A Cisco router or Layer 3 switch running IOS or IOS-XE, reachable from Home Assistant over SSH version 2.
- A local user (or an AAA user) that can log in over SSH and run `show ip arp` and `show version`. Privilege level 1 is enough.

## Installation

### HACS (recommended)

1. Make sure [HACS](https://hacs.xyz/) is installed.
2. Open the repository in HACS with this button, or add `https://github.com/Simeon26/ha-cisco-ios-tracker` as a [custom repository](https://hacs.xyz/docs/faq/custom_repositories/) with the type **Integration**:

   [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Simeon26&repository=ha-cisco-ios-tracker&category=integration)

3. Select **Download**.
4. Restart Home Assistant.

### Manual

1. Download the latest release from the [releases page](https://github.com/Simeon26/ha-cisco-ios-tracker/releases).
2. Copy the `custom_components/cisco_ios_tracker` folder into the `custom_components` folder of your Home Assistant configuration directory, so you end up with `/config/custom_components/cisco_ios_tracker/manifest.json`.
3. Restart Home Assistant.

## Preparing your Cisco device

The integration needs SSH version 2, an RSA host key, and a user account. The examples use a C1111-8PE called `router1`, a user called `ha`, and Home Assistant at `192.0.2.10`. Replace them with your own values.

### IOS-XE (C1111-8PE example)

Enter configuration mode and run:

```text
configure terminal
 hostname router1
 ip domain name home.example
 ! The SSH host key. 2048 or 3072 bits are both fine.
 crypto key generate rsa modulus 2048
 ip ssh version 2
 ! A read-only user. Privilege 1 can run "show ip arp" and "show version".
 username ha privilege 1 algorithm-type scrypt secret Use-A-Long-Random-Password
 line vty 0 4
  transport input ssh
  login local
 exit
end
write memory
```

If your device uses `aaa new-model`, the user must be allowed by your login and exec authorization method lists. For local users that usually means:

```text
aaa authentication login default local
aaa authorization exec default local
```

> [!TIP]
> You don't need privilege level 15 or `enable`. The integration works with both the `router1>` and `router1#` prompts. If you use AAA command authorization, allow `show ip arp`, `show version`, `terminal length` and `terminal width` for this user.

#### Adding an SSH key for the user (optional)

You can skip this if you want to log in with a password.

1. Create a key pair on your computer. Leave the passphrase empty, or set one and enter it in Home Assistant later.

   ```bash
   # ed25519: IOS-XE 17.8.1 or later
   ssh-keygen -t ed25519 -f cisco_ha -C ha

   # ECDSA: IOS-XE 17.x
   ssh-keygen -t ecdsa -b 256 -f cisco_ha -C ha

   # RSA: works on every IOS and IOS-XE version
   ssh-keygen -t rsa -b 3072 -f cisco_ha -C ha
   ```

   This creates the private key `cisco_ha` and the public key `cisco_ha.pub`.

2. Print the base64 part of the public key, wrapped into short lines that are easy to paste into the device console:

   ```bash
   cut -d ' ' -f 2 cisco_ha.pub | fold -w 72
   ```

3. Add it to the user on the device. Paste the lines from step 2 after `key-string`, then type `exit` on its own line:

   ```text
   configure terminal
    ip ssh pubkey-chain
     username ha
      key-string
       AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyReplaceWithYourOwnPublicKeyData0000
      exit
     exit
    exit
   end
   write memory
   ```

   The device stores the key as a hash. You can check it with `show running-config | section pubkey-chain`.

Which key type should you use?

| Software on the device | Recommended key | Notes |
|---|---|---|
| IOS-XE 17.8.1 and later | ed25519 or ECDSA | RSA 2048 or 3072 also works. ed25519 user keys need 17.8.1 or later, and Cisco only documents `key-hash ssh-ed25519` in the pubkey chain from 17.16. If an earlier 17.x release refuses an ed25519 key, use ECDSA or RSA. |
| IOS-XE 17.1 to 17.7 | ECDSA or RSA 2048/3072 | |
| IOS-XE 16.x | RSA 2048/3072 | |
| Classic IOS 12.x and 15.x | RSA 2048/3072 | Classic IOS only accepts RSA user keys. |

RSA 2048 and 3072 keys work on every version. If you removed `ssh-rsa` from `ip ssh server algorithm publickey` on IOS-XE, an RSA key may be rejected. Use ed25519 or ECDSA in that case.

### Classic IOS (12.x and 15.x)

The steps are the same, with a few differences:

- Use `ip domain-name home.example` (with a hyphen) on older releases.
- Generate the host key with `crypto key generate rsa modulus 2048`. SSH version 2 needs a key of at least 768 bits, and 2048 bits is a good choice.
- If your release doesn't support `algorithm-type scrypt`, use `username ha privilege 1 secret ...`.
- Only RSA keys can be used in `ip ssh pubkey-chain`.
- Very old releases may only offer legacy SSH algorithms. The integration detects that automatically, see [Legacy SSH algorithms](#legacy-ssh-algorithms).

### Limiting SSH access (optional)

To make sure only Home Assistant and your management hosts can log in, add an access list to the VTY lines. Include every host you manage the device from, or you will lock yourself out:

```text
ip access-list standard SSH-ACCESS
 permit 192.0.2.10
 permit 192.0.2.20
line vty 0 4
 access-class SSH-ACCESS in
```

### Putting the private key on Home Assistant

You have two choices. You will pick one when you add the integration.

- **Paste the key.** Copy the whole contents of the private key file `cisco_ha`, including the `-----BEGIN ...-----` and `-----END ...-----` lines, into the setup form. The text box is not masked, so make sure nobody is looking over your shoulder.
- **Use a key file.** Copy `cisco_ha` to your Home Assistant configuration directory, for example to `/config/.ssh/cisco_ha`. On Home Assistant OS you can do this with the Samba share or the Terminal & SSH add-on. Make it readable only by its owner with `chmod 600 /config/.ssh/cisco_ha`. In the setup form you can enter the full path, or a path relative to the configuration directory such as `.ssh/cisco_ha`.

> [!IMPORTANT]
> Home Assistant stores passwords, pasted keys and passphrases in its configuration entry storage under `/config/.storage`, like other integrations do. Use a dedicated, read-only account on the device, and protect your Home Assistant backups.

## Adding the integration

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=cisco_ios_tracker)

1. Go to **Settings** > **Devices & services** > **Add integration** and search for **Cisco IOS Tracker**.
2. Enter the **host** (IP address or host name), the SSH **port** (22 by default) and the **username**.
3. Choose how to log in:
   - **Password**: enter the user's password.
   - **Pasted private key**: paste the private key, and enter its passphrase if it has one.
   - **Private key file**: enter the path of the key file, for example `/config/.ssh/cisco_ha`, and its passphrase if it has one.
4. Submit the form. The integration connects to the device, runs `show version` and `show ip arp`, and then:
   - pins the device's SSH host key (see [Host key pinning](#host-key-pinning)),
   - remembers whether the device needs [legacy SSH algorithms](#legacy-ssh-algorithms),
   - names the entry after the device's host name, and uses the serial number to stop you adding the same device twice.

If something goes wrong, the form tells you what to fix. See [Troubleshooting](#troubleshooting) for the meaning of each error.

You can add more than one device. Each one is a separate entry.

### Changing credentials, host or port later

- **New password or key**: if the device rejects the stored credentials, Home Assistant asks you to reauthenticate. You can switch to a different login method at the same time.
- **New IP address, host name or port**: open the integration, select the three-dot menu and choose **Reconfigure**. The integration connects again and checks that it is still the same device (by serial number).

## Options

Open **Settings** > **Devices & services** > **Cisco IOS Tracker** and select **Configure**. Saving the options reloads the integration.

| Option | Default | Range | What it does |
|---|---|---|---|
| Consider home | 180 seconds | 0 to 900 seconds | How long a device stays home after it was last seen in the ARP table. |
| Maximum ARP age | 0 minutes | 0 to 240 minutes | The oldest ARP entry that still counts as "seen". |

### How presence is decided

The `Age (min)` column in `show ip arp` shows how many minutes ago the device last refreshed that entry. An age of `0` means it was refreshed in the last minute.

On every poll:

1. Each entry with an age of **Maximum ARP age** or less counts as seen, and its "last seen" time is set to now.
2. Entries with an age of `-` are ignored. These are the device's own interfaces and static entries. `Incomplete` entries are ignored too.
3. A device is **home** while less than **Consider home** has passed since it was last seen, and **away** after that.

With the defaults, a device is home if its ARP entry was refreshed within the last minute, and it is marked away about 3 minutes after that stops. This is the same rule the core Cisco IOS integration used.

**When should you raise Maximum ARP age?** Some clients, such as phones in deep sleep or quiet IoT devices, don't refresh their ARP entry every minute. If they flap between home and away, try a Maximum ARP age of 5 to 10 minutes. The trade-off is that a device that leaves is marked away later: roughly Maximum ARP age plus Consider home.

## What you get

- **A device for the router or switch**, with model, software version and serial number taken from `show version`.
- **A Connected clients sensor** on that device, which counts the tracked devices that are currently home. Its entity ID is based on the device name, for example `sensor.router1_connected_clients`.
- **A device tracker for each client MAC address.** It is created the first time the MAC address is seen in the ARP table. It is named after the MAC address, with an entity ID such as `device_tracker.00_1d_ec_02_07_ab`. Its attributes include:
  - `ip` and `mac`: the client's current IPv4 address and MAC address.
  - `interface`: the router interface the entry was learned on, for example `Vlan1`.
  - `last_time_reachable`: when the client was last seen.

Trackers are kept when a client goes away; they show `not_home`. After a restart, a client that was home stays home for the Consider home time, so a restart doesn't trigger "left home" automations.

To remove a tracker you no longer need, open its device page and select **Delete**. This is only possible while the client is away. The router device itself can't be deleted this way; remove the integration entry instead.

If one MAC address has several IP addresses (for example a host with secondary addresses), the tracker shows the IP address of the most recently refreshed entry.

## Why new trackers may be disabled

This is standard Home Assistant behavior for router-based trackers. A busy router can have hundreds of ARP entries, so a new tracker is only **enabled by default if another integration already knows its MAC address**. For example, if ESPHome or Shelly has already created a device with that MAC address, the tracker is enabled and attached to that device. All other trackers are added disabled.

To enable a tracker:

1. Go to **Settings** > **Devices & services** > **Entities**.
2. Filter by the **Cisco IOS Tracker** integration and turn on **Show disabled entities**.
3. Select the tracker, open its settings, turn on **Enabled** and select **Update**.

You can enable several at once by selecting them and choosing **Enable selected**. While you are there, you can also give the tracker a friendly name.

If another integration adds a device with that MAC address later, Home Assistant enables the tracker automatically.

## Host key pinning

When you add a device, the integration records its SSH host key ("trust on first use"). On every later connection it checks that the device presents the same key. This protects you from someone impersonating the device on your network.

### Checking the fingerprint

To check that the pinned key really belongs to your device, compare its SHA256 fingerprint in Home Assistant with the one on the device.

1. In Home Assistant, [download the diagnostics](#diagnostics) and look for the host key fingerprint. It looks like `SHA256:7kR1x...`. You can also see it in the debug log.
2. On the device, run `show ip ssh`. Most IOS and IOS-XE releases print the host key under a line that starts with `IOS Keys in SECSH format`. The key starts with `ssh-rsa AAAA` and may wrap over several lines.
3. On your computer, paste that key on a single line into a file called `router1.pub`, and get its fingerprint:

   ```bash
   ssh-keygen -l -f router1.pub
   ```

   The `SHA256:...` value must match the one from Home Assistant.

If `show ip ssh` doesn't print the key, use `show crypto key mypubkey rsa` instead. Copy the hexadecimal `Key Data` block of the key SSH uses into `key.hex`, then run:

```bash
xxd -r -p key.hex > key.der
openssl pkey -pubin -inform DER -in key.der -out key.pem
ssh-keygen -i -m PKCS8 -f key.pem > router1.pub
ssh-keygen -l -f router1.pub
```

### When the host key changes

A device gets a new host key when its RSA key is regenerated (`crypto key generate rsa` or `crypto key zeroize`), when it is replaced, or when its configuration is erased. When that happens:

- the trackers and sensor become unavailable,
- a repair issue appears under **Settings** > **System** > **Repairs**, showing the expected and the presented fingerprints.

To fix it:

1. Check the new fingerprint on the device as described above. If you didn't expect the key to change, investigate before you go on.
2. Open **Settings** > **Devices & services** > **Cisco IOS Tracker**, select the three-dot menu and choose **Reconfigure**.
3. Submit the form. The integration shows the old and the new fingerprint and asks you to confirm.
4. Confirm. The new key is pinned, the integration reloads and the repair issue goes away.

If the new device has a different serial number, reconfiguring is refused because it is a different device. Add it as a new entry instead.

## Legacy SSH algorithms

Current IOS-XE releases, including the C1111-8PE, work with the modern SSH algorithms used by default.

Some older devices only offer algorithms that are disabled by default because they are weak, such as `diffie-hellman-group1-sha1`, CBC ciphers or `hmac-md5`. When you add a device, the integration first tries the modern algorithms. If the device can't agree on any, it tries once more with the legacy algorithms enabled and, if that works, remembers it for that device. You don't need to configure anything. Reconfiguring runs the detection again, so after a software upgrade you can reconfigure to drop back to modern algorithms.

If neither works, you see a "no common algorithms" error. Check that the device has `ip ssh version 2` and an RSA host key of at least 2048 bits.

## Migrating from the core Cisco IOS integration

The core `cisco_ios` integration uses the old YAML device tracker platform, which Home Assistant plans to remove in 2027.5. You can't import its YAML configuration, but the move is quick, and your entity IDs can stay the same.

1. Make a note of the old tracker entity IDs you use in automations, scripts and dashboards, such as `device_tracker.00_1d_ec_02_07_ab`.
2. Remove the `cisco_ios` platform from your `configuration.yaml`:

   ```yaml
   device_tracker:
     - platform: cisco_ios   # remove this block
       host: 192.0.2.1
       username: ha
       password: !secret cisco_password
   ```

3. Remove the entries for those devices from `known_devices.yaml`. If only `cisco_ios` used that file, you can delete it.
4. Restart Home Assistant.
5. [Add the Cisco IOS Tracker integration](#adding-the-integration).
6. [Enable the trackers](#why-new-trackers-may-be-disabled) you want to keep.

New trackers use the same entity ID format, `device_tracker.<mac_address_with_underscores>`, so your automations keep working. If you see IDs ending in `_2`, the old entities still existed when the new ones were created. Remove the old ones and rename the new ones in the entity settings.

What changes for you:

- The `interval_seconds` (12 seconds), `consider_home` and `track_new_devices` settings are gone. Polling is every 30 seconds, Consider home is an option, and new trackers follow the [enabled-by-default rule](#why-new-trackers-may-be-disabled).
- Friendly names and pictures from `known_devices.yaml` are not migrated. Set them in the entity settings.
- The user no longer needs to land in privileged EXEC mode. A privilege level 1 user works.

## Polling interval

The integration polls every 30 seconds. ARP ages only change once a minute, so polling faster would not detect changes sooner. Each poll is one SSH login: it runs `show version` and `show ip arp` in one session and then logs out.

If you want to poll less often, or only at certain times:

1. Open **Settings** > **Devices & services** > **Cisco IOS Tracker**, select the three-dot menu, choose **System options** and turn off **Enable polling for changes**.
2. Create an automation that calls the `homeassistant.update_entity` action for any one of the integration's entities. One call updates all of them.

```yaml
automation:
  - alias: "Refresh Cisco presence every 2 minutes"
    triggers:
      - trigger: time_pattern
        minutes: "/2"
    actions:
      - action: homeassistant.update_entity
        target:
          entity_id: sensor.router1_connected_clients
```

If you poll less often, set Consider home to more than your polling interval, or devices will flap between home and away.

> [!TIP]
> Each poll is a successful login. If your device logs every login to syslog, you may see a `%SEC_LOGIN-5-LOGIN_SUCCESS` message every 30 seconds. You can stop that with `no login on-success log`.

## Diagnostics

Open **Settings** > **Devices & services** > **Cisco IOS Tracker**, select the three-dot menu and choose **Download diagnostics**. The file contains the options, the host key fingerprint, whether legacy algorithms are in use, the last update status, the device model and software version, entry counts, and the ARP entries with interface and age. Host names, credentials, keys, serial numbers, IP addresses and MAC addresses are redacted, so it's safe to attach to an issue.

## Limitations

- **Global ARP table only.** The integration runs `show ip arp`, which only covers the global routing table. Clients in a VRF are not seen.
- **IPv4 only.** IPv6 neighbors are not tracked.
- **Directly connected subnets only.** The device only has ARP entries for clients on subnets it routes for. Clients behind another router are not seen.
- **Presence depends on ARP refreshes.** A client that is connected but quiet can be marked away. See [When should you raise Maximum ARP age?](#how-presence-is-decided)
- **Random MAC addresses.** Phones and computers often use a private (random) Wi-Fi MAC address, which can change. Turn that off for your home network on the devices you want to track.
- **SSH only.** Telnet is not supported.
- **One VTY session per poll.** Each poll uses one VTY line for a moment. If all lines are busy, the poll fails and is retried on the next one.

## Troubleshooting

### Errors when adding the integration

The form shows one of these messages:

| Message starts with | What to check |
|---|---|
| Failed to connect | The host and port, that the device is reachable from Home Assistant, that `transport input ssh` is set on the VTY lines, and that no access list blocks Home Assistant. Run `show users` to see if all VTY lines are busy. |
| The device rejected the username or the credentials | The username and password or key. For a key, check that `show running-config \| section pubkey-chain` lists the key under the right username. With `aaa new-model`, check your login and exec authorization method lists. |
| Home Assistant and the device have no SSH algorithms in common | `ip ssh version 2`, the RSA host key size, and any `ip ssh server algorithm` settings. See [Legacy SSH algorithms](#legacy-ssh-algorithms). |
| You logged in, but the device rejected the `show version` or `show ip arp` command | The user is allowed to run `show ip arp` and `show version`. Look for `% Authorization failed` in the debug log, which means AAA authorization blocked it. |
| The key file does not exist or cannot be read | The path, and that Home Assistant can read the file. Relative paths are relative to the configuration directory, so `.ssh/cisco_ha` means `/config/.ssh/cisco_ha`. |
| The private key is not valid or not supported | That you used the private key (`cisco_ha`), not the public key (`cisco_ha.pub`), and that the whole key including the `BEGIN` and `END` lines was copied. |
| The passphrase is missing or wrong | The key is encrypted and the passphrase is missing or wrong. |
| The device presented a different SSH host key | Only shown when you log in again. The device's host key changed; see [When the host key changes](#when-the-host-key-changes). |

### Debug logging

The quickest way is to open **Settings** > **Devices & services** > **Cisco IOS Tracker** and select **Enable debug logging**. Reproduce the problem, then select **Disable debug logging** to download the log.

You can also enable it in `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.cisco_ios_tracker: debug
    asyncssh: debug
```

The `asyncssh` logs show the SSH negotiation and are useful for algorithm and login problems. They are verbose, so turn them off again afterwards. Passwords and keys are never logged.

If you still can't get it working, [open an issue](https://github.com/Simeon26/ha-cisco-ios-tracker/issues) and include the device model, its software version, the diagnostics and the debug log.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

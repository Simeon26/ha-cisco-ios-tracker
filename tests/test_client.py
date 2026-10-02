"""Tests for the Cisco IOS SSH client and its parsers."""

import builtins
from collections.abc import AsyncIterator
import os
from pathlib import Path
import socket
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest

from custom_components.cisco_ios_tracker import client as client_module
from custom_components.cisco_ios_tracker.client import (
    ArpEntry,
    CiscoAuthenticationError,
    CiscoCommandError,
    CiscoConnectionError,
    CiscoDeviceInfo,
    CiscoError,
    CiscoHostKeyMismatchError,
    CiscoInvalidKeyError,
    CiscoIOSClient,
    CiscoKeyError,
    CiscoKeyExchangeError,
    CiscoKeyFileNotFoundError,
    CiscoPassphraseError,
    _CiscoEarlyDisconnectError,
    fingerprint,
    load_private_key,
    parse_arp_table,
    parse_show_version,
)

from .fake_ios import (
    SHOW_IP_ARP_C1111,
    SHOW_VERSION_C1111,
    FakeIOSConfig,
    FakeIOSServer,
    load_fixture,
    silent_tcp_server,
)

# The SSH tests use real sockets on 127.0.0.1.
pytestmark = pytest.mark.usefixtures("socket_enabled")

C1111_INFO = CiscoDeviceInfo(
    hostname="router1",
    model="C1111-8PE",
    sw_version="17.09.04a",
    serial="FGL2231L0AB",
    base_mac=None,
)
C1111_ARP = [
    ArpEntry("192.168.1.1", "7c:31:0e:5a:1b:40", None, "Vlan1"),
    ArpEntry("192.168.1.20", "00:1d:ec:02:07:ab", 0, "Vlan1"),
    ArpEntry("192.168.1.21", "a4:b1:c1:d2:e3:f4", 3, "Vlan1"),
    ArpEntry("192.168.1.35", "b8:27:eb:12:34:56", 0, "Vlan1"),
    ArpEntry("192.168.1.50", "3c:22:fb:01:02:a3", 17, "Vlan1"),
    ArpEntry("203.0.113.1", "00:50:56:01:01:01", 0, "GigabitEthernet0/0/0"),
    ArpEntry("203.0.113.14", "7c:31:0e:5a:1b:4b", None, "GigabitEthernet0/0/0"),
]
SETUP_COMMANDS = ["terminal length 0", "terminal width 511"]
# What IOS prints when TACACS+ or ISE command authorization denies a command.
COMMAND_AUTHORIZATION_FAILED = "Command authorization failed."
# A failed key exchange is reported either way, depending on whether the
# device's disconnect message or the closed connection arrives first.
KEX_FAILURES = (CiscoKeyExchangeError, _CiscoEarlyDisconnectError)


def _large_arp_table(rows: int) -> str:
    """Return a `show ip arp` output with many rows."""
    lines = ["Protocol  Address          Age (min)  Hardware Addr   Type   Interface"]
    lines.extend(
        f"Internet  10.30.{i // 250}.{i % 250 + 1:<3}         0   "
        f"0022.4466.{i:04x}  ARPA   Vlan30"
        for i in range(rows)
    )
    return "\n".join(lines) + "\n"


# --- Parsers ----------------------------------------------------------------


def test_parse_arp_c1111() -> None:
    """Test parsing the ARP table of a C1111-8PE."""
    assert parse_arp_table(SHOW_IP_ARP_C1111) == C1111_ARP


def test_parse_arp_crlf() -> None:
    """Test that CRLF line endings are handled."""
    output = SHOW_IP_ARP_C1111.replace("\n", "\r\n")
    assert parse_arp_table(output) == C1111_ARP


def test_parse_arp_noisy() -> None:
    """Test banners, prompts, Incomplete rows, `-` rows and rows without interface."""
    output = load_fixture("show_ip_arp_noisy.txt")
    assert parse_arp_table(output) == [
        ArpEntry("10.1.10.1", "00:50:56:01:01:01", None, "Vlan10"),
        ArpEntry("10.1.10.20", "00:1d:ec:02:07:ab", 0, "Vlan10"),
        ArpEntry("10.1.10.25", "a4:b1:c1:d2:e3:f4", 12, "Vlan10"),
        ArpEntry("10.1.20.5", "58:ac:78:aa:bb:01", None, None),
        ArpEntry("10.1.20.6", "58:ac:78:aa:bb:04", 4, None),
        ArpEntry("192.168.100.5", "58:ac:78:aa:bb:02", 237, "GigabitEthernet0/0/1.100"),
        ArpEntry("192.168.100.9", "58:ac:78:aa:bb:03", None, "Port-channel1.100"),
    ]


def test_parse_arp_paged_capture() -> None:
    """Test a raw capture with --More-- prompts and erase sequences."""
    entries = parse_arp_table(load_fixture("show_ip_arp_paged.txt"))
    assert len(entries) == 50
    assert [entry.ip for entry in entries] == [f"10.20.0.{i}" for i in range(1, 51)]
    # The rows right after each --More-- prompt are not lost.
    assert entries[22] == ArpEntry("10.20.0.23", "00:11:22:33:00:17", 2, "Vlan20")
    assert entries[45] == ArpEntry("10.20.0.46", "00:11:22:33:00:2e", 1, "Vlan20")


def test_parse_arp_ansi_sequences() -> None:
    """Test that terminal escape sequences are ignored."""
    output = (
        "\x1b[KInternet  10.0.0.2   5   0011.2233.4455  ARPA   Vlan1\r\n"
        "\x1b[7m --More-- \x1b[m\r        \rInternet  10.0.0.3   -   "
        "0011.2233.4466  ARPA   Vlan1\r\n"
    )
    assert parse_arp_table(output) == [
        ArpEntry("10.0.0.2", "00:11:22:33:44:55", 5, "Vlan1"),
        ArpEntry("10.0.0.3", "00:11:22:33:44:66", None, "Vlan1"),
    ]


@pytest.mark.parametrize(
    "output",
    [
        "",
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n",
        "% Invalid input detected at '^' marker.\n",
    ],
)
def test_parse_arp_empty(output: str) -> None:
    """Test outputs without ARP entries."""
    assert parse_arp_table(output) == []


def test_parse_show_version_c1111() -> None:
    """Test parsing `show version` of a C1111-8PE on IOS-XE 17.9."""
    assert parse_show_version(SHOW_VERSION_C1111) == C1111_INFO


def test_parse_show_version_c1111_crlf() -> None:
    """Test parsing `show version` with CRLF line endings."""
    assert parse_show_version(SHOW_VERSION_C1111.replace("\n", "\r\n")) == C1111_INFO


def test_parse_show_version_c2960x() -> None:
    """Test parsing `show version` of a WS-C2960X on IOS 15.2."""
    assert parse_show_version(
        load_fixture("show_version_ws_c2960x.txt")
    ) == CiscoDeviceInfo(
        hostname="sw1",
        model="WS-C2960X-48FPD-L",
        sw_version="15.2(7)E8",
        serial="FOC2104X1YZ",
        base_mac="70:1f:53:aa:bb:00",
    )


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            (
                "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version"
                " 15.7(3)M8, RELEASE SOFTWARE (fc1)\n"
                "rtr1 uptime is 10 weeks\n"
                "Cisco CISCO2911/K9 (revision 1.0) with 479232K/45056K bytes of"
                " memory.\n"
                "Processor board ID ftx1234a5bc\n"
            ),
            CiscoDeviceInfo("rtr1", "CISCO2911/K9", "15.7(3)M8", "FTX1234A5BC", None),
        ),
        (
            (
                "Cisco IOS XE Software, Version 17.03.05\n"
                "core uptime is 1 year, 2 weeks\n"
                "Processor board ID FOC0000STACK\n"
                "Base Ethernet MAC Address          : 689e.0b11.2200\n"
                "Model Number                       : C9300-48P\n"
                "System Serial Number               : foc2345y1ab\n"
            ),
            CiscoDeviceInfo(
                "core", "C9300-48P", "17.03.05", "FOC2345Y1AB", "68:9e:0b:11:22:00"
            ),
        ),
        (
            "Base ethernet MAC Address       : not-a-mac\n",
            CiscoDeviceInfo(None, None, None, None, None),
        ),
        ("garbage\n", CiscoDeviceInfo(None, None, None, None, None)),
    ],
)
def test_parse_show_version_variants(output: str, expected: CiscoDeviceInfo) -> None:
    """Test serial precedence, model fallback, case and invalid values."""
    assert parse_show_version(output) == expected


def test_fingerprint() -> None:
    """Test the host key fingerprint helper."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    public = key.export_public_key("openssh").decode()
    assert fingerprint(public) == key.get_fingerprint()
    assert fingerprint(public).startswith("SHA256:")
    with pytest.raises(CiscoInvalidKeyError):
        fingerprint("garbage")


# --- Private key loading -----------------------------------------------------

KEY_ALGORITHMS = ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"]


@pytest.fixture(scope="module")
def private_keys() -> dict[str, asyncssh.SSHKey]:
    """Return one private key per supported algorithm."""
    return {alg: asyncssh.generate_private_key(alg) for alg in KEY_ALGORITHMS}


def _export(
    key: asyncssh.SSHKey, fmt: str = "openssh", passphrase: str | None = None
) -> str:
    """Export a private key as text (one KDF round keeps the tests fast)."""
    return key.export_private_key(fmt, passphrase, rounds=1).decode()


@pytest.mark.parametrize("algorithm", KEY_ALGORITHMS)
def test_load_key_text(
    private_keys: dict[str, asyncssh.SSHKey], algorithm: str
) -> None:
    """Test loading pasted key text, with messy whitespace."""
    key = private_keys[algorithm]
    text = _export(key)
    loaded = load_private_key(text, None, None)
    assert loaded.public_data == key.public_data
    # Windows line endings, surrounding whitespace and no final newline.
    messy = "\n  " + text.strip().replace("\n", "\r\n") + "  "
    assert load_private_key(messy, None, "").public_data == key.public_data
    # Line breaks turned into spaces by a single-line field.
    collapsed = text.strip().replace("\n", " ")
    assert load_private_key(collapsed, None, None).public_data == key.public_data


@pytest.mark.parametrize("algorithm", KEY_ALGORITHMS)
def test_load_key_file(
    private_keys: dict[str, asyncssh.SSHKey], algorithm: str, tmp_path: Path
) -> None:
    """Test loading a key file."""
    key = private_keys[algorithm]
    path = tmp_path / "id_key"
    path.write_text(_export(key))
    assert load_private_key(None, str(path), None).public_data == key.public_data


@pytest.mark.parametrize("fmt", ["pkcs8-pem", "pkcs1-pem"])
def test_load_key_pem(private_keys: dict[str, asyncssh.SSHKey], fmt: str) -> None:
    """Test loading PEM keys."""
    key = private_keys["ssh-rsa"]
    assert load_private_key(_export(key, fmt), None, None).public_data == (
        key.public_data
    )


@pytest.mark.parametrize(
    ("algorithm", "fmt"),
    [
        (algorithm, fmt)
        for algorithm in KEY_ALGORITHMS
        for fmt in ("openssh", "pkcs8-pem", "pkcs1-pem")
        # ed25519 keys have no PKCS#1 format.
        if (algorithm, fmt) != ("ssh-ed25519", "pkcs1-pem")
    ],
)
@pytest.mark.filterwarnings("ignore:.*bcrypt.kdf.*:UserWarning")
def test_load_encrypted_key(
    private_keys: dict[str, asyncssh.SSHKey],
    algorithm: str,
    fmt: str,
    tmp_path: Path,
) -> None:
    """Test encrypted keys with the right, a wrong and a missing passphrase."""
    key = private_keys[algorithm]
    text = _export(key, fmt, passphrase="s3cret")
    path = tmp_path / "id_key"
    path.write_text(text)

    assert load_private_key(text, None, "s3cret").public_data == key.public_data
    assert load_private_key(None, str(path), "s3cret").public_data == key.public_data
    for passphrase in (None, "", "wrong"):
        with pytest.raises(CiscoPassphraseError):
            load_private_key(text, None, passphrase)
        with pytest.raises(CiscoPassphraseError):
            load_private_key(None, str(path), passphrase)


def test_load_key_collapsed_pem_headers(
    private_keys: dict[str, asyncssh.SSHKey],
) -> None:
    """Test that collapsed PEM text with headers is not rebuilt and fails cleanly."""
    text = _export(private_keys["ssh-rsa"], "pkcs1-pem", passphrase="s3cret")
    with pytest.raises(CiscoKeyError):
        load_private_key(text.strip().replace("\n", " "), None, "s3cret")


@pytest.mark.parametrize("fmt", ["pkcs8-pem", "pkcs1-pem"])
def test_load_encrypted_pem_undecodable(
    private_keys: dict[str, asyncssh.SSHKey],
    fmt: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test a wrong passphrase that decrypts an encrypted PEM key to garbage.

    With the old PEM encryption this happens about once in 256 tries, and
    asyncssh then reports an invalid key instead of a wrong passphrase.
    """
    text = _export(private_keys["ssh-rsa"], fmt, passphrase="s3cret")
    path = tmp_path / "id_key"
    path.write_text(text)

    def _raise(*args: object) -> None:
        raise asyncssh.KeyImportError("Invalid PEM private key")

    monkeypatch.setattr(asyncssh, "import_private_key", _raise)
    with pytest.raises(CiscoPassphraseError):
        load_private_key(text, None, "wrong")
    with pytest.raises(CiscoPassphraseError):
        load_private_key(None, str(path), "wrong")
    # Without a passphrase, or for a key that isn't encrypted, it is invalid.
    with pytest.raises(CiscoInvalidKeyError):
        load_private_key(text, None, None)
    plain = _export(private_keys["ssh-rsa"], fmt)
    with pytest.raises(CiscoInvalidKeyError):
        load_private_key(plain, None, "wrong")


@pytest.mark.parametrize(
    "text",
    [
        "garbage",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
    ],
)
def test_load_key_invalid_text(text: str) -> None:
    """Test that invalid key text raises CiscoInvalidKeyError."""
    with pytest.raises(CiscoInvalidKeyError):
        load_private_key(text, None, None)


@pytest.mark.parametrize("algorithm", KEY_ALGORITHMS)
def test_load_key_public_key_pasted(
    private_keys: dict[str, asyncssh.SSHKey], algorithm: str
) -> None:
    """Test that a pasted public key is rejected."""
    public = private_keys[algorithm].export_public_key("openssh").decode()
    with pytest.raises(CiscoInvalidKeyError, match="public key"):
        load_private_key(public, None, None)


def test_load_key_invalid_file(tmp_path: Path) -> None:
    """Test that a file without a key raises CiscoInvalidKeyError."""
    path = tmp_path / "id_key"
    path.write_bytes(b"\x00\xffnot a key")
    with pytest.raises(CiscoInvalidKeyError):
        load_private_key(None, str(path), None)


def test_load_key_file_missing(tmp_path: Path) -> None:
    """Test that a missing file or a directory raises CiscoKeyFileNotFoundError."""
    with pytest.raises(CiscoKeyFileNotFoundError):
        load_private_key(None, str(tmp_path / "missing"), None)
    with pytest.raises(CiscoKeyFileNotFoundError):
        load_private_key(None, str(tmp_path), None)


@pytest.mark.parametrize(
    ("key_data", "key_file"), [(None, None), ("", ""), ("key", "/config/key")]
)
def test_load_key_needs_exactly_one_source(
    key_data: str | None, key_file: str | None
) -> None:
    """Test that exactly one of key text and key file must be given."""
    with pytest.raises(CiscoInvalidKeyError):
        load_private_key(key_data, key_file, None)


def test_load_key_other_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that other decoding errors are mapped to CiscoInvalidKeyError."""

    def _raise(*args: object) -> None:
        raise ValueError("bad data")

    monkeypatch.setattr(asyncssh, "import_private_key", _raise)
    with pytest.raises(CiscoInvalidKeyError, match="bad data"):
        load_private_key("x", None, None)


# --- SSH sessions against the fake IOS server ---------------------------------


@pytest.fixture
def rsa_host_key() -> asyncssh.SSHKey:
    """Return a new RSA host key."""
    return asyncssh.generate_private_key("ssh-rsa", key_size=2048)


@pytest.fixture
def ed25519_host_key() -> asyncssh.SSHKey:
    """Return a new ed25519 host key."""
    return asyncssh.generate_private_key("ssh-ed25519")


@pytest.fixture
def fake_config(rsa_host_key: asyncssh.SSHKey) -> FakeIOSConfig:
    """Return the fake device configuration; tests may change it."""
    return FakeIOSConfig(
        host_keys=[rsa_host_key],
        auth_banner="Authorized access only\n",
        motd="*** Welcome to router1, managed by the network team ***",
    )


@pytest.fixture
async def fake_ios(fake_config: FakeIOSConfig) -> AsyncIterator[FakeIOSServer]:
    """Run the fake IOS server."""
    async with FakeIOSServer(fake_config) as server:
        yield server


def _client(server: FakeIOSServer, **kwargs: object) -> CiscoIOSClient:
    """Return a client for the fake server, logging in with a password."""
    options: dict[str, object] = {"password": "cisco", "timeout": 5.0} | kwargs
    return CiscoIOSClient(
        server.host,
        server.port,
        "admin",
        **options,  # type: ignore[arg-type]
    )


async def test_password_auth_get_all(fake_ios: FakeIOSServer) -> None:
    """Test password login and both commands in one session."""
    client = _client(fake_ios)
    device, entries = await client.async_get_all()

    assert device == C1111_INFO
    assert entries == C1111_ARP
    assert client.presented_host_key == fake_ios.host_public_keys[0]
    assert client.legacy_algorithms is False
    assert len(fake_ios.connections) == 1
    (session,) = fake_ios.sessions
    assert session.commands == [*SETUP_COMMANDS, "show version", "show ip arp", "exit"]
    assert session.exited


async def test_no_local_ssh_files_used(
    fake_ios: FakeIOSServer,
    fake_config: FakeIOSConfig,
    private_keys: dict[str, asyncssh.SSHKey],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that connecting never reads `~/.ssh` files or an SSH agent.

    Such file access would block the event loop.
    """
    key = private_keys["ssh-ed25519"]
    fake_config.authorized_keys = [key.convert_to_public()]
    accessed: list[str] = []
    real_open = builtins.open
    real_access = os.access

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        accessed.append(str(file))
        return real_open(file, *args, **kwargs)

    def _access(path: Any, *args: Any, **kwargs: Any) -> bool:
        accessed.append(str(path))
        return real_access(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _open)
    monkeypatch.setattr(os, "access", _access)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/nonexistent/agent.sock")
    for client in (_client(fake_ios), _client(fake_ios, client_key=key)):
        await client.async_get_all()
    assert accessed == []


@pytest.mark.parametrize("privileged", [False, True])
async def test_prompts(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, privileged: bool
) -> None:
    """Test user EXEC (`>`) and privileged EXEC (`#`) prompts."""
    fake_config.privileged = privileged
    fake_config.hostname = "sw-01.lab"
    client = _client(fake_ios)
    assert await client.async_get_arp_table() == C1111_ARP
    assert await client.async_get_device_info() == C1111_INFO
    assert [session.commands for session in fake_ios.sessions] == [
        [*SETUP_COMMANDS, "show ip arp", "exit"],
        [*SETUP_COMMANDS, "show version", "exit"],
    ]


@pytest.mark.parametrize("algorithm", KEY_ALGORITHMS)
async def test_key_auth(
    fake_ios: FakeIOSServer,
    fake_config: FakeIOSConfig,
    private_keys: dict[str, asyncssh.SSHKey],
    algorithm: str,
) -> None:
    """Test public key login with RSA, ECDSA and ed25519 keys."""
    key = private_keys[algorithm]
    fake_config.password = None
    fake_config.authorized_keys = [key.convert_to_public()]
    client = _client(fake_ios, password=None, client_key=key)
    assert await client.async_get_all() == (C1111_INFO, C1111_ARP)


async def test_key_auth_wrong_key(
    fake_ios: FakeIOSServer,
    fake_config: FakeIOSConfig,
    private_keys: dict[str, asyncssh.SSHKey],
) -> None:
    """Test that a key the device does not know is rejected."""
    fake_config.password = None
    fake_config.authorized_keys = [private_keys["ssh-rsa"].convert_to_public()]
    client = _client(fake_ios, password=None, client_key=private_keys["ssh-ed25519"])
    with pytest.raises(CiscoAuthenticationError):
        await client.async_get_all()


async def test_wrong_password(fake_ios: FakeIOSServer) -> None:
    """Test that a wrong password raises CiscoAuthenticationError."""
    client = _client(fake_ios, password="wrong")
    with pytest.raises(CiscoAuthenticationError):
        await client.async_get_all()
    assert not fake_ios.sessions


async def test_keyboard_interactive_login(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that only offers keyboard-interactive, like IOS with AAA."""
    fake_config.kbdint_only = True
    client = _client(fake_ios)
    assert await client.async_get_all() == (C1111_INFO, C1111_ARP)
    assert fake_ios.kbdint_attempts == [["cisco"]]
    assert fake_ios.password_attempts == []


async def test_keyboard_interactive_wrong_password(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a wrong password at the keyboard-interactive prompt."""
    fake_config.kbdint_only = True
    client = _client(fake_ios, password="wrong")
    with pytest.raises(CiscoAuthenticationError):
        await client.async_get_all()
    assert ["wrong"] in fake_ios.kbdint_attempts
    assert not fake_ios.sessions


async def test_host_key_trust_on_first_use_then_pinned(
    fake_ios: FakeIOSServer,
) -> None:
    """Test capturing the host key and then connecting with it pinned."""
    first = _client(fake_ios)
    await first.async_probe()
    assert first.presented_host_key == fake_ios.host_public_keys[0]

    pinned = _client(fake_ios, host_key=first.presented_host_key)
    assert await pinned.async_get_all() == (C1111_INFO, C1111_ARP)
    assert pinned.presented_host_key == first.presented_host_key


async def test_pinned_ed25519_with_rsa_and_ed25519_offered(
    fake_config: FakeIOSConfig,
    rsa_host_key: asyncssh.SSHKey,
    ed25519_host_key: asyncssh.SSHKey,
) -> None:
    """Test a pinned key when the device has several host key types."""
    fake_config.host_keys = [rsa_host_key, ed25519_host_key]
    async with FakeIOSServer(fake_config) as server:
        for host_key in (ed25519_host_key, rsa_host_key):
            public = host_key.export_public_key("openssh").decode().strip()
            client = _client(server, host_key=public)
            await client.async_get_all()
            assert client.presented_host_key == public


async def test_pinned_host_key_mismatch(
    fake_ios: FakeIOSServer, rsa_host_key: asyncssh.SSHKey
) -> None:
    """Test that a changed host key raises CiscoHostKeyMismatchError."""
    other = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    client = _client(fake_ios, host_key=other.export_public_key("openssh").decode())
    with pytest.raises(CiscoHostKeyMismatchError) as exc_info:
        await client.async_get_all()
    assert exc_info.value.expected_fingerprint == other.get_fingerprint()
    assert exc_info.value.presented_fingerprint == rsa_host_key.get_fingerprint()
    assert client.presented_host_key == fake_ios.host_public_keys[0]
    assert not fake_ios.sessions


async def test_pinned_host_key_type_not_offered(
    fake_ios: FakeIOSServer,
    rsa_host_key: asyncssh.SSHKey,
    ed25519_host_key: asyncssh.SSHKey,
) -> None:
    """Test a pinned key type the device no longer offers."""
    client = _client(
        fake_ios, host_key=ed25519_host_key.export_public_key("openssh").decode()
    )
    with pytest.raises(CiscoHostKeyMismatchError) as exc_info:
        await client.async_probe()
    assert exc_info.value.expected_fingerprint == ed25519_host_key.get_fingerprint()
    # The key the device offers now is fetched without logging in.
    assert exc_info.value.presented_fingerprint == rsa_host_key.get_fingerprint()
    assert client.presented_host_key == fake_ios.host_public_keys[0]
    assert client.legacy_algorithms is False
    assert fake_ios.password_attempts == []
    assert not fake_ios.sessions


@pytest.mark.parametrize("key_changed", [False, True])
async def test_pinned_host_key_early_disconnect(
    fake_ios: FakeIOSServer,
    fake_config: FakeIOSConfig,
    rsa_host_key: asyncssh.SSHKey,
    key_changed: bool,
) -> None:
    """Test a device that drops the connection before it presents a key.

    The key is fetched again without logging in, so a changed key is
    reported no matter how the device ends the key exchange.
    """
    fake_config.drop_after_kexinit = frozenset({1})
    pinned = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    host_key = pinned if key_changed else rsa_host_key
    client = _client(fake_ios, host_key=host_key.export_public_key("openssh").decode())
    if key_changed:
        with pytest.raises(CiscoHostKeyMismatchError) as exc_info:
            await client.async_get_all()
        assert exc_info.value.presented_fingerprint == rsa_host_key.get_fingerprint()
        assert client.presented_host_key == fake_ios.host_public_keys[0]
    else:
        with pytest.raises(_CiscoEarlyDisconnectError):
            await client.async_get_all()
        assert client.presented_host_key is None
    assert len(fake_ios.connections) == 2
    assert fake_ios.password_attempts == []


async def test_pinned_host_key_fetch_fails(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test that the original error is kept when the key can't be fetched."""
    fake_config.drop_after_kexinit = frozenset({1, 2})
    other = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    client = _client(fake_ios, host_key=other.export_public_key("openssh").decode())
    with pytest.raises(_CiscoEarlyDisconnectError):
        await client.async_get_all()
    assert len(fake_ios.connections) == 2


async def test_fetch_host_key(fake_ios: FakeIOSServer) -> None:
    """Test fetching the host key without logging in."""
    client = _client(fake_ios)
    assert await client.async_fetch_host_key() == fake_ios.host_public_keys[0]
    assert client.presented_host_key == fake_ios.host_public_keys[0]
    assert client.legacy_algorithms is False
    assert fake_ios.password_attempts == []
    assert not fake_ios.sessions


async def test_fetch_host_key_legacy(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test fetching the host key of a device that needs legacy algorithms."""
    fake_config.legacy_only = True
    async with FakeIOSServer(fake_config) as server:
        client = _client(server)
        assert await client.async_fetch_host_key() == server.host_public_keys[0]
        assert client.legacy_algorithms is True
        assert not server.sessions


async def test_fetch_host_key_errors(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test errors while fetching the host key."""
    fake_config.server_options = {
        "encryption_algs": ["aes128-ctr"],
        "mac_algs": ["hmac-md5-96"],
    }
    async with FakeIOSServer(fake_config) as server:
        client = _client(server, legacy_algorithms=True)
        with pytest.raises(KEX_FAILURES):
            await client.async_fetch_host_key()
        assert len(server.connections) == 1

    async with silent_tcp_server() as port:
        client = CiscoIOSClient(
            "127.0.0.1", port, "admin", password="cisco", timeout=0.3
        )
        with pytest.raises(CiscoConnectionError, match="Timed out"):
            await client.async_fetch_host_key()

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    client = CiscoIOSClient("127.0.0.1", port, "admin", password="cisco", timeout=2)
    with pytest.raises(CiscoConnectionError, match="Cannot connect"):
        await client.async_fetch_host_key()


async def test_fetch_host_key_not_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test a connection that never checked a host key."""
    conn = MagicMock()
    monkeypatch.setattr(
        asyncssh, "create_connection", AsyncMock(return_value=(conn, None))
    )
    client = CiscoIOSClient("127.0.0.1", 22, "admin", password="cisco")
    with pytest.raises(CiscoConnectionError, match="presented no host key"):
        await client.async_fetch_host_key()
    conn.abort.assert_called_once()


async def test_invalid_pinned_host_key(fake_ios: FakeIOSServer) -> None:
    """Test that an unreadable pinned host key raises CiscoInvalidKeyError."""
    client = _client(fake_ios, host_key="ssh-rsa garbage")
    with pytest.raises(CiscoInvalidKeyError):
        await client.async_get_all()


@pytest.mark.parametrize(
    ("encryption", "mac"),
    [
        # Each legacy cipher and MAC that asyncssh doesn't enable by default.
        ("aes128-cbc", "hmac-sha1"),
        ("3des-cbc", "hmac-md5"),
        ("aes256-cbc", "hmac-sha1-96"),
    ],
)
async def test_probe_legacy_fallback(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, encryption: str, mac: str
) -> None:
    """Test that the probe falls back to legacy algorithms for old devices."""
    fake_config.legacy_only = True
    fake_config.server_options = {"encryption_algs": [encryption], "mac_algs": [mac]}
    async with FakeIOSServer(fake_config) as legacy_server:
        client = _client(legacy_server)
        with pytest.raises(KEX_FAILURES):
            await client.async_get_all()

        assert await client.async_probe() == (C1111_INFO, C1111_ARP)
        assert client.legacy_algorithms is True
        # Later polls use the stored setting.
        assert await client.async_get_all() == (C1111_INFO, C1111_ARP)

        # A pinned key does not hide a real algorithm problem.
        pinned = _client(legacy_server, host_key=client.presented_host_key)
        with pytest.raises(KEX_FAILURES):
            await pinned.async_get_all()


async def test_probe_legacy_fallback_after_early_disconnect(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that drops the connection instead of reporting a KEX error."""
    fake_config.drop_after_kexinit = frozenset({1})
    client = _client(fake_ios)
    assert await client.async_probe() == (C1111_INFO, C1111_ARP)
    assert client.legacy_algorithms is True
    assert len(fake_ios.connections) == 2


@pytest.mark.parametrize(
    ("errors", "expected"),
    [
        # A KEX failure with the legacy algorithms is reported as such.
        ((CiscoKeyExchangeError("a"), CiscoKeyExchangeError("b")), 1),
        ((_CiscoEarlyDisconnectError("a"), CiscoKeyExchangeError("b")), 1),
        # Other connection errors of the legacy attempt keep the first error.
        ((CiscoKeyExchangeError("a"), _CiscoEarlyDisconnectError("b")), 0),
        ((CiscoKeyExchangeError("a"), CiscoConnectionError("b")), 0),
        ((_CiscoEarlyDisconnectError("a"), _CiscoEarlyDisconnectError("b")), 0),
        # A login error with the legacy algorithms is real.
        ((CiscoKeyExchangeError("a"), CiscoAuthenticationError("b")), 1),
        # Other errors are not retried.
        ((CiscoConnectionError("a"),), 0),
        ((CiscoHostKeyMismatchError("a", "b"),), 0),
    ],
)
async def test_probe_fallback_errors(
    errors: tuple[Exception, ...], expected: int
) -> None:
    """Test which error the probe reports when the legacy fallback fails."""
    client = CiscoIOSClient("127.0.0.1", 22, "admin", password="cisco")
    get_all = AsyncMock(side_effect=errors)
    client._async_get_all = get_all  # type: ignore[method-assign]
    with pytest.raises(CiscoError) as exc_info:
        await client.async_probe()
    assert exc_info.value is errors[expected]
    assert [call.args for call in get_all.await_args_list] == [
        (False,),
        (True,),
    ][: len(errors)]
    assert client.legacy_algorithms is False


async def test_probe_without_fallback(fake_ios: FakeIOSServer) -> None:
    """Test that a modern device does not enable legacy algorithms."""
    client = _client(fake_ios)
    assert await client.async_probe() == (C1111_INFO, C1111_ARP)
    assert client.legacy_algorithms is False


@pytest.mark.parametrize("legacy", [False, True])
async def test_probe_no_common_algorithms(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, legacy: bool
) -> None:
    """Test a device without common algorithms, even with the legacy ones."""
    # The MAC is only negotiated with a non-AEAD cipher.
    fake_config.server_options = {
        "encryption_algs": ["aes128-ctr"],
        "mac_algs": ["hmac-md5-96"],
    }
    async with FakeIOSServer(fake_config) as server:
        client = _client(server, legacy_algorithms=legacy)
        with pytest.raises(KEX_FAILURES):
            await client.async_probe()
        assert client.legacy_algorithms is legacy
        # Legacy algorithms are only tried if they weren't used already.
        assert len(server.connections) == (1 if legacy else 2)


async def test_paging_when_terminal_length_rejected(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test IOS-XE Lite, which rejects `terminal length 0` and pages output."""
    fake_config.reject_terminal = True
    fake_config.commands["show ip arp"] = _large_arp_table(120)
    client = _client(fake_ios)
    device, entries = await client.async_get_all()
    assert device == C1111_INFO
    assert len(entries) == 120
    assert entries[-1] == ArpEntry("10.30.0.120", "00:22:44:66:00:77", 0, "Vlan30")
    assert len({entry.mac for entry in entries}) == 120


async def test_paging_with_chunked_output(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test paging when the device sends small pieces of output."""
    fake_config.reject_terminal = True
    fake_config.terminal_length = 10
    fake_config.chunk_size = 7
    fake_config.commands["show ip arp"] = _large_arp_table(30)
    client = _client(fake_ios)
    assert len(await client.async_get_arp_table()) == 30


async def test_no_paging_after_terminal_length_0(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a large table when `terminal length 0` is accepted."""
    fake_config.commands["show ip arp"] = _large_arp_table(600)
    client = _client(fake_ios)
    assert len(await client.async_get_arp_table()) == 600


async def test_split_lines_and_prompt_like_lines(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test banner and output lines that look like a prompt.

    Each line and its line ending arrive separately, so such a line is
    briefly the last, incomplete line of the output.
    """
    fake_config.split_lines = True
    fake_config.motd = "Unauthorized access is prohibited\nWARNING#\nLast line"
    fake_config.commands["show version"] = f"{SHOW_VERSION_C1111}status#\n"
    # A prompt-like line in the middle of the output must not end it early.
    arp_lines = SHOW_IP_ARP_C1111.splitlines(keepends=True)
    fake_config.commands["show ip arp"] = "".join(
        [*arp_lines[:4], "status#\n", *arp_lines[4:]]
    )
    client = _client(fake_ios)
    assert await client.async_get_all() == (C1111_INFO, C1111_ARP)


async def test_unknown_command(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test that a rejected command raises CiscoCommandError."""
    del fake_config.commands["show version"]
    client = _client(fake_ios)
    with pytest.raises(CiscoCommandError, match="Invalid input"):
        await client.async_get_all()
    assert await client.async_get_arp_table() == C1111_ARP


async def test_authorization_failed_at_login(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that closes the session because exec is not authorized."""
    fake_config.close_after_login = "% Authorization failed."
    client = _client(fake_ios)
    with pytest.raises(CiscoCommandError, match="Authorization failed"):
        await client.async_get_all()


@pytest.mark.parametrize("command", ["show version", "show ip arp"])
async def test_command_authorization_failed(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, command: str
) -> None:
    """Test a command denied by AAA command authorization (no leading %)."""
    fake_config.commands[command] = f"{COMMAND_AUTHORIZATION_FAILED}\n"
    client = _client(fake_ios)
    with pytest.raises(
        CiscoCommandError, match=f"rejected '{command}': Command authorization failed"
    ):
        await client.async_probe()


@pytest.mark.parametrize(
    ("command", "output"),
    [
        ("show ip arp", "You are not allowed to run this command\n"),
        ("show version", "You are not allowed to run this command\n"),
        ("show version", ""),
    ],
)
async def test_unexpected_command_output(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, command: str, output: str
) -> None:
    """Test output that is not from `show ip arp` or `show version`."""
    fake_config.commands[command] = output
    client = _client(fake_ios)
    with pytest.raises(CiscoCommandError, match="Unexpected output"):
        await client.async_get_all()


@pytest.mark.parametrize(
    "output",
    ["", "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"],
)
async def test_empty_arp_table(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig, output: str
) -> None:
    """Test that an empty ARP table is not an error."""
    fake_config.commands["show ip arp"] = output
    client = _client(fake_ios)
    assert await client.async_get_arp_table() == []


async def test_session_closed_by_device(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that closes the session before the prompt."""
    fake_config.close_after_login = "Goodbye"
    client = _client(fake_ios)
    with pytest.raises(CiscoConnectionError, match="closed the session"):
        await client.async_get_all()


async def test_connection_dropped(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that drops the connection after login."""
    fake_config.drop_connection = True
    client = _client(fake_ios)
    with pytest.raises(CiscoConnectionError):
        await client.async_get_all()


async def test_device_ignores_exit(
    fake_ios: FakeIOSServer,
    fake_config: FakeIOSConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that the client closes the connection if `exit` is ignored."""
    monkeypatch.setattr(client_module, "_EXIT_TIMEOUT", 0.05)
    fake_config.ignore_exit = True
    client = _client(fake_ios)
    assert await client.async_get_all() == (C1111_INFO, C1111_ARP)
    assert fake_ios.sessions[0].commands[-1] == "exit"


async def test_shell_timeout(
    fake_ios: FakeIOSServer, fake_config: FakeIOSConfig
) -> None:
    """Test a device that never shows a prompt."""
    fake_config.silent = True
    client = _client(fake_ios, timeout=0.3)
    with pytest.raises(CiscoConnectionError, match="Timed out"):
        await client.async_get_all()


async def test_connect_timeout() -> None:
    """Test a device that accepts TCP but never starts SSH."""
    async with silent_tcp_server() as port:
        client = CiscoIOSClient(
            "127.0.0.1", port, "admin", password="cisco", timeout=0.3
        )
        with pytest.raises(CiscoConnectionError):
            await client.async_probe()
        assert client.legacy_algorithms is False


async def test_connection_refused() -> None:
    """Test that a closed port raises CiscoConnectionError."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    client = CiscoIOSClient("127.0.0.1", port, "admin", password="cisco", timeout=2)
    with pytest.raises(CiscoConnectionError, match="Cannot connect"):
        await client.async_get_all()
    assert client.presented_host_key is None

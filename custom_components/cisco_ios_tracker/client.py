"""SSH client for reading the ARP table from Cisco IOS and IOS-XE devices.

This module has no Home Assistant imports so it can be tested on its own.
"""

import asyncio
from collections.abc import Sequence
import contextlib
from dataclasses import dataclass
import logging
from pathlib import Path
import re
from typing import Any

import asyncssh

_LOGGER = logging.getLogger(__name__)

CMD_SHOW_ARP = "show ip arp"
CMD_SHOW_VERSION = "show version"

# Sent before the show commands. Errors are ignored because IOS-XE Lite
# rejects them in user EXEC mode; the reader pages through --More-- instead.
_SETUP_COMMANDS = ("terminal length 0", "terminal width 511")

# Algorithms added on top of the asyncssh defaults for old IOS 12.x/15.x.
_LEGACY_KEX_ALGS = "+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1"
_LEGACY_ENCRYPTION_ALGS = "+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc"
_LEGACY_MAC_ALGS = "+hmac-sha1-96,hmac-md5"

# Errors when the device closes an established connection. Before the host
# key is presented, they can also mean that the key exchange failed.
_DROPPED_ERRORS = (BrokenPipeError, ConnectionResetError)

_READ_SIZE = 65536
# How long to wait for the device to close the session after `exit`.
_EXIT_TIMEOUT = 2.0

# A CLI prompt such as `router1>`, `router1#` or `sw-01.lab(config)#`.
_PROMPT_RE = re.compile(r"[ \t]*(?P<prompt>[\w.\-@/:()]{1,63}[>#])[ \t]?")
_MORE_RE = re.compile(r"[ \t]*-{2}[ \t]?More[ \t]?-{2}[ \t]*")
_MORE_AT_END_RE = re.compile(r"[ \t]*-{2}[ \t]?More[ \t]?-{2}[ \t]*$")
# ANSI/VT100 escape sequences (CSI, character set selection, keypad modes).
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[()][0-9A-Za-z]|[=>78])")
# IOS erases the --More-- marker with backspaces, spaces and backspaces.
_ERASE_RE = re.compile(r"\x08+[ \t]*\x08*")
# AAA command authorization denials ("Command authorization failed.") are
# printed without the leading %.
_COMMAND_ERROR_RE = re.compile(
    r"^[ \t]*(?:%[ \t]*(?:Invalid input|Unknown command|Incomplete command"
    r"|Ambiguous command)|%?[ \t]*(?:Command )?[Aa]uthorization failed).*$",
    re.MULTILINE,
)
_PUBLIC_KEY_RE = re.compile(r"^(?:ssh-|ecdsa-sha2-|sk-)\S+ +AAAA")
# PEM keys encrypted with a passphrase (PKCS#8 or the old PKCS#1 encryption).
_ENCRYPTED_PEM_RE = re.compile(
    rb"^(?:-----BEGIN ENCRYPTED |Proc-Type: 4,ENCRYPTED)", re.MULTILINE
)

_ARP_HEADER_RE = re.compile(r"^[ \t]*Protocol[ \t]+Address\b", re.MULTILINE)
_ARP_RE = re.compile(
    r"^[ \t]*Internet[ \t]+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})[ \t]+(?P<age>-|\d+)"
    r"[ \t]+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    r"[ \t]+(?P<type>\S+)(?:[ \t]+(?P<interface>\S+))?[ \t]*$",
    re.MULTILINE,
)
_VERSION_RE = re.compile(
    r"^Cisco IOS.*?,\s+Version\s+([^\s,]+)", re.MULTILINE | re.IGNORECASE
)
_HOSTNAME_RE = re.compile(r"^(\S+)\s+uptime is\s", re.MULTILINE)
_MODEL_RE = re.compile(
    r"^[Cc]isco\s+(\S+)\s+(?:\([^)]*\)\s+)*(?:processor|with\b)", re.MULTILINE
)
_MODEL_NUMBER_RE = re.compile(r"^Model [Nn]umber\s*:\s*(\S+)", re.MULTILINE)
_SERIAL_RE = re.compile(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", re.MULTILINE)
_BOARD_ID_RE = re.compile(r"^Processor board ID\s+(\S+)", re.MULTILINE)
_BASE_MAC_RE = re.compile(
    r"^Base [Ee]thernet MAC (?:Address|address)\s*:\s*(\S+)", re.MULTILINE
)
_PEM_RE = re.compile(
    r"^(?P<begin>-----BEGIN [A-Z0-9 ]+-----)\s*(?P<body>.*?)\s*"
    r"(?P<end>-----END [A-Z0-9 ]+-----)$",
    re.DOTALL,
)


class CiscoError(Exception):
    """Base class for errors raised by the client."""


class CiscoConnectionError(CiscoError):
    """The device could not be reached or the SSH session failed."""


class CiscoAuthenticationError(CiscoError):
    """The device rejected the credentials."""


class CiscoKeyExchangeError(CiscoConnectionError):
    """The client and the device have no SSH algorithms in common."""


class _CiscoEarlyDisconnectError(CiscoConnectionError):
    """The device closed the connection before the key exchange finished.

    Some devices drop the TCP connection right away when they find no common
    algorithms, so this can hide a key exchange failure.
    """


# Errors after which a connection is tried again with legacy algorithms.
_LEGACY_RETRY_ERRORS = (CiscoKeyExchangeError, _CiscoEarlyDisconnectError)


class CiscoHostKeyMismatchError(CiscoError):
    """The device presented a host key that differs from the pinned one."""

    def __init__(
        self, expected_fingerprint: str, presented_fingerprint: str | None
    ) -> None:
        """Initialize the error with both host key fingerprints."""
        super().__init__(
            f"Host key mismatch: expected {expected_fingerprint}, "
            f"got {presented_fingerprint}"
        )
        self.expected_fingerprint = expected_fingerprint
        self.presented_fingerprint = presented_fingerprint


class CiscoKeyError(CiscoError):
    """The private key could not be loaded."""


class CiscoKeyFileNotFoundError(CiscoKeyError):
    """The private key file does not exist or cannot be read."""


class CiscoInvalidKeyError(CiscoKeyError):
    """The private key is not a valid, supported private key."""


class CiscoPassphraseError(CiscoKeyError):
    """The private key passphrase is missing or wrong."""


class CiscoCommandError(CiscoError):
    """The device rejected a command or returned unexpected output."""


@dataclass(frozen=True, slots=True)
class ArpEntry:
    """A single row of the `show ip arp` output."""

    ip: str
    mac: str
    age: int | None
    interface: str | None


@dataclass(frozen=True, slots=True)
class CiscoDeviceInfo:
    """Device details parsed from `show version`."""

    hostname: str | None
    model: str | None
    sw_version: str | None
    serial: str | None
    base_mac: str | None


def _format_mac(value: str) -> str | None:
    """Return a MAC address in lowercase colon form, or None if invalid."""
    digits = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if len(digits) != 12:
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _clean_output(text: str) -> str:
    """Remove terminal control sequences and paging prompts from CLI output."""
    text = _ANSI_RE.sub("", text)
    text = _MORE_RE.sub("", text)
    text = _ERASE_RE.sub("", text)
    return text.replace("\r", "").replace("\x00", "").replace("\x08", "")


def _normalize_key_text(key_data: str) -> str:
    """Normalize pasted key text so asyncssh can import it.

    Line endings are converted and a trailing newline is added. If the line
    breaks inside a PEM block were turned into spaces (for example by pasting
    into a single-line field), they are restored.
    """
    text = key_data.strip().replace("\r\n", "\n").replace("\r", "\n")
    if (match := _PEM_RE.match(text)) and "\n" not in match["body"]:
        body = match["body"]
        if ":" not in body:  # PEM headers such as Proc-Type cannot be rebuilt
            body = "\n".join(body.split())
        text = f"{match['begin']}\n{body}\n{match['end']}"
    return f"{text}\n"


def load_private_key(
    key_data: str | None, key_file: str | None, passphrase: str | None
) -> asyncssh.SSHKey:
    """Load a private key from text or from a file.

    Exactly one of `key_data` and `key_file` must be given. This is blocking
    (file access and key derivation), so run it in an executor.
    """
    if bool(key_data) == bool(key_file):
        raise CiscoInvalidKeyError("Give either the key text or a key file")
    data: bytes | str
    if key_file:
        try:
            data = Path(key_file).read_bytes()
        except OSError as err:
            raise CiscoKeyFileNotFoundError(
                f"Cannot read the key file {key_file}: {err.strerror or err}"
            ) from err
    else:
        data = _normalize_key_text(key_data or "")
        if _PUBLIC_KEY_RE.match(data):
            raise CiscoInvalidKeyError(
                "This is a public key, the private key is needed"
            )
    try:
        return asyncssh.import_private_key(data, passphrase or None)
    except asyncssh.KeyEncryptionError as err:
        raise CiscoPassphraseError(str(err)) from err
    except asyncssh.KeyImportError as err:
        message = str(err)
        if "Passphrase must be specified" in message or "Unable to decrypt" in message:
            raise CiscoPassphraseError(message) from err
        raw = data.encode() if isinstance(data, str) else data
        if passphrase and _ENCRYPTED_PEM_RE.search(raw):
            # A wrong passphrase sometimes decrypts an encrypted PEM key to
            # data that only fails to parse.
            raise CiscoPassphraseError(message) from err
        raise CiscoInvalidKeyError(message) from err
    except ValueError as err:
        raise CiscoInvalidKeyError(str(err)) from err


def _cisco_mac(value: str) -> str:
    """Convert a Cisco `xxxx.xxxx.xxxx` MAC to lowercase colon form."""
    digits = value.replace(".", "").lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def parse_arp_table(output: str) -> list[ArpEntry]:
    """Parse the output of `show ip arp`.

    Header lines, banners, prompts and `Incomplete` rows are skipped.
    """
    return [
        ArpEntry(
            ip=match["ip"],
            mac=_cisco_mac(match["mac"]),
            age=None if match["age"] == "-" else int(match["age"]),
            interface=match["interface"],
        )
        for match in _ARP_RE.finditer(_clean_output(output))
    ]


def _parse_arp_output(output: str) -> list[ArpEntry]:
    """Parse `show ip arp` output from the device and check that it is one.

    Empty output is a valid, empty table. Other text without an ARP header
    or row means the device printed something else, such as an AAA message.
    """
    entries = parse_arp_table(output)
    text = _clean_output(output).strip()
    if text and not entries and not _ARP_HEADER_RE.search(text):
        raise CiscoCommandError(
            f"Unexpected output from {CMD_SHOW_ARP!r}: {text.splitlines()[0]}"
        )
    return entries


def _search(pattern: re.Pattern[str], text: str) -> str | None:
    """Return the first group of the first match, or None."""
    return match[1] if (match := pattern.search(text)) else None


def parse_show_version(output: str) -> CiscoDeviceInfo:
    """Parse the output of `show version`."""
    text = _clean_output(output)
    serial = _search(_SERIAL_RE, text) or _search(_BOARD_ID_RE, text)
    base_mac = _search(_BASE_MAC_RE, text)
    return CiscoDeviceInfo(
        hostname=_search(_HOSTNAME_RE, text),
        model=_search(_MODEL_RE, text) or _search(_MODEL_NUMBER_RE, text),
        sw_version=_search(_VERSION_RE, text),
        serial=serial.upper() if serial else None,
        base_mac=_format_mac(base_mac) if base_mac else None,
    )


def _parse_version_output(output: str) -> CiscoDeviceInfo:
    """Parse `show version` output from the device and check that it is one."""
    device = parse_show_version(output)
    if device.sw_version is None and device.hostname is None:
        text = _clean_output(output).strip()
        first_line = text.splitlines()[0] if text else "no output"
        raise CiscoCommandError(
            f"Unexpected output from {CMD_SHOW_VERSION!r}: {first_line}"
        )
    return device


def fingerprint(public_key_openssh: str) -> str:
    """Return the SHA256 fingerprint of an OpenSSH format public key."""
    try:
        key = asyncssh.import_public_key(public_key_openssh)
    except ValueError as err:  # KeyImportError is a ValueError
        raise CiscoInvalidKeyError(f"Invalid public key: {err}") from err
    return key.get_fingerprint()


def _export_public_key(key: asyncssh.SSHKey) -> str:
    """Return a public key in OpenSSH format without a trailing newline."""
    return key.export_public_key("openssh").decode().strip()


class _HostKeyValidator(asyncssh.SSHClient):
    """Record the host key the device presents and compare it to the pinned key."""

    def __init__(
        self, expected: asyncssh.SSHKey | None, *, reject: bool = False
    ) -> None:
        """Initialize with the pinned key, or None to trust on first use.

        With `reject`, every key is refused after it was recorded, so the
        connection ends before any credentials are sent.
        """
        self.expected = expected
        self.reject = reject
        self.presented: asyncssh.SSHKey | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        """Accept the key if nothing is pinned or it matches the pinned key."""
        _LOGGER.debug("%s presented host key %s", host, key.get_fingerprint())
        self.presented = key
        if self.reject:
            return False
        return self.expected is None or key == self.expected


class _CiscoShell:
    """Drive an interactive IOS CLI session over an SSH PTY channel."""

    def __init__(
        self, process: asyncssh.SSHClientProcess[str], read_timeout: float
    ) -> None:
        """Initialize the shell."""
        self._process = process
        self._read_timeout = read_timeout
        self._prompt: str | None = None
        # Cleaned complete lines received since the last command was sent.
        self._lines: list[str] = []
        # Raw data of the current, incomplete line.
        self._pending = ""

    async def _async_read(self) -> None:
        """Read the next chunk of data from the device."""
        async with asyncio.timeout(self._read_timeout):
            data = await self._process.stdout.read(_READ_SIZE)
        if not data:
            received = "\n".join([*self._lines, _clean_output(self._pending)])
            if match := _COMMAND_ERROR_RE.search(received):
                _LOGGER.debug("The device closed the session: %s", match[0].strip())
                raise CiscoCommandError(match[0].strip())
            raise CiscoConnectionError("The device closed the session")
        complete, newline, self._pending = (self._pending + data).rpartition("\n")
        if newline:
            self._lines.extend(_clean_output(complete).split("\n"))

    def _at_prompt(self) -> bool:
        """Return True if the current incomplete line is the CLI prompt.

        A --More-- paging prompt is answered with a space.
        """
        pending = _ANSI_RE.sub("", self._pending)
        if more := _MORE_AT_END_RE.search(pending):
            # Drop the marker so it is answered only once.
            self._pending = pending[: more.start()]
            self._process.stdin.write(" ")
            return False
        if (match := _PROMPT_RE.fullmatch(_clean_output(pending))) is None:
            return False
        return self._prompt is None or match["prompt"] == self._prompt

    async def async_read_prompt(self) -> str:
        """Read until the first prompt, skipping banners and the MOTD."""
        while not self._at_prompt():
            await self._async_read()
        match = _PROMPT_RE.fullmatch(_clean_output(self._pending))
        assert match is not None
        self._prompt = match["prompt"]
        self._lines.clear()
        self._pending = ""
        return self._prompt

    def _consume_echo(self, command: str) -> bool:
        """Drop everything up to and including the echo of the command.

        Anything before the echo (such as the rest of a banner that looked
        like a prompt) is discarded, and the text in front of the echo on the
        same line is the real prompt.
        """
        for index, line in enumerate(self._lines):
            if (stripped := line.rstrip()).endswith(command):
                if match := _PROMPT_RE.fullmatch(stripped[: -len(command)]):
                    self._prompt = match["prompt"]
                del self._lines[: index + 1]
                return True
        return False

    async def async_run(self, command: str) -> str:
        """Run a command and return its output without the echo and prompt."""
        self._lines.clear()
        self._process.stdin.write(f"{command}\n")
        while not self._consume_echo(command):
            await self._async_read()
        while not self._at_prompt():
            await self._async_read()
        self._pending = ""
        return "\n".join(self._lines).strip("\n")

    async def async_exit(self) -> None:
        """Log out and wait briefly for the device to close the session."""
        with contextlib.suppress(asyncssh.Error, OSError):
            self._process.stdin.write("exit\n")
            async with asyncio.timeout(_EXIT_TIMEOUT):
                await self._process.wait_closed()


class CiscoIOSClient:
    """Run show commands on a Cisco IOS or IOS-XE device over SSH."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        *,
        password: str | None = None,
        client_key: asyncssh.SSHKey | None = None,
        host_key: str | None = None,
        legacy_algorithms: bool = False,
        timeout: float = 15.0,
    ) -> None:
        """Initialize the client."""
        self.host = host
        self.port = port
        self.username = username
        self.legacy_algorithms = legacy_algorithms
        self._password = password
        self._client_key = client_key
        self._host_key = host_key
        self._timeout = timeout
        self._presented_host_key: str | None = None

    @property
    def presented_host_key(self) -> str | None:
        """Return the host key the device presented on the last connection."""
        return self._presented_host_key

    async def async_get_arp_table(self) -> list[ArpEntry]:
        """Return the parsed ARP table."""
        (output,) = await self._async_run_commands(
            (CMD_SHOW_ARP,), self.legacy_algorithms
        )
        return _parse_arp_output(output)

    async def async_get_device_info(self) -> CiscoDeviceInfo:
        """Return the parsed device information."""
        (output,) = await self._async_run_commands(
            (CMD_SHOW_VERSION,), self.legacy_algorithms
        )
        return _parse_version_output(output)

    async def async_get_all(self) -> tuple[CiscoDeviceInfo, list[ArpEntry]]:
        """Return device information and the ARP table from one SSH session."""
        return await self._async_get_all(self.legacy_algorithms)

    async def async_probe(self) -> tuple[CiscoDeviceInfo, list[ArpEntry]]:
        """Test the connection, falling back to legacy algorithms if needed.

        When the fallback works, `legacy_algorithms` is set to True so the
        caller can store it.
        """
        try:
            return await self._async_get_all(self.legacy_algorithms)
        except _LEGACY_RETRY_ERRORS as err:
            if self.legacy_algorithms:
                raise
            first_error: CiscoConnectionError = err
            _LOGGER.debug(
                "No common SSH algorithms with %s, retrying with legacy algorithms: %s",
                self.host,
                err,
            )
        try:
            result = await self._async_get_all(True)
        except CiscoKeyExchangeError:
            raise
        except CiscoConnectionError:
            # The legacy attempt failed for another reason, so the first
            # error describes the problem better.
            pass
        else:
            self.legacy_algorithms = True
            return result
        raise first_error

    async def async_fetch_host_key(self) -> str:
        """Return the host key the device presents, without logging in.

        No credentials are sent. Legacy algorithms are tried like in
        `async_probe`, and `legacy_algorithms` is set to True when needed.
        """
        try:
            key = await self._async_fetch_host_key(self.legacy_algorithms)
        except _LEGACY_RETRY_ERRORS:
            if self.legacy_algorithms:
                raise
            key = await self._async_fetch_host_key(True)
            self.legacy_algorithms = True
        self._presented_host_key = _export_public_key(key)
        return self._presented_host_key

    async def _async_get_all(
        self, legacy: bool
    ) -> tuple[CiscoDeviceInfo, list[ArpEntry]]:
        """Run `show version` and `show ip arp` in one session and parse them."""
        version, arp = await self._async_run_commands(
            (CMD_SHOW_VERSION, CMD_SHOW_ARP), legacy
        )
        return _parse_version_output(version), _parse_arp_output(arp)

    def _connect_options(
        self, expected: asyncssh.SSHKey | None, legacy: bool
    ) -> dict[str, Any]:
        """Return the asyncssh connection options.

        Every option that would make asyncssh read files from `~/.ssh` or use
        an SSH agent is set explicitly so that connecting never blocks.
        """
        options: dict[str, Any] = {
            "port": self.port,
            "username": self.username,
            "password": self._password,
            "client_keys": [self._client_key] if self._client_key else None,
            "preferred_auth": (
                "publickey" if self._client_key else "password,keyboard-interactive"
            ),
            "known_hosts": ([], [], []),
            "config": None,
            "agent_path": None,
            "x509_trusted_certs": None,
            "gss_host": None,
            "connect_timeout": self._timeout,
            "login_timeout": self._timeout,
        }
        if expected is not None:
            # Only negotiate the pinned key type. Otherwise a device with
            # several host keys may present another one and look changed.
            options["server_host_key_algs"] = [
                alg.decode() for alg in expected.sig_algorithms
            ]
        if legacy:
            options["kex_algs"] = _LEGACY_KEX_ALGS
            options["encryption_algs"] = _LEGACY_ENCRYPTION_ALGS
            options["mac_algs"] = _LEGACY_MAC_ALGS
        return options

    async def _async_run_commands(
        self, commands: Sequence[str], legacy: bool
    ) -> list[str]:
        """Connect, run the commands in one CLI session and return their output."""
        expected: asyncssh.SSHKey | None = None
        expected_fingerprint = ""
        if self._host_key is not None:
            try:
                expected = asyncssh.import_public_key(self._host_key)
            except ValueError as err:  # KeyImportError is a ValueError
                raise CiscoInvalidKeyError(f"Invalid pinned host key: {err}") from err
            expected_fingerprint = expected.get_fingerprint()
        validator = _HostKeyValidator(expected)
        options = self._connect_options(expected, legacy)
        self._presented_host_key = None
        try:
            async with asyncio.timeout(self._timeout * 3):
                return await self._async_session(validator, commands, options)
        except asyncssh.PermissionDenied as err:
            raise CiscoAuthenticationError(
                f"Authentication failed: {err.reason}"
            ) from err
        except asyncssh.HostKeyNotVerifiable as err:
            presented = validator.presented
            raise CiscoHostKeyMismatchError(
                expected_fingerprint,
                presented.get_fingerprint() if presented else None,
            ) from err
        except (asyncssh.Error, *_DROPPED_ERRORS) as err:
            if validator.presented is None and expected is not None:
                # The key exchange failed with only the pinned key type
                # allowed. The device may no longer offer that type; how it
                # reports that differs, so check the key it presents now.
                await self._async_raise_if_host_key_changed(expected, legacy, err)
            if isinstance(err, asyncssh.KeyExchangeFailed):
                raise CiscoKeyExchangeError(f"No common SSH algorithms: {err}") from err
            if validator.presented is None:
                raise _CiscoEarlyDisconnectError(f"SSH error: {err}") from err
            raise CiscoConnectionError(f"SSH error: {err}") from err
        except TimeoutError as err:
            raise CiscoConnectionError(
                f"Timed out talking to {self.host}:{self.port}"
            ) from err
        except OSError as err:
            raise CiscoConnectionError(
                f"Cannot connect to {self.host}:{self.port}: {err}"
            ) from err
        finally:
            if validator.presented is not None:
                self._presented_host_key = _export_public_key(validator.presented)

    async def _async_raise_if_host_key_changed(
        self, expected: asyncssh.SSHKey, legacy: bool, err: Exception
    ) -> None:
        """Raise CiscoHostKeyMismatchError if the device presents another key.

        Errors while fetching the key are ignored, so the caller can raise
        the original error.
        """
        try:
            presented = await self._async_fetch_host_key(legacy)
        except CiscoError:
            return
        if presented == expected:
            return
        self._presented_host_key = _export_public_key(presented)
        raise CiscoHostKeyMismatchError(
            expected.get_fingerprint(), presented.get_fingerprint()
        ) from err

    async def _async_fetch_host_key(self, legacy: bool) -> asyncssh.SSHKey:
        """Connect without logging in and return the host key the device presents.

        Any host key type is allowed. The key is refused after it was
        recorded, so the connection ends before authentication.
        """
        validator = _HostKeyValidator(None, reject=True)
        options = self._connect_options(None, legacy) | {
            "password": None,
            "client_keys": None,
        }
        try:
            async with asyncio.timeout(self._timeout * 3):
                conn, _ = await asyncssh.create_connection(
                    lambda: validator, self.host, **options
                )
        except asyncssh.HostKeyNotVerifiable:
            pass
        except asyncssh.KeyExchangeFailed as err:
            raise CiscoKeyExchangeError(
                f"No common SSH algorithms: {err.reason}"
            ) from err
        except (asyncssh.Error, *_DROPPED_ERRORS) as err:
            raise _CiscoEarlyDisconnectError(f"SSH error: {err}") from err
        except TimeoutError as err:
            raise CiscoConnectionError(
                f"Timed out talking to {self.host}:{self.port}"
            ) from err
        except OSError as err:
            raise CiscoConnectionError(
                f"Cannot connect to {self.host}:{self.port}: {err}"
            ) from err
        else:
            # Only reached if no host key was checked at all.
            conn.abort()
        if validator.presented is None:
            raise CiscoConnectionError(f"{self.host} presented no host key")
        _LOGGER.debug(
            "Fetched host key %s from %s",
            validator.presented.get_fingerprint(),
            self.host,
        )
        return validator.presented

    async def _async_session(
        self,
        validator: _HostKeyValidator,
        commands: Sequence[str],
        options: dict[str, Any],
    ) -> list[str]:
        """Open the SSH connection and run the commands in a PTY shell."""
        _LOGGER.debug("Connecting to %s:%s as %s", self.host, self.port, self.username)
        conn, _ = await asyncssh.create_connection(
            lambda: validator, self.host, **options
        )
        async with conn:
            process: asyncssh.SSHClientProcess[str] = await conn.create_process(
                term_type="vt100",
                term_size=(511, 0),
                encoding="utf-8",
                errors="replace",
            )
            shell = _CiscoShell(process, self._timeout)
            prompt = await shell.async_read_prompt()
            _LOGGER.debug("Got prompt %s from %s", prompt, self.host)
            for command in _SETUP_COMMANDS:
                if _COMMAND_ERROR_RE.search(await shell.async_run(command)):
                    _LOGGER.debug(
                        "%s rejected %r, paging through the output instead",
                        self.host,
                        command,
                    )
            outputs: list[str] = []
            for command in commands:
                output = await shell.async_run(command)
                if match := _COMMAND_ERROR_RE.search(output):
                    _LOGGER.debug(
                        "%s rejected %r: %s", self.host, command, match[0].strip()
                    )
                    raise CiscoCommandError(
                        f"The device rejected {command!r}: {match[0].strip()}"
                    )
                outputs.append(output)
            await shell.async_exit()
        return outputs

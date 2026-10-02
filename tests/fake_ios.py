"""In-process asyncssh server that emulates a Cisco IOS/IOS-XE CLI.

The server listens on 127.0.0.1 with a random port. Tests that use it need
`@pytest.mark.usefixtures("socket_enabled")`.
"""

import asyncio
from collections.abc import AsyncIterator
import contextlib
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Self

import asyncssh

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Read at import time so no blocking file access happens in the event loop.
FIXTURES: dict[str, str] = {
    path.name: path.read_bytes().decode() for path in FIXTURES_DIR.glob("*.txt")
}


def load_fixture(name: str) -> str:
    """Return the content of a command output fixture."""
    return FIXTURES[name]


SHOW_VERSION_C1111 = load_fixture("show_version_c1111_8pe.txt")
SHOW_IP_ARP_C1111 = load_fixture("show_ip_arp_c1111.txt")

# Algorithms of an old IOS 12.x device; asyncssh does not enable them by default.
LEGACY_SERVER_ALGORITHMS: dict[str, list[str]] = {
    "kex_algs": ["diffie-hellman-group1-sha1"],
    "encryption_algs": ["aes128-cbc"],
    "mac_algs": ["hmac-sha1"],
    "signature_algs": ["ssh-rsa"],
}

INVALID_INPUT = "% Invalid input detected at '^' marker."
MORE = " --More-- "
# IOS erases the --More-- marker with backspaces, spaces and backspaces.
MORE_ERASE = "\b" * 9 + " " * 9 + "\b" * 9

_TERMINAL_RE = re.compile(
    r"^term(?:inal)?\s+(?P<setting>len(?:gth)?|wid(?:th)?)\s+(\d+)$"
)


def default_commands() -> dict[str, str]:
    """Return the default command outputs (a C1111-8PE on IOS-XE 17.9)."""
    return {
        "show version": SHOW_VERSION_C1111,
        "show ip arp": SHOW_IP_ARP_C1111,
    }


@dataclass
class FakeIOSConfig:
    """Behavior of the fake IOS device."""

    hostname: str = "router1"
    # True for a privileged EXEC prompt (`router1#`), False for `router1>`.
    privileged: bool = False
    username: str = "admin"
    # None disables password authentication.
    password: str | None = "cisco"
    # Only offer keyboard-interactive with a password prompt, like IOS with
    # `aaa new-model` and TACACS+ or RADIUS.
    kbdint_only: bool = False
    # Public (or private) keys accepted for public key authentication.
    authorized_keys: list[asyncssh.SSHKey] = field(default_factory=list)
    # Host keys of the server; an RSA key is generated when empty.
    host_keys: list[asyncssh.SSHKey] = field(default_factory=list)
    # Banner sent during authentication (`banner login`).
    auth_banner: str | None = None
    # Message of the day printed in the shell before the first prompt.
    motd: str | None = None
    # Command outputs by full command; other commands are rejected.
    commands: dict[str, str] = field(default_factory=default_commands)
    # Reject `terminal length`/`terminal width` like IOS-XE Lite does.
    reject_terminal: bool = False
    # Initial terminal length; output is paged with --More-- unless 0.
    terminal_length: int = 24
    # Only offer old algorithms (group1-sha1, aes128-cbc, hmac-sha1).
    legacy_only: bool = False
    # Close these connections (1 is the first) right after sending the
    # KEXINIT, like a device that drops the connection when it finds no
    # common algorithms.
    drop_after_kexinit: frozenset[int] = frozenset()
    # Extra options for `asyncssh.listen`, such as `mac_algs`.
    server_options: dict[str, Any] = field(default_factory=dict)
    # Ignore `exit` instead of closing the session.
    ignore_exit: bool = False
    # Drop the TCP connection as soon as the shell starts.
    drop_connection: bool = False
    # Write output in chunks of this many characters (None: all at once).
    chunk_size: int | None = None
    # Write each line and its line ending separately.
    split_lines: bool = False
    # Print this message and close the session instead of showing a prompt.
    close_after_login: str | None = None
    # Never print a prompt (the shell hangs).
    silent: bool = False

    @property
    def prompt(self) -> str:
        """Return the CLI prompt."""
        return f"{self.hostname}{'#' if self.privileged else '>'}"


@dataclass
class FakeIOSSession:
    """What happened in one shell session."""

    commands: list[str] = field(default_factory=list)
    exited: bool = False


def _close_after_kexinit(conn: asyncssh.SSHServerConnection) -> None:
    """Make the connection close right after it sent its KEXINIT."""
    send_kexinit = conn._send_kexinit

    def _send_kexinit_and_close() -> None:
        send_kexinit()
        conn._transport.close()

    conn._send_kexinit = _send_kexinit_and_close


class _FakeSSHServer(asyncssh.SSHServer):
    """SSH server callbacks for authentication."""

    def __init__(self, server: FakeIOSServer) -> None:
        """Initialize the server callbacks."""
        self._server = server
        self._config = server.config
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Track the connection so it can be closed with the server."""
        self._conn = conn
        self._server.connections.append(conn)
        if len(self._server.connections) in self._config.drop_after_kexinit:
            _close_after_kexinit(conn)

    def begin_auth(self, username: str) -> bool:
        """Send the login banner and require authentication."""
        if self._config.auth_banner and self._conn is not None:
            self._conn.send_auth_banner(self._config.auth_banner)
        return True

    def password_auth_supported(self) -> bool:
        """Return whether password authentication is enabled."""
        return self._config.password is not None and not self._config.kbdint_only

    def validate_password(self, username: str, password: str) -> bool:
        """Check the username and password."""
        self._server.password_attempts.append(password)
        return username == self._config.username and password == self._config.password

    def kbdint_auth_supported(self) -> bool:
        """Return whether keyboard-interactive authentication is enabled."""
        return self._config.password is not None

    def get_kbdint_challenge(
        self, username: str, lang: str, submethods: str
    ) -> tuple[str, str, str, list[tuple[str, bool]]]:
        """Ask for the password like IOS with AAA does."""
        return "", "", "", [("Password: ", False)]

    def validate_kbdint_response(self, username: str, responses: list[str]) -> bool:
        """Check the username and the password typed at the prompt."""
        self._server.kbdint_attempts.append(list(responses))
        return username == self._config.username and responses == [
            self._config.password
        ]

    def public_key_auth_supported(self) -> bool:
        """Return whether public key authentication is enabled."""
        return bool(self._config.authorized_keys)

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Check the username and the client key."""
        return username == self._config.username and any(
            key.public_data == allowed.public_data
            for allowed in self._config.authorized_keys
        )


class _FakeShell:
    """Emulate the IOS EXEC shell on one SSH channel."""

    def __init__(
        self, config: FakeIOSConfig, process: asyncssh.SSHServerProcess[str]
    ) -> None:
        """Initialize the shell."""
        self._config = config
        self._process = process
        self._input = ""
        self._length = config.terminal_length
        self._last_was_cr = False
        self.session = FakeIOSSession()

    async def _write(self, text: str) -> None:
        """Write text with CRLF line endings, optionally in pieces."""
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        pieces = [text]
        if self._config.split_lines:
            pieces = [piece for piece in re.split(r"(\r\n)", text) if piece]
        if size := self._config.chunk_size:
            pieces = [
                piece[i : i + size]
                for piece in pieces
                for i in range(0, len(piece), size)
            ]
        for piece in pieces:
            self._process.stdout.write(piece)
            if len(pieces) > 1:
                await self._process.stdout.drain()
                await asyncio.sleep(0.002)

    async def _getch(self) -> str | None:
        """Return the next typed character, or None at end of input."""
        if not self._input:
            self._input = await self._process.stdin.read(1024)
            if not self._input:
                return None
        char, self._input = self._input[0], self._input[1:]
        return char

    async def _readline(self) -> str | None:
        """Read one command line, echoing it back."""
        line = ""
        while (char := await self._getch()) is not None:
            if char == "\n" and not line and self._last_was_cr:
                self._last_was_cr = False
                continue
            self._last_was_cr = char == "\r"
            if char in "\r\n":
                await self._write("\n")
                return line
            if char in "\x08\x7f":
                line = line[:-1]
                await self._write("\b \b")
                continue
            line += char
            await self._write(char)
        return None

    async def _write_output(self, output: str) -> None:
        """Write command output, pausing with --More-- if paging is on."""
        lines = output.replace("\r\n", "\n").splitlines(keepends=True)
        # IOS shows one line less than the terminal length per page.
        page = self._length - 1
        if page < 1:
            await self._write("".join(lines))
            return
        for start in range(0, len(lines), page):
            await self._write("".join(lines[start : start + page]))
            if start + page < len(lines):
                await self._write(MORE)
                key = await self._getch()
                await self._write(MORE_ERASE)
                if key in (None, "q", "Q"):
                    return

    async def _invalid(self, line: str) -> None:
        """Print the IOS invalid input error with the caret marker."""
        position = len(self._config.prompt) + max(line.rfind(" ") + 1, 0)
        await self._write(f"{' ' * position}^\n{INVALID_INPUT}\n\n")

    async def _execute(self, line: str) -> bool:
        """Run one command; return False when the session should end."""
        command = " ".join(line.split())
        if not command:
            return True
        self.session.commands.append(command)
        if command in ("exit", "quit", "logout"):
            self.session.exited = True
            return self._config.ignore_exit
        if match := _TERMINAL_RE.match(command):
            if self._config.reject_terminal:
                await self._invalid(line)
            elif match["setting"].startswith("len"):
                self._length = int(match[2])
            return True
        if command in self._config.commands:
            await self._write_output(self._config.commands[command])
            return True
        await self._invalid(line)
        return True

    async def run(self) -> None:
        """Run the shell until the client logs out or disconnects."""
        config = self._config
        if config.drop_connection:
            self._process.get_extra_info("connection").abort()
            return
        if config.motd:
            await self._write(f"\n{config.motd}\n")
        if config.close_after_login:
            await self._write(f"{config.close_after_login}\n")
            return
        if config.silent:
            await self._process.stdin.read()
            return
        await self._write(config.prompt)
        while (line := await self._readline()) is not None:
            if not await self._execute(line):
                return
            await self._write(config.prompt)


class FakeIOSServer:
    """An asyncssh server on 127.0.0.1 that behaves like a Cisco IOS device."""

    def __init__(self, config: FakeIOSConfig | None = None) -> None:
        """Initialize the server."""
        self.config = config or FakeIOSConfig()
        if not self.config.host_keys:
            self.config.host_keys = [
                asyncssh.generate_private_key("ssh-rsa", key_size=2048)
            ]
        self.host = "127.0.0.1"
        self.port = 0
        self.sessions: list[FakeIOSSession] = []
        self.connections: list[asyncssh.SSHServerConnection] = []
        # Passwords received with password and keyboard-interactive login.
        self.password_attempts: list[str] = []
        self.kbdint_attempts: list[list[str]] = []
        self._acceptor: asyncssh.SSHAcceptor | None = None

    @property
    def host_public_keys(self) -> list[str]:
        """Return the host public keys in OpenSSH format."""
        return [
            key.export_public_key("openssh").decode().strip()
            for key in self.config.host_keys
        ]

    def _server_factory(self) -> asyncssh.SSHServer:
        """Return the authentication callbacks for a new connection."""
        return _FakeSSHServer(self)

    async def _handle_process(self, process: asyncssh.SSHServerProcess[str]) -> None:
        """Run the fake shell on a new session."""
        shell = _FakeShell(self.config, process)
        self.sessions.append(shell.session)
        with contextlib.suppress(asyncssh.Error, OSError):
            await shell.run()
            process.exit(0)

    async def start(self) -> None:
        """Start listening."""
        options: dict[str, Any] = {}
        if self.config.legacy_only:
            options.update(LEGACY_SERVER_ALGORITHMS)
        options.update(self.config.server_options)
        self._acceptor = await asyncssh.listen(
            self.host,
            0,
            server_factory=self._server_factory,
            server_host_keys=self.config.host_keys,
            process_factory=self._handle_process,
            line_editor=False,
            config=None,
            x509_trusted_certs=None,
            authorized_client_keys=None,
            gss_host=None,
            **options,
        )
        self.port = self._acceptor.sockets[0].getsockname()[1]

    async def close(self) -> None:
        """Stop listening and close all open connections."""
        if self._acceptor is not None:
            self._acceptor.close()
            await self._acceptor.wait_closed()
            self._acceptor = None
        for conn in self.connections:
            conn.close()
            await conn.wait_closed()

    async def __aenter__(self) -> Self:
        """Start the server."""
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Close the server."""
        await self.close()


@contextlib.asynccontextmanager
async def silent_tcp_server() -> AsyncIterator[int]:
    """Accept TCP connections but never answer, to test timeouts.

    Yields the port number.
    """
    writers: list[asyncio.StreamWriter] = []

    async def _handle(
        _reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writers.append(writer)

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        for writer in writers:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        await server.wait_closed()

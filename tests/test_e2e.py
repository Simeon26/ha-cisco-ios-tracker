"""End-to-end tests against an emulated Cisco device over real SSH.

Nothing is mocked between the config flow and the SSH server: the real
client connects to the fake IOS server from `fake_ios.py` on 127.0.0.1.
"""

from collections.abc import AsyncIterator

import asyncssh
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from custom_components.cisco_ios_tracker.client import fingerprint
from custom_components.cisco_ios_tracker.const import (
    AUTH_PASSWORD,
    AUTH_PRIVATE_KEY,
    CONF_AUTH_METHOD,
    CONF_HOST_KEY,
    CONF_LEGACY_ALGORITHMS,
    CONF_PRIVATE_KEY,
    DOMAIN,
    SCAN_INTERVAL,
)
from homeassistant.components.device_tracker import ATTR_IP
from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    SOURCE_USER,
    ConfigEntryState,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    STATE_HOME,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import (
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.util import dt as dt_util

from .fake_ios import SHOW_IP_ARP_C1111, FakeIOSConfig, FakeIOSServer

pytestmark = pytest.mark.usefixtures("socket_enabled")

USERNAME = "homeassistant"
SERIAL = "FGL2231L0AB"
# Clients with age 0 in the C1111 fixture, plus one that appears later.
MAC_LAPTOP = "00:1d:ec:02:07:ab"
MAC_PI = "b8:27:eb:12:34:56"
MAC_UPSTREAM = "00:50:56:01:01:01"
MAC_PHONE = "f0:18:98:aa:bb:cc"
# Entries that must never become trackers.
MAC_STALE = "a4:b1:c1:d2:e3:f4"  # age 3
MAC_ROUTER = "7c:31:0e:5a:1b:40"  # age "-": the router's own interface

ENTITY_LAPTOP = "device_tracker.00_1d_ec_02_07_ab"
ENTITY_PI = "device_tracker.b8_27_eb_12_34_56"
ENTITY_UPSTREAM = "device_tracker.00_50_56_01_01_01"
ENTITY_PHONE = "device_tracker.f0_18_98_aa_bb_cc"
ENTITY_SENSOR = "sensor.router1_connected_clients"

EXPECTED_COMMANDS = [
    "terminal length 0",
    "terminal width 511",
    "show version",
    "show ip arp",
    "exit",
]


@pytest.fixture
def client_key() -> asyncssh.SSHKey:
    """Return the user key of Home Assistant (ed25519, IOS-XE 17.8.1+)."""
    return asyncssh.generate_private_key("ssh-ed25519")


@pytest.fixture(autouse=True)
def known_client_devices(hass: HomeAssistant) -> None:
    """Register the client MACs with another integration.

    Trackers are only enabled by default when another integration already
    knows the MAC address.
    """
    other_entry = MockConfigEntry(domain="something_else")
    other_entry.add_to_hass(hass)
    device_registry = dr.async_get(hass)
    for mac in (MAC_LAPTOP, MAC_PI, MAC_UPSTREAM, MAC_PHONE, MAC_STALE, MAC_ROUTER):
        device_registry.async_get_or_create(
            config_entry_id=other_entry.entry_id,
            connections={(dr.CONNECTION_NETWORK_MAC, mac)},
        )


@pytest.fixture
async def key_server(client_key: asyncssh.SSHKey) -> AsyncIterator[FakeIOSServer]:
    """Emulate a C1111-8PE with key login and a privileged prompt."""
    config = FakeIOSConfig(
        username=USERNAME,
        password=None,
        authorized_keys=[client_key],
        privileged=True,
        auth_banner="Authorized access only\r\n",
        motd="*** router1 - managed by the network team ***",
    )
    async with FakeIOSServer(config) as server:
        yield server


@pytest.fixture
async def password_server() -> AsyncIterator[FakeIOSServer]:
    """Emulate a C1111-8PE with password login and a user EXEC prompt."""
    config = FakeIOSConfig(username=USERNAME, password="cisco", privileged=False)
    async with FakeIOSServer(config) as server:
        yield server


async def _async_config_flow(
    hass: HomeAssistant,
    server: FakeIOSServer,
    method: str,
    credentials: dict[str, str],
) -> MockConfigEntry:
    """Add the integration through the config flow and return the entry."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_HOST: server.host, CONF_PORT: server.port, CONF_USERNAME: USERNAME},
    )
    assert result["type"] is FlowResultType.MENU
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": method}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == method
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], credentials
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY, result.get("errors")
    await hass.async_block_till_done()

    entry = result["result"]
    assert entry.title == "router1"
    assert entry.unique_id == SERIAL
    assert entry.data[CONF_AUTH_METHOD] == method
    # The host key is captured on first use and pinned.
    assert entry.data[CONF_HOST_KEY] == server.host_public_keys[0]
    assert entry.data[CONF_LEGACY_ALGORITHMS] is False
    assert entry.state is ConfigEntryState.LOADED
    return entry


async def _async_poll(hass: HomeAssistant) -> None:
    """Let the coordinator poll the device once."""
    async_fire_time_changed(hass, dt_util.utcnow() + SCAN_INTERVAL)
    await hass.async_block_till_done(wait_background_tasks=True)


def _assert_initial_states(hass: HomeAssistant) -> None:
    """Check the entities created from the C1111 ARP table."""
    laptop = hass.states.get(ENTITY_LAPTOP)
    assert laptop is not None
    assert laptop.state == STATE_HOME
    assert laptop.attributes[ATTR_IP] == "192.168.1.20"
    assert laptop.attributes["interface"] == "Vlan1"

    pi = hass.states.get(ENTITY_PI)
    assert pi is not None
    assert pi.state == STATE_HOME
    assert pi.attributes[ATTR_IP] == "192.168.1.35"

    upstream = hass.states.get(ENTITY_UPSTREAM)
    assert upstream is not None
    assert upstream.attributes["interface"] == "GigabitEthernet0/0/0"

    # Stale entries and the router's own addresses are not tracked.
    assert hass.states.get("device_tracker.a4_b1_c1_d2_e3_f4") is None
    assert hass.states.get("device_tracker.7c_31_0e_5a_1b_40") is None
    assert hass.states.get(ENTITY_PHONE) is None

    sensor = hass.states.get(ENTITY_SENSOR)
    assert sensor is not None
    assert sensor.state == "3"


def _assert_router_device(
    device_registry: dr.DeviceRegistry, entry: MockConfigEntry
) -> None:
    """Check the device registry entry of the router."""
    routers = [
        device
        for device in dr.async_entries_for_config_entry(device_registry, entry.entry_id)
        if (DOMAIN, SERIAL) in device.identifiers
    ]
    assert len(routers) == 1
    router = routers[0]
    assert router.name == "router1"
    assert router.manufacturer == "Cisco"
    assert router.model == "C1111-8PE"
    assert router.sw_version == "17.09.04a"
    assert router.serial_number == SERIAL


async def test_key_login_c1111(
    hass: HomeAssistant,
    key_server: FakeIOSServer,
    client_key: asyncssh.SSHKey,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test a C1111-8PE with a pasted ed25519 key and a `router1#` prompt."""
    private_key = client_key.export_private_key("openssh").decode()
    entry = await _async_config_flow(
        hass, key_server, AUTH_PRIVATE_KEY, {CONF_PRIVATE_KEY: private_key}
    )
    assert CONF_PASSWORD not in entry.data

    _assert_initial_states(hass)
    _assert_router_device(device_registry, entry)
    tracker_entries = [
        registry_entry
        for registry_entry in er.async_entries_for_config_entry(
            entity_registry, entry.entry_id
        )
        if registry_entry.domain == "device_tracker"
    ]
    assert {registry_entry.entity_id for registry_entry in tracker_entries} == {
        ENTITY_LAPTOP,
        ENTITY_PI,
        ENTITY_UPSTREAM,
    }
    # One session for the config flow and one for the first refresh, each
    # running both commands and logging out.
    assert len(key_server.sessions) == 2
    for session in key_server.sessions:
        assert session.commands == EXPECTED_COMMANDS
        assert session.exited

    # A new client shows up on the next poll; the pinned host key still fits.
    key_server.config.commands["show ip arp"] = (
        SHOW_IP_ARP_C1111
        + "Internet  192.168.1.77            0   f018.98aa.bbcc  ARPA   Vlan1\n"
    )
    await _async_poll(hass)

    assert len(key_server.sessions) == 3
    phone = hass.states.get(ENTITY_PHONE)
    assert phone is not None
    assert phone.state == STATE_HOME
    assert phone.attributes[ATTR_IP] == "192.168.1.77"
    sensor = hass.states.get(ENTITY_SENSOR)
    assert sensor is not None
    assert sensor.state == "4"

    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED


async def test_password_login_user_exec(
    hass: HomeAssistant,
    password_server: FakeIOSServer,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test a C1111-8PE with a password and a `router1>` prompt."""
    entry = await _async_config_flow(
        hass, password_server, AUTH_PASSWORD, {CONF_PASSWORD: "cisco"}
    )
    assert entry.data[CONF_PASSWORD] == "cisco"
    assert CONF_PRIVATE_KEY not in entry.data

    _assert_initial_states(hass)
    _assert_router_device(device_registry, entry)

    # Paging is turned off before the commands, so no --More-- is needed.
    assert len(password_server.sessions) == 2
    for session in password_server.sessions:
        assert session.commands == EXPECTED_COMMANDS

    await _async_poll(hass)
    assert len(password_server.sessions) == 3
    laptop = hass.states.get(ENTITY_LAPTOP)
    assert laptop is not None
    assert laptop.state == STATE_HOME

    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_host_key_change_and_reconfigure(
    hass: HomeAssistant,
    password_server: FakeIOSServer,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test a changed host key: repair issue, then reconfigure to accept it."""
    entry = await _async_config_flow(
        hass, password_server, AUTH_PASSWORD, {CONF_PASSWORD: "cisco"}
    )
    real_host_key = entry.data[CONF_HOST_KEY]

    # Pretend another RSA key was pinned, as if the device had a new key.
    other_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    old_host_key = other_key.export_public_key("openssh").decode().strip()
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, CONF_HOST_KEY: old_host_key}
    )
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_RETRY
    issue = issue_registry.async_get_issue(
        DOMAIN, f"host_key_mismatch_{entry.entry_id}"
    )
    assert issue is not None
    assert issue.translation_placeholders is not None
    assert issue.translation_placeholders["expected"] == fingerprint(old_host_key)
    assert issue.translation_placeholders["presented"] == fingerprint(real_host_key)

    # Reconfigure asks to confirm the new key before it logs in.
    password_attempts = len(password_server.password_attempts)
    sessions = len(password_server.sessions)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id}
    )
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_HOST: password_server.host, CONF_PORT: password_server.port},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure_confirm_host_key"
    assert result["description_placeholders"] == {
        "host": password_server.host,
        "old_fingerprint": fingerprint(old_host_key),
        "new_fingerprint": fingerprint(real_host_key),
    }
    # The password was not sent to the device with the unconfirmed key.
    assert len(password_server.password_attempts) == password_attempts
    assert len(password_server.sessions) == sessions

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert password_server.password_attempts[password_attempts:][0] == "cisco"

    assert entry.data[CONF_HOST_KEY] == real_host_key
    assert entry.state is ConfigEntryState.LOADED
    assert (
        issue_registry.async_get_issue(DOMAIN, f"host_key_mismatch_{entry.entry_id}")
        is None
    )
    laptop = hass.states.get(ENTITY_LAPTOP)
    assert laptop is not None
    assert laptop.state == STATE_HOME

    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_command_authorization_failed_during_poll(
    hass: HomeAssistant, password_server: FakeIOSServer
) -> None:
    """Test that a denied `show ip arp` makes the entities unavailable.

    The trackers must not silently go away because of an empty table.
    """
    entry = await _async_config_flow(
        hass, password_server, AUTH_PASSWORD, {CONF_PASSWORD: "cisco"}
    )
    password_server.config.commands["show ip arp"] = "Command authorization failed.\n"
    await _async_poll(hass)

    laptop = hass.states.get(ENTITY_LAPTOP)
    assert laptop is not None
    assert laptop.state == STATE_UNAVAILABLE
    assert entry.runtime_data.last_update_success is False

    assert await hass.config_entries.async_unload(entry.entry_id)

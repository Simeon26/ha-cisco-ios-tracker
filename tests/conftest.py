"""Common fixtures for the Cisco IOS Tracker tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.syrupy import HomeAssistantSnapshotExtension
from syrupy.assertion import SnapshotAssertion

from custom_components.cisco_ios_tracker.client import ArpEntry, CiscoDeviceInfo
from custom_components.cisco_ios_tracker.const import (
    AUTH_PASSWORD,
    CONF_AUTH_METHOD,
    CONF_HOST_KEY,
    CONF_LEGACY_ALGORITHMS,
    CONF_MAX_ARP_AGE,
    DOMAIN,
)
from homeassistant.components.device_tracker import CONF_CONSIDER_HOME
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

HOST = "192.0.2.1"
USERNAME = "homeassistant"
PASSWORD = "secret-password"
SERIAL = "FGL2231L0AB"
HOST_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCstoredkey router1"
NEW_HOST_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnewkey router1"

ROUTER_MAC = "00:1d:ec:00:00:01"
MAC_1 = "00:1d:ec:02:07:ab"
MAC_2 = "00:1d:ec:02:07:ac"
MAC_STALE = "00:1d:ec:02:07:ad"
MAC_NEW = "00:1d:ec:02:07:ae"

DEVICE_INFO = CiscoDeviceInfo(
    hostname="router1",
    model="C1111-8PE",
    sw_version="17.09.04a",
    serial=SERIAL,
    base_mac=None,
)

ARP_ENTRIES = [
    ArpEntry(ip="10.1.10.1", mac=ROUTER_MAC, age=None, interface="Vlan10"),
    ArpEntry(ip="10.1.10.20", mac=MAC_1, age=0, interface="Vlan10"),
    ArpEntry(ip="10.1.20.21", mac=MAC_2, age=0, interface="Vlan20"),
    ArpEntry(ip="10.1.10.30", mac=MAC_STALE, age=5, interface="Vlan10"),
]

ENTRY_DATA = {
    CONF_HOST: HOST,
    CONF_PORT: 22,
    CONF_USERNAME: USERNAME,
    CONF_AUTH_METHOD: AUTH_PASSWORD,
    CONF_PASSWORD: PASSWORD,
    CONF_HOST_KEY: HOST_KEY,
    CONF_LEGACY_ALGORITHMS: False,
}
ENTRY_OPTIONS = {CONF_CONSIDER_HOME: 180, CONF_MAX_ARP_AGE: 0}


def fake_fingerprint(public_key: str) -> str:
    """Return a deterministic stand-in for a SHA256 fingerprint."""
    return f"SHA256:{public_key.split()[1][-8:]}"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Allow Home Assistant to load the custom integration in every test."""


@pytest.fixture
def mock_fingerprint() -> Generator[None]:
    """Make fingerprints of the fake host keys work in the config flow."""
    with patch(
        "custom_components.cisco_ios_tracker.config_flow.fingerprint",
        side_effect=fake_fingerprint,
    ):
        yield


@pytest.fixture
def snapshot(snapshot: SnapshotAssertion) -> SnapshotAssertion:
    """Return a snapshot assertion with the Home Assistant extension."""
    return snapshot.use_extension(HomeAssistantSnapshotExtension)


@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
    """Prevent the integration from being set up in config flow tests."""
    with patch(
        "custom_components.cisco_ios_tracker.async_setup_entry", return_value=True
    ) as mock_setup:
        yield mock_setup


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a config entry for a C1111-8PE with password login."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="router1",
        data=dict(ENTRY_DATA),
        options=dict(ENTRY_OPTIONS),
        unique_id=SERIAL,
        entry_id="01JCISCO0000000000000000AB",
    )


@pytest.fixture
def mock_client_class() -> Generator[MagicMock]:
    """Mock the SSH client class in the integration and the config flow."""
    with (
        patch(
            "custom_components.cisco_ios_tracker.CiscoIOSClient", autospec=True
        ) as client_class,
        patch(
            "custom_components.cisco_ios_tracker.config_flow.CiscoIOSClient",
            new=client_class,
        ),
    ):
        client = client_class.return_value
        client.async_get_all.return_value = (DEVICE_INFO, list(ARP_ENTRIES))
        client.async_probe.return_value = (DEVICE_INFO, list(ARP_ENTRIES))
        client.presented_host_key = HOST_KEY
        client.legacy_algorithms = False
        yield client_class


@pytest.fixture
def mock_client(mock_client_class: MagicMock) -> MagicMock:
    """Return the mocked SSH client."""
    return mock_client_class.return_value


@pytest.fixture
def mock_load_private_key() -> Generator[MagicMock]:
    """Mock loading private keys in the integration and the config flow."""
    with (
        patch(
            "custom_components.cisco_ios_tracker.load_private_key"
        ) as load_private_key,
        patch(
            "custom_components.cisco_ios_tracker.config_flow.load_private_key",
            new=load_private_key,
        ),
    ):
        yield load_private_key


@pytest.fixture
def mock_device_registry_devices(hass: HomeAssistant) -> None:
    """Register the client MACs with another integration.

    Trackers are only enabled by default when another integration already
    knows the MAC address.
    """
    other_entry = MockConfigEntry(domain="something_else")
    other_entry.add_to_hass(hass)
    device_registry = dr.async_get(hass)
    for index, mac in enumerate((MAC_1, MAC_2, MAC_STALE, MAC_NEW)):
        device_registry.async_get_or_create(
            name=f"Client {index}",
            config_entry_id=other_entry.entry_id,
            connections={(dr.CONNECTION_NETWORK_MAC, mac)},
        )


@pytest.fixture
async def init_integration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_client: MagicMock,
) -> MockConfigEntry:
    """Set up the integration."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    return mock_config_entry

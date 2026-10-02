"""Tests for the Cisco IOS Tracker setup."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import MagicMock

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)
from syrupy.assertion import SnapshotAssertion

from custom_components.cisco_ios_tracker import async_remove_config_entry_device
from custom_components.cisco_ios_tracker.client import (
    CiscoAuthenticationError,
    CiscoConnectionError,
    CiscoHostKeyMismatchError,
    CiscoInvalidKeyError,
    CiscoKeyFileNotFoundError,
    CiscoPassphraseError,
)
from custom_components.cisco_ios_tracker.const import (
    AUTH_KEY_FILE,
    AUTH_PRIVATE_KEY,
    CONF_AUTH_METHOD,
    CONF_KEY_FILE,
    CONF_PASSPHRASE,
    CONF_PRIVATE_KEY,
    DOMAIN,
    SCAN_INTERVAL,
)
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, issue_registry as ir

from .conftest import ARP_ENTRIES, DEVICE_INFO, ENTRY_DATA, HOST_KEY, MAC_1, MAC_STALE


def _get_device(
    device_registry: dr.DeviceRegistry,
    entry_id: str,
    *,
    identifier: str | None = None,
    mac: str | None = None,
) -> dr.DeviceEntry:
    """Return the device of the config entry with an identifier or MAC."""
    devices = [
        device
        for device in dr.async_entries_for_config_entry(device_registry, entry_id)
        if (DOMAIN, identifier) in device.identifiers
        or (dr.CONNECTION_NETWORK_MAC, mac) in device.connections
    ]
    assert len(devices) == 1
    return devices[0]


KEY_ENTRY_DATA = {
    key: value for key, value in ENTRY_DATA.items() if key != CONF_PASSWORD
}


async def test_setup_and_unload(
    hass: HomeAssistant,
    mock_client_class: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test setting up and unloading a config entry."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    mock_client_class.assert_called_once_with(
        "192.0.2.1",
        22,
        "homeassistant",
        password="secret-password",
        client_key=None,
        host_key=HOST_KEY,
        legacy_algorithms=False,
    )

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED


@pytest.mark.parametrize(
    ("auth_data", "expected_args"),
    [
        (
            {CONF_AUTH_METHOD: AUTH_PRIVATE_KEY, CONF_PRIVATE_KEY: "key"},
            ("key", None, None),
        ),
        (
            {
                CONF_AUTH_METHOD: AUTH_KEY_FILE,
                CONF_KEY_FILE: "/config/.ssh/id_rsa",
                CONF_PASSPHRASE: "phrase",
            },
            (None, "/config/.ssh/id_rsa", "phrase"),
        ),
    ],
)
async def test_setup_with_key(
    hass: HomeAssistant,
    mock_client_class: MagicMock,
    mock_load_private_key: MagicMock,
    auth_data: dict[str, str],
    expected_args: tuple[str | None, ...],
) -> None:
    """Test that the key is loaded and passed to the client."""
    entry = MockConfigEntry(
        domain=DOMAIN, data={**KEY_ENTRY_DATA, **auth_data}, unique_id="FGL2231L0AB"
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.LOADED
    mock_load_private_key.assert_called_once_with(*expected_args)
    kwargs = mock_client_class.call_args.kwargs
    assert kwargs["client_key"] is mock_load_private_key.return_value
    assert kwargs["password"] is None


async def test_setup_key_file_not_found(
    hass: HomeAssistant, mock_client: MagicMock, mock_load_private_key: MagicMock
) -> None:
    """Test that a missing key file fails setup without reauthentication."""
    mock_load_private_key.side_effect = CiscoKeyFileNotFoundError
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            **KEY_ENTRY_DATA,
            CONF_AUTH_METHOD: AUTH_KEY_FILE,
            CONF_KEY_FILE: "/config/.ssh/missing",
        },
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_ERROR
    assert not hass.config_entries.flow.async_progress()
    mock_client.async_get_all.assert_not_called()


@pytest.mark.parametrize("side_effect", [CiscoPassphraseError, CiscoInvalidKeyError])
async def test_setup_key_invalid(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_load_private_key: MagicMock,
    side_effect: type[Exception],
) -> None:
    """Test that a key that cannot be loaded starts reauthentication."""
    mock_load_private_key.side_effect = side_effect
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**KEY_ENTRY_DATA, CONF_AUTH_METHOD: AUTH_PRIVATE_KEY, "private_key": "x"},
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    assert flows[0]["context"]["source"] == SOURCE_REAUTH


async def test_setup_not_ready(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that a connection error retries setup later."""
    mock_client.async_get_all.side_effect = CiscoConnectionError("timeout")
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_setup_auth_failed(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that rejected credentials start reauthentication."""
    mock_client.async_get_all.side_effect = CiscoAuthenticationError
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    assert flows[0]["context"]["source"] == SOURCE_REAUTH
    assert flows[0]["context"]["entry_id"] == mock_config_entry.entry_id


async def test_setup_host_key_mismatch(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test that a changed host key at startup creates a repair issue."""
    mock_client.async_get_all.side_effect = CiscoHostKeyMismatchError(
        "SHA256:stored", "SHA256:presented"
    )
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
    issue = issue_registry.async_get_issue(
        DOMAIN, f"host_key_mismatch_{mock_config_entry.entry_id}"
    )
    assert issue is not None
    assert issue.severity is ir.IssueSeverity.ERROR
    assert not issue.is_fixable
    assert issue.translation_placeholders == {
        "host": "192.0.2.1",
        "title": "router1",
        "expected": "SHA256:stored",
        "presented": "SHA256:presented",
    }


@pytest.mark.usefixtures("init_integration")
async def test_router_device(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    device_registry: dr.DeviceRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test that the router is registered as a device."""
    device = _get_device(
        device_registry, mock_config_entry.entry_id, identifier="FGL2231L0AB"
    )
    assert device == snapshot


async def test_router_device_updates(
    hass: HomeAssistant,
    mock_client: MagicMock,
    device_registry: dr.DeviceRegistry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test the router device without serial and after a software update."""
    entry = MockConfigEntry(domain=DOMAIN, data=dict(ENTRY_DATA), unique_id=None)
    switch = replace(
        DEVICE_INFO,
        hostname=None,
        model="WS-C2960X-48FPD-L",
        sw_version="15.2(7)E8",
        serial=None,
        base_mac="00:1d:ec:00:00:99",
    )
    mock_client.async_get_all.return_value = (switch, list(ARP_ENTRIES))
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    device = _get_device(device_registry, entry.entry_id, identifier=entry.entry_id)
    assert device.name == "192.0.2.1"
    assert device.serial_number is None
    assert device.connections == {(dr.CONNECTION_NETWORK_MAC, "00:1d:ec:00:00:99")}
    assert device.sw_version == "15.2(7)E8"

    mock_client.async_get_all.return_value = (
        replace(switch, sw_version="15.2(7)E9"),
        list(ARP_ENTRIES),
    )
    freezer.tick(SCAN_INTERVAL)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    device = _get_device(device_registry, entry.entry_id, identifier=entry.entry_id)
    assert device.sw_version == "15.2(7)E9"


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_remove_config_entry_device(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    device_registry: dr.DeviceRegistry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test which devices can be removed from the config entry."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    entry_id = mock_config_entry.entry_id
    router = _get_device(device_registry, entry_id, identifier="FGL2231L0AB")
    assert not await async_remove_config_entry_device(hass, mock_config_entry, router)

    client = _get_device(device_registry, entry_id, mac=MAC_1)
    assert not await async_remove_config_entry_device(hass, mock_config_entry, client)

    # A device that was never seen can be removed.
    stale = MagicMock(
        spec=dr.DeviceEntry,
        connections={(dr.CONNECTION_NETWORK_MAC, MAC_STALE)},
        identifiers={("something_else", "stale")},
    )
    assert await async_remove_config_entry_device(hass, mock_config_entry, stale)

    # After the client left and consider home passed, it can be removed.
    mock_client.async_get_all.return_value = (DEVICE_INFO, [])
    freezer.tick(timedelta(seconds=181))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert await async_remove_config_entry_device(hass, mock_config_entry, client)

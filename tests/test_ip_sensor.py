"""Tests for the IP address sensors of the Cisco IOS Tracker integration."""

from datetime import timedelta
from unittest.mock import MagicMock

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
    mock_restore_cache_with_extra_data,
)

from custom_components.cisco_ios_tracker.client import ArpEntry, CiscoConnectionError
from custom_components.cisco_ios_tracker.const import DOMAIN
from homeassistant.const import STATE_UNAVAILABLE, EntityCategory
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .conftest import DEVICE_INFO, MAC_1, MAC_2, SERIAL, find_entry_device

TRACKER_1 = "device_tracker.00_1d_ec_02_07_ab"
SENSOR_1 = "sensor.00_1d_ec_02_07_ab_ip_address"
SENSOR_2 = "sensor.00_1d_ec_02_07_ac_ip_address"


async def _poll(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: int = 30
) -> None:
    """Let the coordinator poll the router."""
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()


async def _reload(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Reload the config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()


async def test_unknown_mac(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the sensor of a client whose MAC address no integration knows."""
    sensor = entity_registry.async_get(SENSOR_1)
    assert sensor is not None
    assert sensor.unique_id == f"{SERIAL}_{MAC_1}_ip_address"
    assert sensor.entity_category is EntityCategory.DIAGNOSTIC
    assert sensor.device_id is None
    # Disabled together with its tracker.
    assert sensor.disabled_by is er.RegistryEntryDisabler.INTEGRATION

    # Enabling the tracker enables the sensor.
    entity_registry.async_update_entity(TRACKER_1, disabled_by=None)
    await hass.async_block_till_done()
    assert entity_registry.async_get(SENSOR_1).disabled_by is None
    await _reload(hass, init_integration)

    state = hass.states.get(SENSOR_1)
    assert state.state == "10.1.10.20"
    assert state.attributes["friendly_name"] == "00:1d:ec:02:07:ab IP address"


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_known_mac(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test the sensor sits on the same automatic device as its tracker."""
    sensor = entity_registry.async_get(SENSOR_1)
    assert sensor.disabled_by is None
    tracker = entity_registry.async_get(TRACKER_1)
    assert sensor.device_id is not None
    assert sensor.device_id == tracker.device_id
    assert (
        find_entry_device(
            hass, init_integration.entry_id, (dr.CONNECTION_NETWORK_MAC, MAC_1)
        ).id
        == sensor.device_id
    )

    state = hass.states.get(SENSOR_1)
    assert state.state == "10.1.10.20"
    assert state.attributes["friendly_name"] == "00:1d:ec:02:07:ab IP address"
    assert hass.states.get(SENSOR_2).state == "10.1.20.21"


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_last_known_address(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that the sensor follows address changes and keeps the last one."""
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [ArpEntry("10.1.10.99", MAC_1, 0, "Vlan10")],
    )
    await _poll(hass, freezer)
    assert hass.states.get(SENSOR_1).state == "10.1.10.99"
    # The second client left the ARP table; its last address is kept.
    assert hass.states.get(SENSOR_2).state == "10.1.20.21"

    mock_client.async_get_all.return_value = (DEVICE_INFO, [])
    await _poll(hass, freezer, 600)
    assert hass.states.get(SENSOR_1).state == "10.1.10.99"


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_unavailable(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    mock_client: MagicMock,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test the sensor is unavailable while the router can't be reached."""
    mock_client.async_get_all.side_effect = CiscoConnectionError("down")
    await _poll(hass, freezer)
    assert hass.states.get(SENSOR_1).state == STATE_UNAVAILABLE


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_restore(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_client: MagicMock,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the last known address of an away client survives a restart."""
    mock_config_entry.add_to_hass(hass)
    entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"{SERIAL}_{MAC_2}",
        config_entry=mock_config_entry,
        suggested_object_id="00_1d_ec_02_07_ac",
    )
    entity_registry.async_get_or_create(
        "sensor",
        DOMAIN,
        f"{SERIAL}_{MAC_2}_ip_address",
        config_entry=mock_config_entry,
        suggested_object_id="00_1d_ec_02_07_ac_ip_address",
    )
    mock_restore_cache_with_extra_data(
        hass,
        [
            (
                State(SENSOR_2, "10.1.20.50"),
                {"native_value": "10.1.20.50", "native_unit_of_measurement": None},
            )
        ],
    )
    # Only the first client is active after the restart.
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [ArpEntry("10.1.10.20", MAC_1, 0, "Vlan10")],
    )
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert hass.states.get(SENSOR_2).state == "10.1.20.50"
    assert hass.states.get(SENSOR_1).state == "10.1.10.20"


async def test_follows_tracker_enabled_state(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the sensor is enabled and disabled together with its tracker."""
    entity_registry.async_update_entity(TRACKER_1, disabled_by=None)
    await hass.async_block_till_done()
    assert entity_registry.async_get(SENSOR_1).disabled_by is None

    entity_registry.async_update_entity(
        TRACKER_1, disabled_by=er.RegistryEntryDisabler.USER
    )
    await hass.async_block_till_done()
    assert (
        entity_registry.async_get(SENSOR_1).disabled_by
        is er.RegistryEntryDisabler.INTEGRATION
    )

    # A sensor you disabled yourself stays disabled.
    entity_registry.async_update_entity(
        SENSOR_1, disabled_by=er.RegistryEntryDisabler.USER
    )
    entity_registry.async_update_entity(TRACKER_1, disabled_by=None)
    await hass.async_block_till_done()
    assert (
        entity_registry.async_get(SENSOR_1).disabled_by is er.RegistryEntryDisabler.USER
    )

    # Disabling the tracker again leaves the sensor alone too.
    entity_registry.async_update_entity(
        TRACKER_1, disabled_by=er.RegistryEntryDisabler.USER
    )
    await hass.async_block_till_done()
    assert (
        entity_registry.async_get(SENSOR_1).disabled_by is er.RegistryEntryDisabler.USER
    )


async def test_unrelated_registry_updates(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test registry changes that don't concern a tracker are ignored."""
    # Not the disabled state.
    entity_registry.async_update_entity(TRACKER_1, name="Laptop")
    # Not a tracker.
    entity_registry.async_update_entity(SENSOR_2, disabled_by=None)
    # A tracker of another integration.
    other = entity_registry.async_get_or_create(
        "device_tracker", "other", "abc", disabled_by=er.RegistryEntryDisabler.USER
    )
    entity_registry.async_update_entity(other.entity_id, disabled_by=None)
    # A tracker whose sensor was deleted.
    entity_registry.async_remove(SENSOR_1)
    entity_registry.async_update_entity(TRACKER_1, disabled_by=None)
    await hass.async_block_till_done()
    assert entity_registry.async_get(SENSOR_1) is None
    assert (
        entity_registry.async_get(TRACKER_1.replace("ab", "ac")).disabled_by
        is er.RegistryEntryDisabler.INTEGRATION
    )


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_removed_with_tracker(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    mock_client: MagicMock,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test the sensor is removed with its tracker and added back with it."""
    # The client is away when you delete its tracker.
    mock_client.async_get_all.return_value = (DEVICE_INFO, [])
    await _poll(hass, freezer)
    entity_registry.async_remove(TRACKER_1)
    await _poll(hass, freezer)
    assert entity_registry.async_get(SENSOR_1) is None

    # Both come back when the client is active again.
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [ArpEntry("10.1.10.20", MAC_1, 0, "Vlan10")],
    )
    await _poll(hass, freezer)
    assert entity_registry.async_get(TRACKER_1) is not None
    assert hass.states.get(SENSOR_1).state == "10.1.10.20"


async def test_upgrade_with_enabled_tracker(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_client: MagicMock,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test a new sensor for a tracker you enabled by hand starts enabled."""
    mock_config_entry.add_to_hass(hass)
    entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"{SERIAL}_{MAC_1}",
        config_entry=mock_config_entry,
        suggested_object_id="00_1d_ec_02_07_ab",
    )
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert entity_registry.async_get(SENSOR_1).disabled_by is None
    assert hass.states.get(SENSOR_1).state == "10.1.10.20"
    # The other tracker is new and its MAC unknown, so both start disabled.
    assert (
        entity_registry.async_get(SENSOR_2).disabled_by
        is er.RegistryEntryDisabler.INTEGRATION
    )

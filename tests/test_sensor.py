"""Tests for the Cisco IOS Tracker sensor platform."""

from collections.abc import Generator
from datetime import timedelta
from unittest.mock import MagicMock, patch

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
    snapshot_platform,
)
from syrupy.assertion import SnapshotAssertion

from custom_components.cisco_ios_tracker.client import ArpEntry
from custom_components.cisco_ios_tracker.const import DOMAIN
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .conftest import DEVICE_INFO, MAC_1, SERIAL

ENTITY_ID = "sensor.router1_connected_clients"


@pytest.fixture(autouse=True)
def platforms() -> Generator[None]:
    """Only set up the sensor platform."""
    with patch("custom_components.cisco_ios_tracker.PLATFORMS", [Platform.SENSOR]):
        yield


@pytest.mark.usefixtures("init_integration")
async def test_entities(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the sensor entity."""
    await snapshot_platform(hass, entity_registry, snapshot, mock_config_entry.entry_id)

    entity_entry = entity_registry.async_get(ENTITY_ID)
    assert entity_entry is not None
    device = device_registry.async_get(entity_entry.device_id)
    assert device is not None
    assert (DOMAIN, SERIAL) in device.identifiers


@pytest.mark.usefixtures("init_integration")
async def test_connected_clients(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that the sensor counts the clients that are home."""
    assert hass.states.get(ENTITY_ID).state == "2"

    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [ArpEntry("10.1.10.20", MAC_1, 0, "Vlan10")],
    )
    freezer.tick(timedelta(seconds=200))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    assert hass.states.get(ENTITY_ID).state == "1"

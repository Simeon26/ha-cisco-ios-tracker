"""Sensor platform for the Cisco IOS Tracker integration."""

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoConfigEntry, CiscoCoordinator

# The coordinator does all the polling.
PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CiscoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the sensor for the router."""
    async_add_entities([CiscoConnectedClientsSensor(entry.runtime_data)])


class CiscoConnectedClientsSensor(CoordinatorEntity[CiscoCoordinator], SensorEntity):
    """Number of clients that are currently home."""

    _attr_has_entity_name = True
    _attr_translation_key = "connected_clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: CiscoCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        identifier = coordinator.router_identifier
        self._attr_unique_id = f"{identifier}_connected_clients"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, identifier)})

    @property
    def native_value(self) -> int:
        """Return the number of clients that are home."""
        return len(self.coordinator.connected_macs())

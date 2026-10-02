"""Sensor platform for the Cisco IOS Tracker integration."""

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.sensor import (
    RestoreSensor,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import CiscoConfigEntry, CiscoCoordinator
from .links import (
    async_get_linked_device,
    async_mac_known,
    async_tracker_entries,
    ip_sensor_unique_id,
    tracker_unique_id,
)

# The coordinator does all the polling.
PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CiscoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the router sensor and an IP address sensor per tracker."""
    coordinator = entry.runtime_data
    async_add_entities([CiscoConnectedClientsSensor(coordinator)])

    # Same rule as the trackers: every known tracker, plus every client that
    # becomes active for the first time.
    tracked = set(async_tracker_entries(hass, entry))
    async_add_entities(
        CiscoIPAddressSensor(coordinator, mac, tracked) for mac in tracked
    )

    @callback
    def _async_add_new_clients() -> None:
        """Add sensors for clients that became active for the first time."""
        new_macs = [mac for mac in coordinator.data.arp if mac not in tracked]
        if not new_macs:
            return
        tracked.update(new_macs)
        async_add_entities(
            CiscoIPAddressSensor(coordinator, mac, tracked) for mac in new_macs
        )

    _async_add_new_clients()
    entry.async_on_unload(coordinator.async_add_listener(_async_add_new_clients))


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


class CiscoIPAddressSensor(CoordinatorEntity[CiscoCoordinator], RestoreSensor):
    """The last known IP address of a client.

    The sensor sits on the same device as its tracker: the device you linked
    the tracker to, or the automatic device HA creates when another
    integration knows the MAC address. Otherwise it has no device.
    """

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self, coordinator: CiscoCoordinator, mac: str, tracked: set[str]
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._mac = mac
        self._tracked = tracked
        entry = coordinator.config_entry
        self._attr_unique_id = ip_sensor_unique_id(entry, mac)
        self.device_entry = async_get_linked_device(coordinator.hass, entry, mac)
        self._linked = self.device_entry is not None
        self._mac_known = async_mac_known(coordinator.hass, mac)
        if self._linked:
            self._attr_translation_key = "ip_address"
        elif self._mac_known:
            # The same device ScannerEntity registers for the tracker.
            self._attr_translation_key = "ip_address"
            self._attr_device_info = DeviceInfo(
                connections={(dr.CONNECTION_NETWORK_MAC, mac)}, name=mac
            )
        else:
            # Without a device, name the sensor after its tracker, so a name
            # you gave the tracker (or imported) shows here too.
            self._attr_translation_key = "client_ip_address"
            self._attr_translation_placeholders = {
                "client": self._tracker_name(coordinator.hass, entry, mac)
            }
        if (arp := coordinator.data.arp.get(mac)) is not None:
            self._attr_native_value = arp.ip

    @staticmethod
    def _tracker_name(hass: HomeAssistant, entry: CiscoConfigEntry, mac: str) -> str:
        """Return the name of the tracker of a MAC address."""
        entity_registry = er.async_get(hass)
        if (
            tracker_entity_id := entity_registry.async_get_entity_id(
                DEVICE_TRACKER_DOMAIN, DOMAIN, tracker_unique_id(entry, mac)
            )
        ) and (tracker := entity_registry.async_get(tracker_entity_id)):
            return tracker.name or tracker.original_name or mac
        return mac

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Enable the sensor when its tracker is enabled."""
        entity_registry = er.async_get(self.hass)
        if (
            tracker_entity_id := entity_registry.async_get_entity_id(
                DEVICE_TRACKER_DOMAIN,
                DOMAIN,
                tracker_unique_id(self.coordinator.config_entry, self._mac),
            )
        ) and (tracker := entity_registry.async_get(tracker_entity_id)):
            return tracker.disabled_by is None
        # The tracker is being added too; it follows the same rule.
        return self._linked or self._mac_known

    @callback
    def _handle_coordinator_update(self) -> None:
        """Keep the last known address while the client is away."""
        if (arp := self.coordinator.data.arp.get(self._mac)) is not None:
            self._attr_native_value = arp.ip
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """Restore the last known address after a restart."""
        await super().async_added_to_hass()
        if self._attr_native_value is None and (
            last_data := await self.async_get_last_sensor_data()
        ):
            self._attr_native_value = last_data.native_value

    async def async_removed_from_registry(self) -> None:
        """Forget the client so the sensor is added again when it is active."""
        self._tracked.discard(self._mac)

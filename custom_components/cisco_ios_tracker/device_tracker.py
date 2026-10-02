"""Device tracker platform for the Cisco IOS Tracker integration."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.device_tracker import (
    ATTR_IP,
    DOMAIN as DEVICE_TRACKER_DOMAIN,
    ScannerEntity,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.restore_state import ExtraStoredData, RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import ATTR_INTERFACE
from .coordinator import CiscoConfigEntry, CiscoCoordinator

# The coordinator does all the polling.
PARALLEL_UPDATES = 0

LAST_SEEN = "last_seen"


@dataclass(slots=True)
class CiscoTrackerExtraData(ExtraStoredData):
    """When the client was last seen, stored to restore it after a restart."""

    last_seen: datetime | None

    def as_dict(self) -> dict[str, Any]:
        """Return a dict representation of the extra data."""
        return {LAST_SEEN: self.last_seen.isoformat() if self.last_seen else None}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CiscoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up device trackers for the clients in the ARP table."""
    coordinator = entry.runtime_data
    tracked: set[str] = set()
    prefix = f"{coordinator.router_identifier}_"

    # Restore trackers seen before, so offline clients show as away after a
    # restart instead of disappearing.
    restored: list[CiscoScannerEntity] = []
    for registry_entry in er.async_entries_for_config_entry(
        er.async_get(hass), entry.entry_id
    ):
        if registry_entry.domain != DEVICE_TRACKER_DOMAIN:
            continue
        if not registry_entry.unique_id.startswith(prefix):
            continue
        mac = registry_entry.unique_id.rpartition("_")[2]
        tracked.add(mac)
        restored.append(CiscoScannerEntity(coordinator, mac, tracked))
    async_add_entities(restored)

    @callback
    def _async_add_new_clients() -> None:
        """Add trackers for clients that became active for the first time."""
        new_macs = [mac for mac in coordinator.data.arp if mac not in tracked]
        if not new_macs:
            return
        tracked.update(new_macs)
        async_add_entities(
            CiscoScannerEntity(coordinator, mac, tracked) for mac in new_macs
        )

    _async_add_new_clients()
    entry.async_on_unload(coordinator.async_add_listener(_async_add_new_clients))


class CiscoScannerEntity(
    CoordinatorEntity[CiscoCoordinator], ScannerEntity, RestoreEntity
):
    """A client seen in the ARP table of the router."""

    _attr_translation_key = "device_tracker"

    def __init__(
        self, coordinator: CiscoCoordinator, mac: str, tracked: set[str]
    ) -> None:
        """Initialize the tracker."""
        super().__init__(coordinator)
        self._mac = mac
        self._tracked = tracked
        self._attr_name = mac
        self._attr_mac_address = mac
        self._interface: str | None = None
        self._update_from_arp()

    @property
    def unique_id(self) -> str:
        """Return a unique ID that is unique across config entries."""
        return f"{self.coordinator.router_identifier}_{self._mac}"

    @property
    def is_connected(self) -> bool:
        """Return true if the client is considered home."""
        return self.coordinator.is_connected(self._mac)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the interface the client was last seen on."""
        # The last seen time changes on every poll while the client is home,
        # so it is stored as restore data instead of a state attribute.
        return {ATTR_INTERFACE: self._interface}

    @property
    def extra_restore_state_data(self) -> CiscoTrackerExtraData:
        """Return the time the client was last seen, to restore it later."""
        return CiscoTrackerExtraData(self.coordinator.last_seen.get(self._mac))

    @callback
    def _update_from_arp(self) -> None:
        """Remember the address and interface of the current ARP entry."""
        if (arp := self.coordinator.data.arp.get(self._mac)) is not None:
            self._attr_ip_address = arp.ip
            self._interface = arp.interface

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_from_arp()
        super()._handle_coordinator_update()

    async def async_added_to_hass(self) -> None:
        """Restore the last known state after a restart."""
        await super().async_added_to_hass()
        # A client that is active now has current data and needs no restore.
        if self._mac in self.coordinator.last_seen:
            return
        if (last_state := await self.async_get_last_state()) is None:
            return
        attributes = last_state.attributes
        self._attr_ip_address = attributes.get(ATTR_IP)
        self._interface = attributes.get(ATTR_INTERFACE)
        if (extra_data := await self.async_get_last_extra_data()) is None:
            return
        reachable = extra_data.as_dict().get(LAST_SEEN)
        if isinstance(reachable, str) and (
            last_seen := dt_util.parse_datetime(reachable)
        ):
            # Keep a client that was home before the restart home for the
            # rest of its consider home time.
            self.coordinator.last_seen.setdefault(self._mac, dt_util.as_utc(last_seen))

    async def async_removed_from_registry(self) -> None:
        """Forget the client so it is added again when it becomes active."""
        self._tracked.discard(self._mac)

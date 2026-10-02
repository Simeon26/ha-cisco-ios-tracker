"""Data update coordinator for the Cisco IOS Tracker integration."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from homeassistant.components.device_tracker import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr, issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .client import (
    ArpEntry,
    CiscoAuthenticationError,
    CiscoDeviceInfo,
    CiscoError,
    CiscoHostKeyMismatchError,
    CiscoIOSClient,
)
from .const import CONF_MAX_ARP_AGE, DEFAULT_MAX_ARP_AGE, DOMAIN, LOGGER, SCAN_INTERVAL


@dataclass(slots=True)
class CiscoData:
    """Data returned by one poll of the device."""

    device: CiscoDeviceInfo
    arp: dict[str, ArpEntry]
    """Active ARP entries keyed by MAC address (best entry per MAC)."""
    last_seen: dict[str, datetime]
    """When each MAC address was last active (kept across polls)."""


type CiscoConfigEntry = ConfigEntry[CiscoCoordinator]


class CiscoCoordinator(DataUpdateCoordinator[CiscoData]):
    """Poll the ARP table of a Cisco IOS device."""

    config_entry: CiscoConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: CiscoConfigEntry,
        client: CiscoIOSClient,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=SCAN_INTERVAL,
        )
        self.client = client
        self.consider_home = timedelta(
            seconds=config_entry.options.get(
                CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME.total_seconds()
            )
        )
        self.max_arp_age: int = config_entry.options.get(
            CONF_MAX_ARP_AGE, DEFAULT_MAX_ARP_AGE
        )
        self.last_seen: dict[str, datetime] = {}

    @property
    def router_identifier(self) -> str:
        """Return the identifier of the router device and entity prefix."""
        return self.config_entry.unique_id or self.config_entry.entry_id

    @property
    def host_key_issue_id(self) -> str:
        """Return the repair issue id used for host key mismatches."""
        return f"host_key_mismatch_{self.config_entry.entry_id}"

    @callback
    def is_connected(self, mac: str) -> bool:
        """Return whether a MAC address is considered home."""
        if (last_seen := self.last_seen.get(mac)) is None:
            return False
        return dt_util.utcnow() - last_seen < self.consider_home

    @callback
    def connected_macs(self) -> set[str]:
        """Return the MAC addresses currently considered home."""
        return {mac for mac in self.last_seen if self.is_connected(mac)}

    @callback
    def async_update_router_device(self, device: CiscoDeviceInfo) -> None:
        """Create or update the device registry entry for the router."""
        dr.async_get(self.hass).async_get_or_create(
            config_entry_id=self.config_entry.entry_id,
            identifiers={(DOMAIN, self.router_identifier)},
            connections=(
                {(dr.CONNECTION_NETWORK_MAC, device.base_mac)}
                if device.base_mac
                else set()
            ),
            manufacturer="Cisco",
            model=device.model,
            sw_version=device.sw_version,
            serial_number=device.serial,
            name=device.hostname or self.config_entry.data[CONF_HOST],
        )

    async def _async_update_data(self) -> CiscoData:
        """Fetch the ARP table and device information."""
        try:
            device, entries = await self.client.async_get_all()
        except CiscoAuthenticationError as err:
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN, translation_key="invalid_auth"
            ) from err
        except CiscoHostKeyMismatchError as err:
            self._async_create_host_key_issue(err)
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="host_key_mismatch",
                translation_placeholders={"host": self.config_entry.data[CONF_HOST]},
            ) from err
        except CiscoError as err:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
                translation_placeholders={"error": str(err)},
            ) from err

        ir.async_delete_issue(self.hass, DOMAIN, self.host_key_issue_id)

        active: dict[str, ArpEntry] = {}
        for entry in entries:
            # Entries without an age are the router's own interfaces or static
            # entries; they are never clients.
            if entry.age is None or entry.age > self.max_arp_age:
                continue
            best = active.get(entry.mac)
            if best is None or (best.age is not None and entry.age < best.age):
                active[entry.mac] = entry

        now = dt_util.utcnow()
        for mac in active:
            self.last_seen[mac] = now

        if self.data is not None and self.data.device != device:
            self.async_update_router_device(device)

        return CiscoData(device=device, arp=active, last_seen=self.last_seen)

    @callback
    def _async_create_host_key_issue(self, err: CiscoHostKeyMismatchError) -> None:
        """Create a repair issue telling the user the host key changed."""
        LOGGER.debug(
            "Host key mismatch: expected %s, presented %s",
            err.expected_fingerprint,
            err.presented_fingerprint,
        )
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            self.host_key_issue_id,
            is_fixable=False,
            is_persistent=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key="host_key_mismatch",
            translation_placeholders={
                "host": self.config_entry.data[CONF_HOST],
                "title": self.config_entry.title,
                "expected": err.expected_fingerprint,
                "presented": err.presented_fingerprint or "unknown",
            },
        )

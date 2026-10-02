"""Diagnostics support for the Cisco IOS Tracker integration."""

from dataclasses import asdict
from typing import Any

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.diagnostics import REDACTED, async_redact_data
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_UNIQUE_ID, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import (
    CONF_HOST_KEY,
    CONF_KEY_FILE,
    CONF_LEGACY_ALGORITHMS,
    CONF_PASSPHRASE,
    CONF_PRIVATE_KEY,
)
from .coordinator import CiscoConfigEntry

TO_REDACT = {
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_PRIVATE_KEY,
    CONF_KEY_FILE,
    CONF_PASSPHRASE,
    CONF_HOST_KEY,
    CONF_UNIQUE_ID,
    "title",
}
DEVICE_TO_REDACT = {"serial", "base_mac", "hostname"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: CiscoConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    data = coordinator.data
    host_key: str | None = entry.data.get(CONF_HOST_KEY)

    return {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        # Not the fingerprint: it identifies the device in internet scans.
        "host_key_pinned": host_key is not None,
        "host_key_type": host_key.split()[0] if host_key else None,
        "legacy_algorithms": entry.data.get(CONF_LEGACY_ALGORITHMS, False),
        "last_update_success": coordinator.last_update_success,
        "options": dict(entry.options),
        "device": async_redact_data(asdict(data.device), DEVICE_TO_REDACT),
        "counts": {
            "arp_active": len(data.arp),
            "tracked": sum(
                registry_entry.domain == DEVICE_TRACKER_DOMAIN
                for registry_entry in er.async_entries_for_config_entry(
                    er.async_get(hass), entry.entry_id
                )
            ),
            "home": len(coordinator.connected_macs()),
        },
        "active_entries": [
            {
                "mac": REDACTED,
                "ip": REDACTED,
                "interface": arp.interface,
                "age": arp.age,
            }
            for arp in data.arp.values()
        ],
    }

"""Manual links between trackers and devices of other integrations.

A link puts a tracker (and its IP address sensor) on a device chosen by the
user, for example a Chromecast that the Cast integration registered without a
MAC address. Links are stored in the config entry options as a mapping of
tracker MAC address to device registry id.
"""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.sensor import DOMAIN as SENSOR_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .const import CONF_DEVICE_LINKS, DOMAIN, IP_ADDRESS_SUFFIX


def entity_prefix(entry: ConfigEntry) -> str:
    """Return the unique ID prefix of the entities of a config entry."""
    return f"{entry.unique_id or entry.entry_id}_"


def tracker_unique_id(entry: ConfigEntry, mac: str) -> str:
    """Return the unique ID of the tracker for a MAC address."""
    return f"{entity_prefix(entry)}{mac}"


def ip_sensor_unique_id(entry: ConfigEntry, mac: str) -> str:
    """Return the unique ID of the IP address sensor for a MAC address."""
    return f"{entity_prefix(entry)}{mac}{IP_ADDRESS_SUFFIX}"


def device_owner(device: dr.DeviceEntry) -> str | None:
    """Return the config entry that owns a device.

    From HA 2026.8 a device belongs to exactly one config entry. Before that,
    devices were shared and the primary config entry is the owner.
    """
    if (config_entry_id := getattr(device, "config_entry_id", None)) is not None:
        return str(config_entry_id)
    return device.primary_config_entry


@callback
def async_mac_known(hass: HomeAssistant, mac: str) -> bool:
    """Return whether any device has the MAC address as a connection."""
    device_registry = dr.async_get(hass)
    connections = {(dr.CONNECTION_NETWORK_MAC, mac)}
    if hasattr(device_registry, "async_get_devices"):  # HA 2026.8 and later
        return bool(device_registry.async_get_devices(connections=connections))
    return device_registry.async_get_device(connections=connections) is not None


@callback
def _async_release_mac_device(
    hass: HomeAssistant, entry: ConfigEntry, mac: str
) -> None:
    """Remove the automatic device of a tracker once it has no entities.

    Shared devices (before HA 2026.8) are kept and only lose this entry.
    """
    device_registry = dr.async_get(hass)
    entity_registry = er.async_get(hass)
    for device in dr.async_entries_for_config_entry(device_registry, entry.entry_id):
        if (dr.CONNECTION_NETWORK_MAC, mac) not in device.connections:
            continue
        if any(
            registry_entry.config_entry_id == entry.entry_id
            for registry_entry in er.async_entries_for_device(
                entity_registry, device.id, include_disabled_entities=True
            )
        ):
            continue
        if getattr(device, "config_entry_id", None) is not None:
            device_registry.async_remove_device(device.id)
        else:
            device_registry.async_update_device(
                device.id, remove_config_entry_id=entry.entry_id
            )


def get_links(options: Mapping[str, Any]) -> dict[str, str]:
    """Return the manual links stored in the config entry options."""
    return dict(options.get(CONF_DEVICE_LINKS, {}))


@callback
def async_tracker_entries(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, er.RegistryEntry]:
    """Return the tracker registry entries of a config entry, keyed by MAC."""
    prefix = entity_prefix(entry)
    return {
        registry_entry.unique_id.removeprefix(prefix): registry_entry
        for registry_entry in er.async_entries_for_config_entry(
            er.async_get(hass), entry.entry_id
        )
        if registry_entry.domain == DEVICE_TRACKER_DOMAIN
        and registry_entry.unique_id.startswith(prefix)
    }


@callback
def async_get_linked_device(
    hass: HomeAssistant, entry: ConfigEntry, mac: str
) -> dr.DeviceEntry | None:
    """Return the device a tracker is linked to, if the device still exists."""
    if (device_id := get_links(entry.options).get(mac)) is None:
        return None
    device = dr.async_get(hass).async_get(device_id)
    return device if isinstance(device, dr.DeviceEntry) else None


@callback
def async_link_device(
    hass: HomeAssistant, entry: ConfigEntry, mac: str, device_id: str
) -> dict[str, Any]:
    """Link the tracker of a MAC address to a device.

    Returns the new config entry options; the caller stores them and reloads
    the entry. Raises ServiceValidationError if the link is not possible.
    """
    device_registry = dr.async_get(hass)
    device = device_registry.async_get(device_id)
    if not isinstance(device, dr.DeviceEntry):
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="device_not_found"
        )
    if device_owner(device) == entry.entry_id:
        # The router device and the automatic tracker devices of this entry.
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="own_device"
        )
    trackers = async_tracker_entries(hass, entry)
    if mac not in trackers:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="tracker_not_found"
        )

    entity_registry = er.async_get(hass)
    entities = [trackers[mac]]
    if (
        sensor_entity_id := entity_registry.async_get_entity_id(
            SENSOR_DOMAIN, DOMAIN, ip_sensor_unique_id(entry, mac)
        )
    ) and (sensor_entry := entity_registry.async_get(sensor_entity_id)):
        entities.append(sensor_entry)

    # Move the entities now, so the automatic device of the tracker (if any) is
    # left without entities and can be removed without removing them with it.
    for registry_entry in entities:
        entity_registry.async_update_entity(
            registry_entry.entity_id,
            device_id=device.id,
            # Linking a tracker means you want it, so enable it if it was
            # only disabled because its MAC address was unknown.
            disabled_by=(
                None
                if registry_entry.disabled_by is er.RegistryEntryDisabler.INTEGRATION
                else registry_entry.disabled_by
            ),
        )
    _async_release_mac_device(hass, entry, mac)

    links = get_links(entry.options)
    links[mac] = device.id
    return {**entry.options, CONF_DEVICE_LINKS: links}


@callback
def async_unlink_device(
    hass: HomeAssistant, entry: ConfigEntry, mac: str
) -> dict[str, Any]:
    """Remove the link of a tracker.

    Returns the new config entry options; the caller stores them and reloads
    the entry, after which the tracker gets its automatic device again.
    Raises ServiceValidationError if the tracker is not linked.
    """
    links = get_links(entry.options)
    if links.pop(mac, None) is None:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="not_linked"
        )
    return {**entry.options, CONF_DEVICE_LINKS: links}


@callback
def async_prune_links(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Forget links to devices that no longer exist."""
    links = get_links(entry.options)
    device_registry = dr.async_get(hass)
    kept = {
        mac: device_id
        for mac, device_id in links.items()
        if device_registry.async_get(device_id) is not None
    }
    if kept != links:
        hass.config_entries.async_update_entry(
            entry, options={**entry.options, CONF_DEVICE_LINKS: kept}
        )

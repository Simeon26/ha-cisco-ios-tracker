"""Service actions for the Cisco IOS Tracker integration."""

import voluptuous as vol

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv, entity_registry as er

from .const import ATTR_DEVICE_ID, DOMAIN, SERVICE_LINK_DEVICE, SERVICE_UNLINK_DEVICE
from .links import async_link_device, async_unlink_device, entity_prefix

LINK_DEVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_ENTITY_ID): cv.entity_id,
        vol.Required(ATTR_DEVICE_ID): cv.string,
    }
)
UNLINK_DEVICE_SCHEMA = vol.Schema({vol.Required(ATTR_ENTITY_ID): cv.entity_id})


@callback
def _async_get_tracker(hass: HomeAssistant, entity_id: str) -> tuple[ConfigEntry, str]:
    """Return the config entry and MAC address of a tracker entity."""
    registry_entry = er.async_get(hass).async_get(entity_id)
    if (
        registry_entry is None
        or registry_entry.platform != DOMAIN
        or registry_entry.domain != DEVICE_TRACKER_DOMAIN
        or registry_entry.config_entry_id is None
        or (
            entry := hass.config_entries.async_get_entry(registry_entry.config_entry_id)
        )
        is None
    ):
        raise ServiceValidationError(
            translation_domain=DOMAIN,
            translation_key="not_a_tracker",
            translation_placeholders={"entity_id": entity_id},
        )
    return entry, registry_entry.unique_id.removeprefix(entity_prefix(entry))


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the service actions."""

    @callback
    def _async_link_device(call: ServiceCall) -> None:
        """Link a tracker to a device."""
        entry, mac = _async_get_tracker(hass, call.data[ATTR_ENTITY_ID])
        options = async_link_device(hass, entry, mac, call.data[ATTR_DEVICE_ID])
        hass.config_entries.async_update_entry(entry, options=options)
        hass.config_entries.async_schedule_reload(entry.entry_id)

    @callback
    def _async_unlink_device(call: ServiceCall) -> None:
        """Remove the link of a tracker."""
        entry, mac = _async_get_tracker(hass, call.data[ATTR_ENTITY_ID])
        options = async_unlink_device(hass, entry, mac)
        hass.config_entries.async_update_entry(entry, options=options)
        hass.config_entries.async_schedule_reload(entry.entry_id)

    hass.services.async_register(
        DOMAIN, SERVICE_LINK_DEVICE, _async_link_device, schema=LINK_DEVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_UNLINK_DEVICE,
        _async_unlink_device,
        schema=UNLINK_DEVICE_SCHEMA,
    )

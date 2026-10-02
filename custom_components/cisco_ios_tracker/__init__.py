"""The Cisco IOS Tracker integration."""

import asyncssh

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.sensor import DOMAIN as SENSOR_DOMAIN
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.helpers.typing import ConfigType

from .client import (
    CiscoIOSClient,
    CiscoKeyError,
    CiscoKeyFileNotFoundError,
    load_private_key,
)
from .const import (
    AUTH_PASSWORD,
    CONF_AUTH_METHOD,
    CONF_HOST_KEY,
    CONF_KEY_FILE,
    CONF_LEGACY_ALGORITHMS,
    CONF_PASSPHRASE,
    CONF_PRIVATE_KEY,
    DEFAULT_PORT,
    DOMAIN,
)
from .coordinator import CiscoConfigEntry, CiscoCoordinator, host_key_issue_id
from .links import async_prune_links, entity_prefix, get_links, ip_sensor_unique_id
from .services import async_setup_services

PLATFORMS: list[Platform] = [Platform.DEVICE_TRACKER, Platform.SENSOR]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Cisco IOS Tracker service actions."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: CiscoConfigEntry) -> bool:
    """Set up Cisco IOS Tracker from a config entry."""
    client_key: asyncssh.SSHKey | None = None
    if entry.data[CONF_AUTH_METHOD] != AUTH_PASSWORD:
        try:
            client_key = await hass.async_add_executor_job(
                load_private_key,
                entry.data.get(CONF_PRIVATE_KEY),
                entry.data.get(CONF_KEY_FILE),
                entry.data.get(CONF_PASSPHRASE),
            )
        except CiscoKeyFileNotFoundError as err:
            # Reauthentication lets the user enter a new path or switch to
            # another login method.
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN,
                translation_key="key_file_not_found",
                translation_placeholders={
                    "key_file": entry.data.get(CONF_KEY_FILE, "")
                },
            ) from err
        except CiscoKeyError as err:
            # A wrong passphrase or an invalid key needs new credentials.
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN, translation_key="invalid_key"
            ) from err

    client = CiscoIOSClient(
        entry.data[CONF_HOST],
        entry.data.get(CONF_PORT, DEFAULT_PORT),
        entry.data[CONF_USERNAME],
        password=entry.data.get(CONF_PASSWORD),
        client_key=client_key,
        host_key=entry.data.get(CONF_HOST_KEY),
        legacy_algorithms=entry.data.get(CONF_LEGACY_ALGORITHMS, False),
    )
    coordinator = CiscoCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    coordinator.async_update_router_device(coordinator.data.device)

    entry.runtime_data = coordinator
    async_prune_links(hass, entry)
    entry.async_on_unload(
        hass.bus.async_listen(
            dr.EVENT_DEVICE_REGISTRY_UPDATED,
            callback(lambda event: _async_device_updated(hass, entry, event)),
        )
    )
    entry.async_on_unload(
        hass.bus.async_listen(
            er.EVENT_ENTITY_REGISTRY_UPDATED,
            callback(lambda event: _async_entity_updated(hass, entry, event)),
        )
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


@callback
def _async_device_updated(
    hass: HomeAssistant,
    entry: CiscoConfigEntry,
    event: Event[dr.EventDeviceRegistryUpdatedData],
) -> None:
    """Forget the link of a tracker when its linked device is deleted."""
    if event.data["action"] != "remove":
        return
    if event.data["device_id"] not in get_links(entry.options).values():
        return
    async_prune_links(hass, entry)
    # Reload so the tracker gets its automatic device again.
    hass.config_entries.async_schedule_reload(entry.entry_id)


@callback
def _async_entity_updated(
    hass: HomeAssistant,
    entry: CiscoConfigEntry,
    event: Event[er.EventEntityRegistryUpdatedData],
) -> None:
    """Enable or disable the IP address sensor together with its tracker."""
    if event.data["action"] != "update" or "disabled_by" not in event.data["changes"]:
        return
    entity_registry = er.async_get(hass)
    tracker = entity_registry.async_get(event.data["entity_id"])
    if (
        tracker is None
        or tracker.config_entry_id != entry.entry_id
        or tracker.domain != DEVICE_TRACKER_DOMAIN
    ):
        return
    mac = tracker.unique_id.removeprefix(entity_prefix(entry))
    sensor_entity_id = entity_registry.async_get_entity_id(
        SENSOR_DOMAIN, DOMAIN, ip_sensor_unique_id(entry, mac)
    )
    if (
        sensor_entity_id is None
        or (sensor := entity_registry.async_get(sensor_entity_id)) is None
    ):
        return
    if tracker.disabled_by is None:
        # Don't enable a sensor you disabled yourself.
        if sensor.disabled_by is er.RegistryEntryDisabler.INTEGRATION:
            entity_registry.async_update_entity(sensor.entity_id, disabled_by=None)
    elif sensor.disabled_by is None:
        entity_registry.async_update_entity(
            sensor.entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION
        )


async def async_unload_entry(hass: HomeAssistant, entry: CiscoConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        # The next poll creates the issue again if the key still differs.
        _async_delete_host_key_issue(hass, entry)
    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: CiscoConfigEntry) -> None:
    """Remove the repair issue of a deleted config entry."""
    _async_delete_host_key_issue(hass, entry)


@callback
def _async_delete_host_key_issue(hass: HomeAssistant, entry: CiscoConfigEntry) -> None:
    """Delete the host key mismatch repair issue of a config entry."""
    ir.async_delete_issue(hass, DOMAIN, host_key_issue_id(entry.entry_id))


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: CiscoConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Allow removing a client device unless it is currently home."""
    if any(domain == DOMAIN for domain, _ in device_entry.identifiers):
        # The router itself can only be removed with the config entry.
        return False
    if entry.state is not ConfigEntryState.LOADED:
        # Without a connection no client can be confirmed as home.
        return True
    coordinator = entry.runtime_data
    return not any(
        connection_type == dr.CONNECTION_NETWORK_MAC and coordinator.is_connected(mac)
        for connection_type, mac in device_entry.connections
    )

"""The Cisco IOS Tracker integration."""

import asyncssh

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryError
from homeassistant.helpers import device_registry as dr

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
from .coordinator import CiscoConfigEntry, CiscoCoordinator

PLATFORMS: list[Platform] = [Platform.DEVICE_TRACKER, Platform.SENSOR]


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
            raise ConfigEntryError(
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
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: CiscoConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: CiscoConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Allow removing a client device unless it is currently home."""
    if any(domain == DOMAIN for domain, _ in device_entry.identifiers):
        # The router itself can only be removed with the config entry.
        return False
    coordinator = entry.runtime_data
    return not any(
        connection_type == dr.CONNECTION_NETWORK_MAC and coordinator.is_connected(mac)
        for connection_type, mac in device_entry.connections
    )

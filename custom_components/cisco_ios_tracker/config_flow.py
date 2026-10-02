"""Config flow for the Cisco IOS Tracker integration."""

from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

import asyncssh
import voluptuous as vol

from homeassistant.components.device_tracker import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
)
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithReload,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PATH,
    CONF_PORT,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.selector import (
    DeviceSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .client import (
    CiscoAuthenticationError,
    CiscoCommandError,
    CiscoConnectionError,
    CiscoDeviceInfo,
    CiscoHostKeyMismatchError,
    CiscoIOSClient,
    CiscoKeyError,
    CiscoKeyExchangeError,
    CiscoKeyFileNotFoundError,
    CiscoPassphraseError,
    fingerprint,
    load_private_key,
)
from .const import (
    AUTH_KEY_FILE,
    AUTH_PASSWORD,
    AUTH_PRIVATE_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_LINKS,
    CONF_HOST_KEY,
    CONF_KEY_FILE,
    CONF_LEGACY_ALGORITHMS,
    CONF_MAX_ARP_AGE,
    CONF_PASSPHRASE,
    CONF_PRIVATE_KEY,
    DEFAULT_MAX_ARP_AGE,
    DEFAULT_PORT,
    DOMAIN,
    LOGGER,
    MAX_ARP_AGE_LIMIT,
    MAX_CONSIDER_HOME,
)
from .known_devices import (
    KNOWN_DEVICES_FILE,
    ImportPlan,
    KnownDevicesError,
    async_apply_import,
    async_plan_import,
    load_known_devices,
)
from .links import async_link_device, async_tracker_entries, get_links

AUTH_METHODS = [AUTH_PASSWORD, AUTH_PRIVATE_KEY, AUTH_KEY_FILE]
CONF_TRACKER = "tracker"
CONF_TRACKERS = "trackers"
CONF_DEVICE = "device"
# Keys that hold credentials; replaced as a whole when the credentials change.
AUTH_KEYS = (
    CONF_AUTH_METHOD,
    CONF_PASSWORD,
    CONF_PRIVATE_KEY,
    CONF_KEY_FILE,
    CONF_PASSPHRASE,
)
# Values that are never shown again when a form is re-displayed.
SECRET_KEYS = (CONF_PASSWORD, CONF_PASSPHRASE)

PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): TextSelector(),
        vol.Required(CONF_PORT, default=DEFAULT_PORT): vol.All(
            NumberSelector(
                NumberSelectorConfig(
                    min=1, max=65535, step=1, mode=NumberSelectorMode.BOX
                )
            ),
            vol.Coerce(int),
        ),
        vol.Required(CONF_USERNAME): TextSelector(),
    }
)
RECONFIGURE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): TextSelector(),
        vol.Required(CONF_PORT): vol.All(
            NumberSelector(
                NumberSelectorConfig(
                    min=1, max=65535, step=1, mode=NumberSelectorMode.BOX
                )
            ),
            vol.Coerce(int),
        ),
    }
)
AUTH_SCHEMAS: dict[str, dict[vol.Marker, Any]] = {
    AUTH_PASSWORD: {vol.Required(CONF_PASSWORD): PASSWORD_SELECTOR},
    AUTH_PRIVATE_KEY: {
        vol.Required(CONF_PRIVATE_KEY): TextSelector(
            TextSelectorConfig(multiline=True)
        ),
        vol.Optional(CONF_PASSPHRASE): PASSWORD_SELECTOR,
    },
    AUTH_KEY_FILE: {
        vol.Required(CONF_KEY_FILE): TextSelector(),
        vol.Optional(CONF_PASSPHRASE): PASSWORD_SELECTOR,
    },
}
OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(
            CONF_CONSIDER_HOME, default=int(DEFAULT_CONSIDER_HOME.total_seconds())
        ): NumberSelector(
            NumberSelectorConfig(
                min=0,
                max=MAX_CONSIDER_HOME,
                step=1,
                unit_of_measurement="s",
                mode=NumberSelectorMode.BOX,
            )
        ),
        vol.Required(CONF_MAX_ARP_AGE, default=DEFAULT_MAX_ARP_AGE): NumberSelector(
            NumberSelectorConfig(
                min=0,
                max=MAX_ARP_AGE_LIMIT,
                step=1,
                unit_of_measurement="min",
                mode=NumberSelectorMode.BOX,
            )
        ),
    }
)

type ValidationResult = tuple[CiscoDeviceInfo, str | None, bool]


class CiscoIOSTrackerConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cisco IOS Tracker."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._data: dict[str, Any] = {}
        # Reconfigure: the entry data with the new address, and the new host
        # key that the user has to confirm before Home Assistant logs in.
        self._reconfigure_data: dict[str, Any] = {}
        self._new_host_key = ""

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow handler."""
        return CiscoIOSTrackerOptionsFlow()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the address of the device and the username."""
        if user_input is not None:
            self._data = {
                CONF_HOST: user_input[CONF_HOST].strip(),
                CONF_PORT: user_input[CONF_PORT],
                CONF_USERNAME: user_input[CONF_USERNAME],
            }
            self._async_abort_entries_match(
                {CONF_HOST: self._data[CONF_HOST], CONF_PORT: self._data[CONF_PORT]}
            )
            return await self.async_step_auth()
        return self.async_show_form(step_id="user", data_schema=USER_SCHEMA)

    async def async_step_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose how to log in."""
        return self.async_show_menu(step_id="auth", menu_options=AUTH_METHODS)

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauthentication after the device rejected the credentials."""
        self._data = {
            CONF_HOST: entry_data[CONF_HOST],
            CONF_PORT: entry_data.get(CONF_PORT, DEFAULT_PORT),
            CONF_USERNAME: entry_data[CONF_USERNAME],
        }
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose how to log in again."""
        return self.async_show_menu(
            step_id="reauth_confirm",
            menu_options=AUTH_METHODS,
            description_placeholders={"host": self._data[CONF_HOST]},
        )

    async def async_step_password(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Log in with a password."""
        return await self._async_step_credentials(AUTH_PASSWORD, user_input)

    async def async_step_private_key(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Log in with a pasted private key."""
        return await self._async_step_credentials(AUTH_PRIVATE_KEY, user_input)

    async def async_step_key_file(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Log in with a private key file."""
        return await self._async_step_credentials(AUTH_KEY_FILE, user_input)

    async def _async_step_credentials(
        self, method: str, user_input: dict[str, Any] | None
    ) -> ConfigFlowResult:
        """Validate the credentials for one of the login methods."""
        reauth = self.source == SOURCE_REAUTH
        fields: dict[vol.Marker, Any] = {}
        if reauth:
            # Reauthentication may also be caused by a changed username.
            fields[vol.Required(CONF_USERNAME)] = TextSelector()
        fields.update(AUTH_SCHEMAS[method])
        schema = vol.Schema(fields)
        errors: dict[str, str] = {}
        suggested: dict[str, Any] = {CONF_USERNAME: self._data[CONF_USERNAME]}

        if user_input is not None:
            if reauth:
                self._data[CONF_USERNAME] = user_input[CONF_USERNAME]
            auth = self._auth_data(method, user_input)
            data = {**self._data, **auth}
            if reauth:
                entry = self._get_reauth_entry()
                result = await self._async_try_validate(
                    data,
                    errors,
                    host_key=entry.data.get(CONF_HOST_KEY),
                    legacy=entry.data.get(CONF_LEGACY_ALGORITHMS, False),
                )
            else:
                result = await self._async_try_validate(data, errors)
            if result is not None:
                device, host_key, legacy = result
                if reauth:
                    return await self._async_finish_reauth(
                        data, device, host_key, legacy
                    )
                return await self._async_finish_user(data, device, host_key, legacy)
            suggested = {
                key: value
                for key, value in user_input.items()
                if key not in SECRET_KEYS
            }

        return self.async_show_form(
            step_id=method,
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
            description_placeholders={"host": self._data[CONF_HOST]},
        )

    def _auth_data(self, method: str, user_input: dict[str, Any]) -> dict[str, Any]:
        """Return the entry data for the chosen login method."""
        data: dict[str, Any] = {CONF_AUTH_METHOD: method}
        if method == AUTH_PASSWORD:
            data[CONF_PASSWORD] = user_input[CONF_PASSWORD]
            return data
        if method == AUTH_PRIVATE_KEY:
            data[CONF_PRIVATE_KEY] = user_input[CONF_PRIVATE_KEY]
        else:
            key_file = Path(user_input[CONF_KEY_FILE].strip())
            if not key_file.is_absolute():
                key_file = Path(self.hass.config.path(str(key_file)))
            data[CONF_KEY_FILE] = str(key_file)
        if passphrase := user_input.get(CONF_PASSPHRASE):
            data[CONF_PASSPHRASE] = passphrase
        return data

    async def _async_create_client(
        self, data: Mapping[str, Any], host_key: str | None, legacy: bool
    ) -> CiscoIOSClient:
        """Load the private key, if any, and return a client for the device."""
        client_key: asyncssh.SSHKey | None = None
        if data[CONF_AUTH_METHOD] != AUTH_PASSWORD:
            client_key = await self.hass.async_add_executor_job(
                load_private_key,
                data.get(CONF_PRIVATE_KEY),
                data.get(CONF_KEY_FILE),
                data.get(CONF_PASSPHRASE),
            )
        return CiscoIOSClient(
            data[CONF_HOST],
            data[CONF_PORT],
            data[CONF_USERNAME],
            password=data.get(CONF_PASSWORD),
            client_key=client_key,
            host_key=host_key,
            legacy_algorithms=legacy,
        )

    async def _async_validate(
        self, data: Mapping[str, Any], host_key: str | None, legacy: bool
    ) -> ValidationResult:
        """Connect to the device and return its details, host key and legacy flag."""
        client = await self._async_create_client(data, host_key, legacy)
        device, _ = await client.async_probe()
        return device, client.presented_host_key or host_key, client.legacy_algorithms

    async def _async_try_validate(
        self,
        data: Mapping[str, Any],
        errors: dict[str, str],
        *,
        host_key: str | None = None,
        legacy: bool = False,
        field_errors: bool = True,
    ) -> ValidationResult | None:
        """Validate the connection and fill in errors on failure."""
        return await self._async_try(
            lambda: self._async_validate(data, host_key, legacy),
            errors,
            field_errors=field_errors,
        )

    async def _async_try[T](
        self,
        func: Callable[[], Awaitable[T]],
        errors: dict[str, str],
        *,
        field_errors: bool = True,
    ) -> T | None:
        """Run a connection check and fill in errors on failure.

        Errors about the key file or the passphrase are shown on that field
        when `field_errors` is set, otherwise as a general error.
        """
        field = "base"
        try:
            return await func()
        except CiscoKeyFileNotFoundError:
            field, error = CONF_KEY_FILE, "key_file_not_found"
        except CiscoPassphraseError:
            field, error = CONF_PASSPHRASE, "invalid_passphrase"
        except CiscoKeyError:
            error = "invalid_key"
        except CiscoHostKeyMismatchError:
            error = "host_key_mismatch"
        except CiscoAuthenticationError:
            error = "invalid_auth"
        except CiscoKeyExchangeError:
            error = "no_common_algorithms"
        except CiscoCommandError:
            error = "command_failed"
        except CiscoConnectionError:
            error = "cannot_connect"
        except Exception:  # noqa: BLE001
            LOGGER.exception("Unexpected exception while connecting")
            error = "unknown"
        errors[field if field_errors else "base"] = error
        return None

    async def _async_finish_user(
        self,
        data: dict[str, Any],
        device: CiscoDeviceInfo,
        host_key: str | None,
        legacy: bool,
    ) -> ConfigFlowResult:
        """Create the config entry."""
        if device.serial:
            await self.async_set_unique_id(device.serial.upper())
            self._abort_if_unique_id_configured(
                updates={CONF_HOST: data[CONF_HOST], CONF_PORT: data[CONF_PORT]}
            )
        return self.async_create_entry(
            title=device.hostname or data[CONF_HOST],
            data={
                **data,
                CONF_HOST_KEY: host_key,
                CONF_LEGACY_ALGORITHMS: legacy,
            },
            options={
                CONF_CONSIDER_HOME: int(DEFAULT_CONSIDER_HOME.total_seconds()),
                CONF_MAX_ARP_AGE: DEFAULT_MAX_ARP_AGE,
            },
        )

    async def _async_abort_if_wrong_device(
        self, entry: ConfigEntry, device: CiscoDeviceInfo
    ) -> None:
        """Abort when the device is not the one of the config entry."""
        if entry.unique_id is not None and device.serial:
            await self.async_set_unique_id(device.serial.upper())
            self._abort_if_unique_id_mismatch(reason="wrong_device")

    async def _async_finish_reauth(
        self,
        data: dict[str, Any],
        device: CiscoDeviceInfo,
        host_key: str | None,
        legacy: bool,
    ) -> ConfigFlowResult:
        """Replace the credentials of the config entry."""
        entry = self._get_reauth_entry()
        await self._async_abort_if_wrong_device(entry, device)
        new_data = {
            key: value for key, value in entry.data.items() if key not in AUTH_KEYS
        }
        new_data.update(data)
        new_data[CONF_HOST_KEY] = host_key
        new_data[CONF_LEGACY_ALGORITHMS] = legacy
        return self.async_update_reload_and_abort(entry, data=new_data)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change the address of the device.

        The host key is checked before any credentials are sent: either the
        device proves it has the stored key, or the user must confirm the new
        key first.
        """
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        suggested: Mapping[str, Any] = entry.data

        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            port = user_input[CONF_PORT]
            self._async_abort_entries_match({CONF_HOST: host, CONF_PORT: port})
            data = {**entry.data, CONF_HOST: host, CONF_PORT: port}
            stored_key: str | None = entry.data.get(CONF_HOST_KEY)
            result = await self._async_try(
                lambda: self._async_check_host_key(data, stored_key),
                errors,
                field_errors=False,
            )
            if result is not None:
                device, host_key, legacy = result
                self._reconfigure_data = data
                if device is None:
                    # The key changed and nothing was sent to the device yet.
                    self._new_host_key = host_key
                    return await self.async_step_reconfigure_confirm_host_key()
                return await self._async_finish_reconfigure(device, host_key, legacy)
            suggested = user_input

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                RECONFIGURE_SCHEMA, suggested
            ),
            errors=errors,
        )

    async def _async_check_host_key(
        self, data: Mapping[str, Any], stored_key: str | None
    ) -> tuple[CiscoDeviceInfo | None, str, bool]:
        """Connect with the stored host key pinned, or fetch the new host key.

        Returns the device details if the device has the stored key. If the
        key changed, returns None instead, and the new key: the device then
        failed the host key check before any credentials were sent.
        Legacy algorithms are detected again in both cases.
        """
        client = await self._async_create_client(data, stored_key, False)
        if stored_key is None:
            return None, await client.async_fetch_host_key(), client.legacy_algorithms
        try:
            device, _ = await client.async_probe()
        except CiscoHostKeyMismatchError:
            if (presented := client.presented_host_key) is None:
                raise
            return None, presented, client.legacy_algorithms
        return device, stored_key, client.legacy_algorithms

    async def async_step_reconfigure_confirm_host_key(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask the user to confirm a changed host key, then log in."""
        errors: dict[str, str] = {}
        if user_input is not None:
            # Log in with the confirmed key pinned, so the credentials only
            # reach a device that has that key.
            result = await self._async_try_validate(
                self._reconfigure_data,
                errors,
                host_key=self._new_host_key,
                field_errors=False,
            )
            if result is not None:
                return await self._async_finish_reconfigure(*result)
        old_host_key: str | None = self._get_reconfigure_entry().data.get(CONF_HOST_KEY)
        return self.async_show_form(
            step_id="reconfigure_confirm_host_key",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={
                "host": self._reconfigure_data[CONF_HOST],
                "old_fingerprint": (
                    fingerprint(old_host_key) if old_host_key else "none"
                ),
                "new_fingerprint": fingerprint(self._new_host_key),
            },
        )

    async def _async_finish_reconfigure(
        self, device: CiscoDeviceInfo, host_key: str | None, legacy: bool
    ) -> ConfigFlowResult:
        """Check the device and store the new address and host key."""
        entry = self._get_reconfigure_entry()
        await self._async_abort_if_wrong_device(entry, device)
        return self.async_update_reload_and_abort(
            entry,
            data_updates={
                CONF_HOST: self._reconfigure_data[CONF_HOST],
                CONF_PORT: self._reconfigure_data[CONF_PORT],
                CONF_HOST_KEY: host_key,
                CONF_LEGACY_ALGORITHMS: legacy,
            },
        )


class CiscoIOSTrackerOptionsFlow(OptionsFlowWithReload):
    """Handle the options for Cisco IOS Tracker."""

    _import_plan: ImportPlan

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the options menu."""
        menu_options = ["settings", "link_device"]
        if get_links(self.config_entry.options):
            menu_options.append("unlink_device")
        menu_options.append("import_known_devices")
        return self.async_show_menu(step_id="init", menu_options=menu_options)

    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change how clients are detected."""
        if user_input is not None:
            return self.async_create_entry(
                data={
                    **self.config_entry.options,
                    CONF_CONSIDER_HOME: int(user_input[CONF_CONSIDER_HOME]),
                    CONF_MAX_ARP_AGE: int(user_input[CONF_MAX_ARP_AGE]),
                }
            )
        return self.async_show_form(
            step_id="settings",
            data_schema=self.add_suggested_values_to_schema(
                OPTIONS_SCHEMA, self.config_entry.options
            ),
        )

    async def async_step_link_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Link a tracker to a device of another integration."""
        trackers = async_tracker_entries(self.hass, self.config_entry)
        if not trackers:
            return self.async_abort(reason="no_trackers")
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                options = async_link_device(
                    self.hass,
                    self.config_entry,
                    user_input[CONF_TRACKER],
                    user_input[CONF_DEVICE],
                )
            except ServiceValidationError as err:
                errors["base"] = err.translation_key or "unknown"
            else:
                return self.async_create_entry(data=options)

        tracker_options = [
            SelectOptionDict(value=mac, label=_tracker_label(registry_entry))
            for mac, registry_entry in sorted(
                trackers.items(), key=lambda item: _tracker_label(item[1]).lower()
            )
        ]
        schema = vol.Schema(
            {
                vol.Required(CONF_TRACKER): SelectSelector(
                    SelectSelectorConfig(
                        options=tracker_options, mode=SelectSelectorMode.DROPDOWN
                    )
                ),
                vol.Required(CONF_DEVICE): DeviceSelector(),
            }
        )
        return self.async_show_form(
            step_id="link_device",
            data_schema=self.add_suggested_values_to_schema(schema, user_input or {}),
            errors=errors,
        )

    async def async_step_unlink_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Remove links between trackers and devices."""
        links = get_links(self.config_entry.options)
        if user_input is not None:
            remaining = {
                mac: device_id
                for mac, device_id in links.items()
                if mac not in user_input[CONF_TRACKERS]
            }
            return self.async_create_entry(
                data={**self.config_entry.options, CONF_DEVICE_LINKS: remaining}
            )

        trackers = async_tracker_entries(self.hass, self.config_entry)
        device_registry = dr.async_get(self.hass)
        link_options = []
        for mac, device_id in links.items():
            tracker = _tracker_label(trackers[mac]) if mac in trackers else mac
            device = device_registry.async_get(device_id)
            device_name = (
                (device.name_by_user or device.name or device_id)
                if device
                else device_id
            )
            link_options.append(
                SelectOptionDict(value=mac, label=f"{tracker} → {device_name}")
            )
        schema = vol.Schema(
            {
                vol.Required(CONF_TRACKERS): SelectSelector(
                    SelectSelectorConfig(
                        options=link_options,
                        multiple=True,
                        mode=SelectSelectorMode.LIST,
                    )
                ),
            }
        )
        return self.async_show_form(step_id="unlink_device", data_schema=schema)

    async def async_step_import_known_devices(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Read known_devices.yaml from a legacy device tracker."""
        errors: dict[str, str] = {}
        if user_input is not None:
            # Relative paths are relative to the configuration directory.
            path = Path(self.hass.config.path(user_input[CONF_PATH].strip()))
            try:
                known = await self.hass.async_add_executor_job(
                    load_known_devices, path, Path(self.hass.config.config_dir)
                )
            except KnownDevicesError as err:
                errors["base"] = err.translation_key
            else:
                self._import_plan = async_plan_import(
                    self.hass, self.config_entry, known
                )
                return await self.async_step_import_known_devices_confirm()

        schema = vol.Schema({vol.Required(CONF_PATH): TextSelector()})
        return self.async_show_form(
            step_id="import_known_devices",
            data_schema=self.add_suggested_values_to_schema(
                schema, user_input or {CONF_PATH: KNOWN_DEVICES_FILE}
            ),
            errors=errors,
        )

    async def async_step_import_known_devices_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show what the import changes, and import when confirmed."""
        plan = self._import_plan
        if user_input is not None:
            async_apply_import(self.hass, self.config_entry, plan)
            # Reload so the new trackers and sensors are added.
            self.hass.config_entries.async_schedule_reload(self.config_entry.entry_id)
            return self.async_abort(
                reason="import_successful",
                description_placeholders={"count": str(len(plan.known.devices))},
            )
        return self.async_show_form(
            step_id="import_known_devices_confirm",
            data_schema=vol.Schema({}),
            description_placeholders={
                "devices": str(len(plan.known.devices)),
                "new": str(plan.new),
                "existing": str(plan.existing),
                "skipped": str(plan.known.skipped),
                "unavailable": (
                    ", ".join(f"`{entity_id}`" for entity_id in plan.unavailable)
                    or "none"
                ),
            },
        )


def _tracker_label(registry_entry: er.RegistryEntry) -> str:
    """Return a label for a tracker in a selector."""
    name = registry_entry.name or registry_entry.original_name
    return f"{name} ({registry_entry.entity_id})"

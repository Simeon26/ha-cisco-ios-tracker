"""Import trackers from the known_devices.yaml file of legacy device trackers.

The core cisco_ios integration (and every other legacy tracker) kept its
devices in known_devices.yaml. Importing that file creates a tracker for each
device with a MAC address and carries over its entity ID, name, icon and
whether it was tracked, so automations that use the old entity IDs keep
working.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

import voluptuous as vol

from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.sensor import DOMAIN as SENSOR_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback, valid_entity_id
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import (
    config_validation as cv,
    device_registry as dr,
    entity_registry as er,
)
from homeassistant.util import slugify
from homeassistant.util.yaml import Secrets, load_yaml_dict

from .const import DOMAIN
from .links import async_tracker_entries, ip_sensor_unique_id, tracker_unique_id

KNOWN_DEVICES_FILE = "known_devices.yaml"

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass(frozen=True, slots=True)
class KnownDevice:
    """A device from known_devices.yaml that has a MAC address."""

    dev_id: str
    """The key of the device, which was its entity ID without the domain."""
    mac: str
    name: str | None
    icon: str | None
    track: bool

    @property
    def tracker_entity_id(self) -> str:
        """Return the entity ID the legacy tracker had."""
        return f"{DEVICE_TRACKER_DOMAIN}.{self.dev_id}"

    @property
    def sensor_entity_id(self) -> str:
        """Return the entity ID for the IP address sensor."""
        return f"{SENSOR_DOMAIN}.{self.dev_id}_ip_address"


@dataclass(slots=True)
class KnownDevices:
    """The devices read from known_devices.yaml."""

    devices: list[KnownDevice] = field(default_factory=list)
    skipped: int = 0
    """Entries without a valid MAC address, or with a duplicate one."""


class KnownDevicesError(Exception):
    """known_devices.yaml could not be imported."""

    def __init__(self, translation_key: str) -> None:
        """Initialize the error with the key of its translated message."""
        super().__init__(translation_key)
        self.translation_key = translation_key


def load_known_devices(path: Path, config_dir: Path) -> KnownDevices:
    """Read the devices with a MAC address from known_devices.yaml.

    This reads a file, so run it in an executor.
    """
    try:
        data = load_yaml_dict(path, Secrets(config_dir))
    except FileNotFoundError as err:
        raise KnownDevicesError("file_not_found") from err
    except (HomeAssistantError, OSError, ValueError) as err:
        # Invalid YAML, a top level that isn't a mapping, a directory, or a
        # file that can't be read or decoded.
        raise KnownDevicesError("invalid_file") from err

    result = KnownDevices()
    seen: set[str] = set()
    for key, config in data.items():
        device = _parse_device(key, config)
        if device is None or device.mac in seen:
            result.skipped += 1
            continue
        seen.add(device.mac)
        result.devices.append(device)
    if not result.devices:
        raise KnownDevicesError("no_devices")
    return result


def _parse_device(key: Any, config: Any) -> KnownDevice | None:
    """Return the device of one known_devices.yaml entry, if it has a MAC."""
    if not isinstance(config, dict) or not isinstance(mac := config.get("mac"), str):
        return None
    mac = dr.format_mac(mac.strip())
    dev_id = slugify(str(key))
    if not _MAC_RE.match(mac) or not valid_entity_id(
        f"{DEVICE_TRACKER_DOMAIN}.{dev_id}"
    ):
        return None
    name = config.get("name")
    name = str(name).strip() if name is not None else ""
    if name == str(key):
        # Legacy trackers named new devices after their key; that is not a
        # name you chose.
        name = ""
    icon = config.get("icon")
    try:
        icon = cv.icon(icon) if icon else None
    except vol.Invalid:
        icon = None
    try:
        track = cv.boolean(config.get("track", False))
    except vol.Invalid:
        track = False
    return KnownDevice(
        dev_id=dev_id,
        mac=mac,
        name=name or None,
        icon=icon,
        track=track,
    )


@dataclass(slots=True)
class ImportPlan:
    """What an import will change."""

    known: KnownDevices
    new: int = 0
    """Devices that get a new tracker."""
    existing: int = 0
    """Devices whose tracker already exists and is updated."""
    unavailable: list[str] = field(default_factory=list)
    """Entity IDs from the file that another entity uses."""


@callback
def async_plan_import(
    hass: HomeAssistant, entry: ConfigEntry, known: KnownDevices
) -> ImportPlan:
    """Work out what importing the devices would change."""
    entity_registry = er.async_get(hass)
    trackers = async_tracker_entries(hass, entry)
    plan = ImportPlan(known=known)
    for device in known.devices:
        tracker = trackers.get(device.mac)
        if tracker is None:
            plan.new += 1
        else:
            plan.existing += 1
        if not _async_entity_id_available(
            hass, entity_registry, device.tracker_entity_id, tracker
        ):
            plan.unavailable.append(device.tracker_entity_id)
    return plan


@callback
def async_apply_import(
    hass: HomeAssistant, entry: ConfigEntry, plan: ImportPlan
) -> None:
    """Create and update the trackers for the imported devices.

    Names and icons you already set in Home Assistant are kept. The caller
    reloads the config entry afterwards, so new trackers are added.
    """
    entity_registry = er.async_get(hass)
    trackers = async_tracker_entries(hass, entry)
    for device in plan.known.devices:
        tracker = trackers.get(device.mac)
        if tracker is None:
            tracker = entity_registry.async_get_or_create(
                DEVICE_TRACKER_DOMAIN,
                DOMAIN,
                tracker_unique_id(entry, device.mac),
                config_entry=entry,
                suggested_object_id=(
                    device.dev_id
                    if _async_entity_id_available(
                        hass, entity_registry, device.tracker_entity_id, None
                    )
                    else slugify(device.mac)
                ),
                disabled_by=(None if device.track else er.RegistryEntryDisabler.USER),
            )
            changes: dict[str, Any] = {}
        else:
            changes = _tracker_changes(device, tracker)
        # A tracker that was deleted before comes back with its old entity
        # ID, so rename new trackers too.
        if tracker.entity_id != device.tracker_entity_id and (
            _async_entity_id_available(
                hass, entity_registry, device.tracker_entity_id, None
            )
        ):
            changes["new_entity_id"] = device.tracker_entity_id
        if tracker.name is None and device.name:
            changes["name"] = device.name
        if tracker.icon is None and device.icon:
            changes["icon"] = device.icon
        if changes:
            tracker = entity_registry.async_update_entity(tracker.entity_id, **changes)
        _async_import_sensor(hass, entity_registry, entry, device, tracker)


def _tracker_changes(device: KnownDevice, tracker: er.RegistryEntry) -> dict[str, Any]:
    """Return the enabled state changes for an existing tracker."""
    if device.track and tracker.disabled_by is er.RegistryEntryDisabler.INTEGRATION:
        return {"disabled_by": None}
    if not device.track and tracker.disabled_by is None:
        return {"disabled_by": er.RegistryEntryDisabler.USER}
    return {}


@callback
def _async_import_sensor(
    hass: HomeAssistant,
    entity_registry: er.EntityRegistry,
    entry: ConfigEntry,
    device: KnownDevice,
    tracker: er.RegistryEntry,
) -> None:
    """Give the IP address sensor an entity ID that matches the tracker."""
    unique_id = ip_sensor_unique_id(entry, device.mac)
    sensor_entity_id = entity_registry.async_get_entity_id(
        SENSOR_DOMAIN, DOMAIN, unique_id
    )
    sensor = entity_registry.async_get(sensor_entity_id) if sensor_entity_id else None
    if sensor is None:
        # Created now so the sensor platform adds it on the next reload.
        sensor = entity_registry.async_get_or_create(
            SENSOR_DOMAIN,
            DOMAIN,
            unique_id,
            config_entry=entry,
            suggested_object_id=f"{device.dev_id}_ip_address",
            disabled_by=(
                None
                if tracker.disabled_by is None
                else er.RegistryEntryDisabler.INTEGRATION
            ),
        )
    changes: dict[str, Any] = {}
    if sensor.entity_id != device.sensor_entity_id and (
        _async_entity_id_available(hass, entity_registry, device.sensor_entity_id, None)
    ):
        changes["new_entity_id"] = device.sensor_entity_id
    # Follow the tracker, like the integration does when you enable or
    # disable a tracker; a restored sensor keeps its old disabled state.
    if tracker.disabled_by is None:
        if sensor.disabled_by is er.RegistryEntryDisabler.INTEGRATION:
            changes["disabled_by"] = None
    elif sensor.disabled_by is None:
        changes["disabled_by"] = er.RegistryEntryDisabler.INTEGRATION
    if changes:
        entity_registry.async_update_entity(sensor.entity_id, **changes)


@callback
def _async_entity_id_available(
    hass: HomeAssistant,
    entity_registry: er.EntityRegistry,
    entity_id: str,
    current: er.RegistryEntry | None,
) -> bool:
    """Return whether an entity can take an entity ID.

    True if the entity already has it, or if no other entity (registered or
    only in the state machine, like a legacy tracker) uses it.
    """
    if current is not None and current.entity_id == entity_id:
        return True
    return (
        entity_id not in entity_registry.entities and hass.states.get(entity_id) is None
    )

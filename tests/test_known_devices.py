"""Tests for importing known_devices.yaml."""

from pathlib import Path
import shutil

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cisco_ios_tracker.const import DOMAIN
from custom_components.cisco_ios_tracker.known_devices import (
    KnownDevice,
    KnownDevices,
    KnownDevicesError,
    async_apply_import,
    async_plan_import,
    load_known_devices,
)
from homeassistant.const import CONF_PATH, STATE_NOT_HOME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry as er

from .conftest import MAC_1, MAC_2, SERIAL

FIXTURE = Path(__file__).parent / "fixtures" / "known_devices.yaml"
MAC_PRINTER = "94:dd:f8:00:00:01"
MAC_TAKEN = "94:dd:f8:00:00:02"
MAC_BAD_ICON = "94:dd:f8:00:00:03"


def test_load_known_devices() -> None:
    """Test reading the devices with a MAC address."""
    known = load_known_devices(FIXTURE, FIXTURE.parent)
    # No MAC, a duplicate MAC, an invalid MAC and an entry that isn't a mapping.
    assert known.skipped == 4
    devices = {device.dev_id: device for device in known.devices}
    assert list(devices) == [
        "laptop",
        "00_1d_ec_02_07_ac",
        "printer",
        "taken",
        "bad_icon",
    ]
    laptop = devices["laptop"]
    assert laptop.mac == MAC_1
    assert laptop.name == "Office laptop"
    assert laptop.icon == "mdi:laptop"
    assert laptop.track is True
    assert laptop.tracker_entity_id == "device_tracker.laptop"
    assert laptop.sensor_entity_id == "sensor.laptop_ip_address"
    # A name that only repeats the key is not a real name.
    assert devices["00_1d_ec_02_07_ac"].name is None
    assert devices["00_1d_ec_02_07_ac"].track is False
    # Lowercase MAC addresses and "yes" work.
    assert devices["printer"].mac == MAC_PRINTER
    assert devices["printer"].track is True
    # Invalid icons and track values are ignored.
    assert devices["bad_icon"].icon is None
    assert devices["bad_icon"].track is False


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (None, "file_not_found"),
        ("laptop: [unclosed", "invalid_file"),
        ("- a list\n- not a mapping\n", "invalid_file"),
        ("phone:\n  name: GPS only\n", "no_devices"),
        ("", "no_devices"),
    ],
)
def test_load_known_devices_errors(
    tmp_path: Path, content: str | None, error: str
) -> None:
    """Test files that can't be imported."""
    path = tmp_path / "known_devices.yaml"
    if content is not None:
        path.write_text(content)
    with pytest.raises(KnownDevicesError) as exc_info:
        load_known_devices(path, tmp_path)
    assert exc_info.value.translation_key == error


def test_load_known_devices_directory(tmp_path: Path) -> None:
    """Test a path that is a directory."""
    with pytest.raises(KnownDevicesError) as exc_info:
        load_known_devices(tmp_path, tmp_path)
    assert exc_info.value.translation_key == "invalid_file"


def _suggested_path(result: dict) -> str:
    """Return the path suggested in the import form."""
    (key,) = result["data_schema"].schema
    assert key == CONF_PATH
    return key.description["suggested_value"]


async def _start_import(hass: HomeAssistant, entry: MockConfigEntry, path: str) -> dict:
    """Open the import step and submit a path."""
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert "import_known_devices" in result["menu_options"]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "import_known_devices"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "import_known_devices"
    return await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_PATH: path}
    )


async def test_import(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    tmp_path: Path,
) -> None:
    """Test importing known_devices.yaml from the options."""
    # A legacy tracker still owns this entity ID.
    hass.states.async_set("device_tracker.taken", "home")
    # A tracker that already exists with a name you set keeps the name.
    entity_registry.async_update_entity(
        "device_tracker.00_1d_ec_02_07_ac", name="My tablet"
    )
    hass.config.config_dir = str(tmp_path)
    shutil.copy(FIXTURE, tmp_path / "known_devices.yaml")

    result = await _start_import(hass, init_integration, "known_devices.yaml")
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "import_known_devices_confirm"
    assert result["description_placeholders"] == {
        "devices": "5",
        "new": "3",
        "existing": "2",
        "skipped": "4",
        "unavailable": "`device_tracker.taken`",
    }

    result = await hass.config_entries.options.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "import_successful"
    assert result["description_placeholders"] == {"count": "5"}
    await hass.async_block_till_done()

    # The existing, active tracker takes the old entity ID, name and icon,
    # and is enabled because the file says track: true.
    laptop = entity_registry.async_get("device_tracker.laptop")
    assert laptop.unique_id == f"{SERIAL}_{MAC_1}"
    assert laptop.name == "Office laptop"
    assert laptop.icon == "mdi:laptop"
    assert laptop.disabled_by is None
    assert hass.states.get("device_tracker.laptop").state == "home"
    assert hass.states.get("sensor.laptop_ip_address").state == "10.1.10.20"

    # track: false keeps it disabled, and your own name is kept.
    tablet = entity_registry.async_get("device_tracker.00_1d_ec_02_07_ac")
    assert tablet.unique_id == f"{SERIAL}_{MAC_2}"
    assert tablet.name == "My tablet"
    assert tablet.disabled_by is er.RegistryEntryDisabler.INTEGRATION

    # A device the router hasn't seen yet gets a tracker that is away.
    printer = entity_registry.async_get("device_tracker.printer")
    assert printer.unique_id == f"{SERIAL}_{MAC_PRINTER}"
    assert printer.disabled_by is None
    assert hass.states.get("device_tracker.printer").state == STATE_NOT_HOME
    sensor = hass.states.get("sensor.printer_ip_address")
    assert sensor.state == "unknown"
    assert sensor.attributes["friendly_name"] == "Study printer IP address"

    # The old entity ID is in use, so the MAC address is used instead.
    taken = entity_registry.async_get("device_tracker.94_dd_f8_00_00_02")
    assert taken.unique_id == f"{SERIAL}_{MAC_TAKEN}"
    assert taken.name == "Old entity"

    # track: false on a new device creates it disabled, with its sensor.
    bad_icon = entity_registry.async_get("device_tracker.bad_icon")
    assert bad_icon.disabled_by is er.RegistryEntryDisabler.USER
    assert bad_icon.icon is None
    assert (
        entity_registry.async_get("sensor.bad_icon_ip_address").disabled_by
        is er.RegistryEntryDisabler.INTEGRATION
    )


async def test_import_existing_trackers(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    tmp_path: Path,
) -> None:
    """Test the enabled state and sensor of trackers that already exist."""
    entity_registry.async_update_entity(
        "device_tracker.00_1d_ec_02_07_ab", disabled_by=None
    )
    await hass.async_block_till_done()
    # The sensor's new entity ID is taken, so it keeps its current one.
    hass.states.async_set("sensor.laptop_ip_address", "in use")
    path = tmp_path / "devices.yaml"
    path.write_text(
        "laptop:\n  name: Laptop\n  mac: 00:1D:EC:02:07:AB\n  track: false\n"
        "tablet:\n  name: Tablet\n  mac: 00:1D:EC:02:07:AC\n  track: true\n"
    )
    entity_registry.async_remove("sensor.00_1d_ec_02_07_ac_ip_address")

    result = await _start_import(hass, init_integration, str(path))
    assert result["description_placeholders"]["unavailable"] == "none"
    await hass.config_entries.options.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()

    # track: false disables a tracker that was enabled.
    laptop = entity_registry.async_get("device_tracker.laptop")
    assert laptop.disabled_by is er.RegistryEntryDisabler.USER
    assert entity_registry.async_get("sensor.00_1d_ec_02_07_ab_ip_address")
    # track: true enables a tracker that was disabled for an unknown MAC, and
    # its deleted sensor is created again with the matching entity ID.
    tablet = entity_registry.async_get("device_tracker.tablet")
    assert tablet.disabled_by is None
    sensor = entity_registry.async_get("sensor.tablet_ip_address")
    assert sensor.unique_id == f"{SERIAL}_{MAC_2}_ip_address"
    assert sensor.disabled_by is None


async def test_import_keeps_matching_entity_id(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    tmp_path: Path,
) -> None:
    """Test importing a device whose tracker already has the old entity ID."""
    path = tmp_path / "known_devices.yaml"
    path.write_text(
        "00_1d_ec_02_07_ab:\n  name: Laptop\n  mac: 00:1D:EC:02:07:AB\n  track: true\n"
    )
    result = await _start_import(hass, init_integration, str(path))
    assert result["description_placeholders"]["unavailable"] == "none"
    await hass.config_entries.options.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()
    tracker = entity_registry.async_get("device_tracker.00_1d_ec_02_07_ab")
    assert tracker.name == "Laptop"
    assert entity_registry.async_get(
        "sensor.00_1d_ec_02_07_ab_ip_address"
    ).unique_id == (f"{SERIAL}_{MAC_1}_ip_address")


@pytest.mark.parametrize(
    ("content", "error"),
    [(None, "file_not_found"), ("phone:\n  name: GPS only\n", "no_devices")],
)
async def test_import_errors(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    tmp_path: Path,
    content: str | None,
    error: str,
) -> None:
    """Test import errors, and that you can try again."""
    path = tmp_path / "known_devices.yaml"
    if content is not None:
        path.write_text(content)
    result = await _start_import(hass, init_integration, str(path))
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert _suggested_path(result) == str(path)

    shutil.copy(FIXTURE, path)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_PATH: str(path)}
    )
    assert result["step_id"] == "import_known_devices_confirm"


async def test_import_default_path(
    hass: HomeAssistant, init_integration: MockConfigEntry
) -> None:
    """Test the import step suggests known_devices.yaml."""
    result = await hass.config_entries.options.async_init(init_integration.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "import_known_devices"}
    )
    assert _suggested_path(result) == "known_devices.yaml"
    assert DOMAIN == "cisco_ios_tracker"


async def test_import_twice_changes_nothing(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test that importing the same file again leaves the trackers alone."""
    for _ in range(2):
        result = await _start_import(hass, init_integration, str(FIXTURE))
        await hass.config_entries.options.async_configure(result["flow_id"], {})
        await hass.async_block_till_done()
    # The second time, every tracker already has its imported entity ID.
    result = await _start_import(hass, init_integration, str(FIXTURE))
    assert result["description_placeholders"]["new"] == "0"
    assert result["description_placeholders"]["existing"] == "5"
    assert entity_registry.async_get("device_tracker.laptop").name == "Office laptop"


async def test_import_while_not_loaded(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test importing while the entry is not loaded.

    The sensor of a tracker that the import disables is disabled too, even
    though the integration isn't running to follow the change.
    """
    mock_config_entry.add_to_hass(hass)
    tracker = entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"{SERIAL}_{MAC_1}",
        config_entry=mock_config_entry,
        suggested_object_id="laptop",
    )
    sensor = entity_registry.async_get_or_create(
        "sensor",
        DOMAIN,
        f"{SERIAL}_{MAC_1}_ip_address",
        config_entry=mock_config_entry,
        suggested_object_id="laptop_ip_address",
    )
    known = KnownDevices(
        devices=[
            KnownDevice(dev_id="laptop", mac=MAC_1, name=None, icon=None, track=False)
        ]
    )
    async_apply_import(
        hass, mock_config_entry, async_plan_import(hass, mock_config_entry, known)
    )
    assert (
        entity_registry.async_get(tracker.entity_id).disabled_by
        is er.RegistryEntryDisabler.USER
    )
    assert (
        entity_registry.async_get(sensor.entity_id).disabled_by
        is er.RegistryEntryDisabler.INTEGRATION
    )

"""Tests for manually linking trackers to devices of other integrations."""

from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cisco_ios_tracker.const import (
    CONF_DEVICE_LINKS,
    DOMAIN,
    SERVICE_LINK_DEVICE,
    SERVICE_UNLINK_DEVICE,
)
from custom_components.cisco_ios_tracker.links import (
    _async_release_mac_device,
    async_link_device,
    async_mac_known,
    device_owner,
)
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr, entity_registry as er

from .conftest import MAC_1, MAC_2, SERIAL, find_entry_device

TRACKER_1 = "device_tracker.00_1d_ec_02_07_ab"
TRACKER_2 = "device_tracker.00_1d_ec_02_07_ac"
SENSOR_1 = "sensor.00_1d_ec_02_07_ab_ip_address"


@pytest.fixture
def cast_device(hass: HomeAssistant) -> dr.DeviceEntry:
    """Register a device without a MAC address, like a Chromecast."""
    cast_entry = MockConfigEntry(domain="cast_like", title="Cast")
    cast_entry.add_to_hass(hass)
    return dr.async_get(hass).async_get_or_create(
        config_entry_id=cast_entry.entry_id,
        identifiers={("cast_like", "uuid-1")},
        name="Kitchen speaker",
    )


async def _link_with_options_flow(
    hass: HomeAssistant, entry: MockConfigEntry, mac: str, device_id: str
) -> dict:
    """Run the link step of the options flow."""
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "link_device"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "link_device"
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"tracker": mac, "device": device_id}
    )
    await hass.async_block_till_done()
    return result


async def test_link_with_options_flow(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test linking a disabled tracker to a device without a MAC address."""
    # Nobody knows the MAC address, so the tracker and its sensor start
    # disabled and without a device.
    tracker = entity_registry.async_get(TRACKER_1)
    assert tracker.disabled_by is er.RegistryEntryDisabler.INTEGRATION
    assert tracker.device_id is None

    result = await _link_with_options_flow(
        hass, init_integration, MAC_1, cast_device.id
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert init_integration.options[CONF_DEVICE_LINKS] == {MAC_1: cast_device.id}
    assert init_integration.state is ConfigEntryState.LOADED

    for entity_id in (TRACKER_1, SENSOR_1):
        registry_entry = entity_registry.async_get(entity_id)
        assert registry_entry.device_id == cast_device.id
        assert registry_entry.disabled_by is None
    # The other tracker is not affected.
    assert entity_registry.async_get(TRACKER_2).device_id is None

    # The link is kept when the entry is loaded again, and the enabled
    # entities get a state.
    await hass.config_entries.async_reload(init_integration.entry_id)
    await hass.async_block_till_done()
    assert entity_registry.async_get(TRACKER_1).device_id == cast_device.id
    assert hass.states.get(TRACKER_1).state == "home"
    sensor = hass.states.get(SENSOR_1)
    assert sensor.state == "10.1.10.20"
    assert sensor.attributes["friendly_name"] == "Kitchen speaker IP address"


async def test_link_options_flow_labels(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the trackers offered by the link step."""
    entity_registry.async_update_entity(TRACKER_2, name="Laptop")
    result = await hass.config_entries.options.async_init(init_integration.entry_id)
    assert result["menu_options"] == ["settings", "link_device", "import_known_devices"]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "link_device"}
    )
    selector = result["data_schema"].schema["tracker"]
    options = selector.config["options"]
    assert [option["value"] for option in options] == [MAC_1, MAC_2]
    assert options[0]["label"] == "00:1d:ec:02:07:ab (device_tracker.00_1d_ec_02_07_ab)"
    assert options[1]["label"] == "Laptop (device_tracker.00_1d_ec_02_07_ac)"


@pytest.mark.parametrize(
    ("device_id", "error"),
    [("does-not-exist", "device_not_found"), ("router", "own_device")],
)
async def test_link_options_flow_errors(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    device_registry: dr.DeviceRegistry,
    device_id: str,
    error: str,
) -> None:
    """Test linking to a device that doesn't exist or belongs to the router."""
    if device_id == "router":
        device_id = find_entry_device(
            hass, init_integration.entry_id, (DOMAIN, SERIAL)
        ).id
    result = await _link_with_options_flow(hass, init_integration, MAC_1, device_id)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    # The form can be submitted again with a valid device.
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"tracker": MAC_1, "device": cast_device.id}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_link_options_flow_tracker_deleted(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test linking a tracker that was deleted while the form was open."""
    result = await hass.config_entries.options.async_init(init_integration.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "link_device"}
    )
    entity_registry.async_remove(TRACKER_1)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"tracker": MAC_1, "device": cast_device.id}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "tracker_not_found"}


async def test_link_options_flow_without_trackers(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test the link step before any client was seen."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "link_device"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_trackers"


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_manual_link_wins(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test that a link replaces the automatic device of a known MAC address."""
    automatic = find_entry_device(
        hass, init_integration.entry_id, (dr.CONNECTION_NETWORK_MAC, MAC_1)
    )
    assert automatic is not None
    assert entity_registry.async_get(TRACKER_1).device_id == automatic.id
    sensor_entity_id = entity_registry.async_get_entity_id(
        "sensor", DOMAIN, f"{SERIAL}_{MAC_1}_ip_address"
    )
    assert entity_registry.async_get(sensor_entity_id).device_id == automatic.id

    result = await _link_with_options_flow(
        hass, init_integration, MAC_1, cast_device.id
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY

    assert entity_registry.async_get(TRACKER_1).device_id == cast_device.id
    assert entity_registry.async_get(sensor_entity_id).device_id == cast_device.id
    # The automatic device has no entities left: it is removed (or, with the
    # shared devices before HA 2026.8, no longer belongs to this entry).
    assert (
        find_entry_device(
            hass, init_integration.entry_id, (dr.CONNECTION_NETWORK_MAC, MAC_1)
        )
        is None
    )
    # The device of the other integration is not changed.
    assert device_registry.async_get(cast_device.id) == cast_device

    # Removing the link brings the automatic device back.
    result = await hass.config_entries.options.async_init(init_integration.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "unlink_device"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["data_schema"].schema["trackers"].config["options"] == [
        {
            "value": MAC_1,
            "label": "00:1d:ec:02:07:ab (device_tracker.00_1d_ec_02_07_ab)"
            " → Kitchen speaker",
        }
    ]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"trackers": [MAC_1]}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done()
    assert init_integration.options[CONF_DEVICE_LINKS] == {}
    automatic = find_entry_device(
        hass, init_integration.entry_id, (dr.CONNECTION_NETWORK_MAC, MAC_1)
    )
    assert automatic is not None
    assert entity_registry.async_get(TRACKER_1).device_id == automatic.id


async def test_unlink_labels_for_missing_items(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test the unlink step for a deleted tracker and a deleted device."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={**mock_config_entry.options, CONF_DEVICE_LINKS: {MAC_1: "gone"}},
    )
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "unlink_device"}
    )
    assert result["data_schema"].schema["trackers"].config["options"] == [
        {"value": MAC_1, "label": f"{MAC_1} → gone"}
    ]


async def test_link_and_unlink_services(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the link and unlink service actions."""
    await hass.services.async_call(
        DOMAIN,
        SERVICE_LINK_DEVICE,
        {ATTR_ENTITY_ID: TRACKER_1, "device_id": cast_device.id},
        blocking=True,
    )
    await hass.async_block_till_done()
    assert init_integration.options[CONF_DEVICE_LINKS] == {MAC_1: cast_device.id}
    assert entity_registry.async_get(TRACKER_1).device_id == cast_device.id
    assert hass.states.get(TRACKER_1).state == "home"

    await hass.services.async_call(
        DOMAIN, SERVICE_UNLINK_DEVICE, {ATTR_ENTITY_ID: TRACKER_1}, blocking=True
    )
    await hass.async_block_till_done()
    assert init_integration.options[CONF_DEVICE_LINKS] == {}
    assert entity_registry.async_get(TRACKER_1).device_id is None
    assert init_integration.state is ConfigEntryState.LOADED


@pytest.mark.parametrize(
    ("service", "data", "error"),
    [
        (
            SERVICE_LINK_DEVICE,
            {ATTR_ENTITY_ID: "device_tracker.unknown", "device_id": "x"},
            "not_a_tracker",
        ),
        (
            SERVICE_LINK_DEVICE,
            {ATTR_ENTITY_ID: SENSOR_1, "device_id": "x"},
            "not_a_tracker",
        ),
        (
            SERVICE_LINK_DEVICE,
            {ATTR_ENTITY_ID: TRACKER_1, "device_id": "x"},
            "device_not_found",
        ),
        (SERVICE_UNLINK_DEVICE, {ATTR_ENTITY_ID: TRACKER_1}, "not_linked"),
    ],
)
async def test_service_errors(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    service: str,
    data: dict,
    error: str,
) -> None:
    """Test service action validation errors."""
    with pytest.raises(ServiceValidationError) as exc_info:
        await hass.services.async_call(DOMAIN, service, data, blocking=True)
    assert exc_info.value.translation_key == error


async def test_service_tracker_without_config_entry(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test a tracker registry entry whose config entry is gone."""
    entity_registry.async_get_or_create(
        "device_tracker", DOMAIN, "orphan", suggested_object_id="orphan"
    )
    with pytest.raises(ServiceValidationError) as exc_info:
        await hass.services.async_call(
            DOMAIN,
            SERVICE_UNLINK_DEVICE,
            {ATTR_ENTITY_ID: "device_tracker.orphan"},
            blocking=True,
        )
    assert exc_info.value.translation_key == "not_a_tracker"


async def test_linked_device_deleted(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test that deleting the linked device keeps the tracker and drops the link."""
    await _link_with_options_flow(hass, init_integration, MAC_1, cast_device.id)
    # Another device change doesn't matter.
    device_registry.async_update_device(cast_device.id, name_by_user="Speaker")
    await hass.async_block_till_done()
    assert init_integration.options[CONF_DEVICE_LINKS] == {MAC_1: cast_device.id}

    device_registry.async_remove_device(cast_device.id)
    await hass.async_block_till_done()
    assert init_integration.options[CONF_DEVICE_LINKS] == {}
    tracker = entity_registry.async_get(TRACKER_1)
    assert tracker is not None
    assert tracker.device_id is None
    assert init_integration.state is ConfigEntryState.LOADED


async def test_unrelated_device_deleted(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test that deleting a device that isn't linked changes nothing."""
    device_registry.async_remove_device(cast_device.id)
    await hass.async_block_till_done()
    assert CONF_DEVICE_LINKS not in init_integration.options


async def test_stale_links_pruned_on_setup(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_client: MagicMock,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test that links to deleted devices are dropped when the entry loads."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={
            **mock_config_entry.options,
            CONF_DEVICE_LINKS: {MAC_1: "gone", MAC_2: cast_device.id},
        },
    )
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.options[CONF_DEVICE_LINKS] == {MAC_2: cast_device.id}
    # A tracker created for a linked MAC is enabled and on the linked device.
    tracker = entity_registry.async_get(
        entity_registry.async_get_entity_id(
            "device_tracker", DOMAIN, f"{SERIAL}_{MAC_2}"
        )
    )
    assert tracker.device_id == cast_device.id
    assert tracker.disabled_by is None
    assert entity_registry.async_get(TRACKER_1).device_id is None


async def test_link_keeps_user_disabled(
    hass: HomeAssistant,
    init_integration: MockConfigEntry,
    cast_device: dr.DeviceEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test that linking doesn't enable a tracker you disabled yourself.

    Also covers a tracker whose IP address sensor was deleted.
    """
    entity_registry.async_remove(SENSOR_1)
    entity_registry.async_update_entity(
        TRACKER_1, disabled_by=er.RegistryEntryDisabler.USER
    )
    options = async_link_device(hass, init_integration, MAC_1, cast_device.id)
    assert options[CONF_DEVICE_LINKS] == {MAC_1: cast_device.id}
    assert (
        entity_registry.async_get(TRACKER_1).disabled_by
        is er.RegistryEntryDisabler.USER
    )


@pytest.mark.parametrize(
    ("device", "owner"),
    [
        # HA 2026.8 and later: one config entry per device.
        (SimpleNamespace(config_entry_id="owner", primary_config_entry=None), "owner"),
        # Before HA 2026.8: shared devices with a primary config entry.
        (SimpleNamespace(primary_config_entry="primary"), "primary"),
    ],
)
def test_device_owner(device: SimpleNamespace, owner: str) -> None:
    """Test finding the owner of a device on old and new HA versions."""
    assert device_owner(cast(dr.DeviceEntry, device)) == owner


@pytest.mark.parametrize("new_registry", [True, False])
async def test_mac_known_registry_versions(
    hass: HomeAssistant, new_registry: bool
) -> None:
    """Test the MAC lookup with and without async_get_devices."""
    if new_registry:
        registry = MagicMock(spec=["async_get_devices"])
        registry.async_get_devices.return_value = []
    else:
        registry = MagicMock(spec=["async_get_device"])
        registry.async_get_device.return_value = object()
    with patch(
        "custom_components.cisco_ios_tracker.links.dr.async_get",
        return_value=registry,
    ):
        assert async_mac_known(hass, MAC_1) is not new_registry


@pytest.mark.parametrize("new_registry", [True, False])
async def test_release_mac_device_registry_versions(
    hass: HomeAssistant, init_integration: MockConfigEntry, new_registry: bool
) -> None:
    """Test the automatic device is removed, or only left, after a link.

    Before HA 2026.8 the automatic device is shared with another integration,
    so only this config entry is removed from it.
    """
    connection = (dr.CONNECTION_NETWORK_MAC, MAC_1)
    devices = [
        SimpleNamespace(id="other", connections={("mac", "ff:ff:ff:ff:ff:ff")}),
        SimpleNamespace(id="busy", connections={connection}),
        (
            SimpleNamespace(id="free", connections={connection}, config_entry_id="x")
            if new_registry
            else SimpleNamespace(id="free", connections={connection})
        ),
    ]
    registry = MagicMock()
    with (
        patch(
            "custom_components.cisco_ios_tracker.links.dr.async_get",
            return_value=registry,
        ),
        patch(
            "custom_components.cisco_ios_tracker.links.dr.async_entries_for_config_entry",
            return_value=devices,
        ),
        patch(
            "custom_components.cisco_ios_tracker.links.er.async_entries_for_device",
            side_effect=lambda _registry, device_id, **_: (
                [SimpleNamespace(config_entry_id=init_integration.entry_id)]
                if device_id == "busy"
                else []
            ),
        ),
    ):
        _async_release_mac_device(hass, init_integration, MAC_1)
    if new_registry:
        registry.async_remove_device.assert_called_once_with("free")
        registry.async_update_device.assert_not_called()
    else:
        registry.async_update_device.assert_called_once_with(
            "free", remove_config_entry_id=init_integration.entry_id
        )
        registry.async_remove_device.assert_not_called()

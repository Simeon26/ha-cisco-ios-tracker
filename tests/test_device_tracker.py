"""Tests for the Cisco IOS Tracker device tracker platform."""

from collections.abc import Generator
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from freezegun.api import FrozenDateTimeFactory
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_capture_events,
    async_fire_time_changed,
    mock_restore_cache,
    mock_restore_cache_with_extra_data,
    snapshot_platform,
)
from syrupy.assertion import SnapshotAssertion

from custom_components.cisco_ios_tracker.client import (
    ArpEntry,
    CiscoAuthenticationError,
    CiscoConnectionError,
    CiscoHostKeyMismatchError,
)
from custom_components.cisco_ios_tracker.const import (
    CONF_MAX_ARP_AGE,
    DOMAIN,
    SCAN_INTERVAL,
)
from homeassistant.components.device_tracker import CONF_CONSIDER_HOME
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import (
    EVENT_STATE_CHANGED,
    STATE_HOME,
    STATE_NOT_HOME,
    STATE_UNAVAILABLE,
    Platform,
)
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import (
    device_registry as dr,
    entity_registry as er,
    issue_registry as ir,
)
from homeassistant.util import dt as dt_util

from .conftest import ARP_ENTRIES, DEVICE_INFO, MAC_1, MAC_2, MAC_NEW, MAC_STALE, SERIAL

ENTITY_1 = "device_tracker.00_1d_ec_02_07_ab"
ENTITY_2 = "device_tracker.00_1d_ec_02_07_ac"
ENTITY_STALE = "device_tracker.00_1d_ec_02_07_ad"
ENTITY_NEW = "device_tracker.00_1d_ec_02_07_ae"
MAC_OLD = "00:1d:ec:02:07:af"
ENTITY_OLD = "device_tracker.00_1d_ec_02_07_af"


@pytest.fixture(autouse=True)
def platforms() -> Generator[None]:
    """Only set up the device tracker platform."""
    with patch(
        "custom_components.cisco_ios_tracker.PLATFORMS", [Platform.DEVICE_TRACKER]
    ):
        yield


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Set up the config entry."""
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def _with_options(
    entry: MockConfigEntry, consider_home: int, max_arp_age: int
) -> MockConfigEntry:
    """Return a copy of the config entry with other options."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=entry.title,
        data=dict(entry.data),
        options={CONF_CONSIDER_HOME: consider_home, CONF_MAX_ARP_AGE: max_arp_age},
        unique_id=entry.unique_id,
    )


async def _poll(hass: HomeAssistant, freezer: FrozenDateTimeFactory) -> None:
    """Advance the time to the next poll."""
    freezer.tick(SCAN_INTERVAL)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()


@pytest.mark.freeze_time("2026-10-02 12:00:00+00:00")
@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_entities(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the tracker entities."""
    await snapshot_platform(hass, entity_registry, snapshot, mock_config_entry.entry_id)

    # The router's own entry and stale entries are not tracked.
    assert hass.states.get(ENTITY_STALE) is None
    assert hass.states.get("device_tracker.00_1d_ec_00_00_01") is None


@pytest.mark.usefixtures("init_integration")
async def test_disabled_by_default(
    hass: HomeAssistant, entity_registry: er.EntityRegistry
) -> None:
    """Test that trackers for MACs unknown to other integrations are disabled."""
    entity_entry = entity_registry.async_get(ENTITY_1)
    assert entity_entry is not None
    assert entity_entry.disabled_by is er.RegistryEntryDisabler.INTEGRATION
    assert hass.states.get(ENTITY_1) is None


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_new_clients_added(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that a tracker is added when a client becomes active."""
    assert hass.states.get(ENTITY_NEW) is None

    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [*ARP_ENTRIES, ArpEntry("10.1.10.50", MAC_NEW, 0, None)],
    )
    await _poll(hass, freezer)

    state = hass.states.get(ENTITY_NEW)
    assert state is not None
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == "10.1.10.50"
    assert state.attributes["interface"] is None


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_consider_home(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that a client stays home for the consider home time."""
    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_HOME
    start = state.last_updated

    # The client becomes stale; the entry stays in the table with a higher age.
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [
            ArpEntry("10.1.10.20", MAC_1, 1, "Vlan10"),
            ArpEntry("10.1.20.21", MAC_2, 0, "Vlan20"),
        ],
    )
    for _ in range(5):
        await _poll(hass, freezer)
    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_HOME
    # Nothing about the client changed, so its state was not written again.
    assert state.last_updated == start

    # 180 seconds after the client was last seen it is away.
    await _poll(hass, freezer)
    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_NOT_HOME
    # The last known address is kept.
    assert state.attributes["ip"] == "10.1.10.20"
    assert state.attributes["interface"] == "Vlan10"
    assert hass.states.get(ENTITY_2).state == STATE_HOME

    # The client returns.
    mock_client.async_get_all.return_value = (DEVICE_INFO, list(ARP_ENTRIES))
    await _poll(hass, freezer)
    assert hass.states.get(ENTITY_1).state == STATE_HOME


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_home_client_is_not_written_every_poll(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory
) -> None:
    """Test that a client that stays home causes no state changes."""
    events = async_capture_events(hass, EVENT_STATE_CHANGED)
    for _ in range(3):
        await _poll(hass, freezer)
    assert [e for e in events if e.data["entity_id"] == ENTITY_1] == []
    state = hass.states.get(ENTITY_1)
    assert state.attributes["interface"] == "Vlan10"
    assert "last_time_reachable" not in state.attributes


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_address_change(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that a new IP address or interface of a known client is shown."""
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [ArpEntry("10.1.20.40", MAC_1, 0, "Vlan20")],
    )
    await _poll(hass, freezer)

    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == "10.1.20.40"
    assert state.attributes["interface"] == "Vlan20"


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_consider_home_zero(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test that with consider home 0 a client is home while it is active.

    The time is not frozen, so time passes between the poll and the state.
    """
    await _setup(hass, _with_options(mock_config_entry, 0, 5))

    # The entry with age 5 counts as seen with a maximum ARP age of 5.
    state = hass.states.get(ENTITY_STALE)
    assert state is not None
    assert state.state == STATE_HOME
    assert hass.states.get(ENTITY_1).state == STATE_HOME

    # On the first poll that misses it, the client is away.
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [entry for entry in ARP_ENTRIES if entry.mac != MAC_STALE],
    )
    async_fire_time_changed(hass, dt_util.utcnow() + SCAN_INTERVAL)
    await hass.async_block_till_done()
    assert hass.states.get(ENTITY_STALE).state == STATE_NOT_HOME
    assert hass.states.get(ENTITY_1).state == STATE_HOME


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_options_max_arp_age(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test that the maximum ARP age option makes older entries count."""
    await _setup(hass, _with_options(mock_config_entry, 180, 5))

    assert hass.states.get(ENTITY_STALE).state == STATE_HOME


@pytest.mark.usefixtures("mock_device_registry_devices")
async def test_multiple_addresses(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test that the address with the lowest age is used for a MAC."""
    mock_client.async_get_all.return_value = (
        DEVICE_INFO,
        [
            ArpEntry("10.1.10.20", MAC_1, 3, "Vlan10"),
            ArpEntry("10.1.10.21", MAC_1, 1, "Vlan11"),
            ArpEntry("10.1.10.22", MAC_1, 1, "Vlan12"),
            ArpEntry("10.1.10.23", MAC_1, 2, "Vlan13"),
        ],
    )
    await _setup(hass, _with_options(mock_config_entry, 180, 5))

    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == "10.1.10.21"
    assert state.attributes["interface"] == "Vlan11"


@pytest.mark.usefixtures("mock_device_registry_devices", "mock_client")
async def test_restore_from_registry(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test that known clients are restored as away after a restart."""
    mock_config_entry.add_to_hass(hass)
    entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"{SERIAL}_{MAC_OLD}",
        config_entry=mock_config_entry,
        suggested_object_id="00_1d_ec_02_07_af",
    )
    # Entries of another platform or entry prefix are ignored.
    entity_registry.async_get_or_create(
        "sensor", DOMAIN, f"{SERIAL}_connected_clients", config_entry=mock_config_entry
    )
    entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"OTHER_{MAC_NEW}",
        config_entry=mock_config_entry,
        suggested_object_id="other",
    )
    await _setup(hass, mock_config_entry)

    state = hass.states.get(ENTITY_OLD)
    assert state is not None
    assert state.state == STATE_NOT_HOME
    assert hass.states.get("device_tracker.other") is None
    # The entry of the other prefix doesn't create a tracker for its MAC.
    assert hass.states.get(ENTITY_NEW) is None
    assert (
        entity_registry.async_get_entity_id(
            "device_tracker", DOMAIN, f"{SERIAL}_{MAC_NEW}"
        )
        is None
    )
    assert hass.states.get(ENTITY_1).state == STATE_HOME


@pytest.mark.usefixtures("mock_device_registry_devices", "mock_client")
async def test_restore_state(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test that a client that was home before a restart stays home."""
    last_seen = dt_util.utcnow() - timedelta(seconds=60)
    mock_config_entry.add_to_hass(hass)
    for mac, object_id in ((MAC_OLD, "00_1d_ec_02_07_af"), (MAC_1, None)):
        entity_registry.async_get_or_create(
            "device_tracker",
            DOMAIN,
            f"{SERIAL}_{mac}",
            config_entry=mock_config_entry,
            suggested_object_id=object_id or "00_1d_ec_02_07_ab",
        )

    def _stored(entity_id: str, state: str, ip: str, interface: str) -> object:
        attributes = {"ip": ip, "interface": interface}
        return (
            State(entity_id, state, attributes),
            {"last_seen": last_seen.isoformat()},
        )

    stored = [
        _stored(ENTITY_OLD, STATE_HOME, "10.1.10.99", "Vlan99"),
        # A client that is active now keeps its current data.
        _stored(ENTITY_1, STATE_NOT_HOME, "10.1.10.98", "Vlan98"),
    ]
    mock_restore_cache_with_extra_data(hass, stored)
    await _setup(hass, mock_config_entry)

    state = hass.states.get(ENTITY_OLD)
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == "10.1.10.99"
    assert state.attributes["interface"] == "Vlan99"
    assert "last_time_reachable" not in state.attributes
    state = hass.states.get(ENTITY_1)
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == "10.1.10.20"

    # The last seen time is saved for the next restart.
    entity = hass.data["entity_components"]["device_tracker"].get_entity(ENTITY_OLD)
    assert entity.extra_restore_state_data.as_dict() == {
        "last_seen": last_seen.isoformat()
    }

    # Consider home started when the client was last seen before the restart.
    freezer.tick(timedelta(seconds=120))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    assert hass.states.get(ENTITY_OLD).state == STATE_NOT_HOME


@pytest.mark.parametrize(
    "extra_data", [None, {"last_seen": None}, {"last_seen": "not a time"}]
)
@pytest.mark.usefixtures("mock_device_registry_devices", "mock_client")
async def test_restore_state_without_last_seen(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    extra_data: dict[str, Any] | None,
) -> None:
    """Test restoring a state without a usable last seen time."""
    mock_config_entry.add_to_hass(hass)
    entity_registry.async_get_or_create(
        "device_tracker",
        DOMAIN,
        f"{SERIAL}_{MAC_OLD}",
        config_entry=mock_config_entry,
        suggested_object_id="00_1d_ec_02_07_af",
    )
    last_state = State(ENTITY_OLD, STATE_HOME, {})
    if extra_data is None:
        mock_restore_cache(hass, [last_state])
    else:
        mock_restore_cache_with_extra_data(hass, [(last_state, extra_data)])
    await _setup(hass, mock_config_entry)

    state = hass.states.get(ENTITY_OLD)
    assert state.state == STATE_NOT_HOME
    assert "ip" not in state.attributes
    assert state.attributes["interface"] is None
    entity = hass.data["entity_components"]["device_tracker"].get_entity(ENTITY_OLD)
    assert entity.extra_restore_state_data.as_dict() == {"last_seen": None}


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_unavailable_and_recovery(
    hass: HomeAssistant, mock_client: MagicMock, freezer: FrozenDateTimeFactory
) -> None:
    """Test that trackers are unavailable while the router is unreachable."""
    mock_client.async_get_all.side_effect = CiscoConnectionError("timeout")
    await _poll(hass, freezer)
    assert hass.states.get(ENTITY_1).state == STATE_UNAVAILABLE

    mock_client.async_get_all.side_effect = None
    await _poll(hass, freezer)
    assert hass.states.get(ENTITY_1).state == STATE_HOME


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_auth_failed(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test that rejected credentials during a poll start reauthentication."""
    mock_client.async_get_all.side_effect = CiscoAuthenticationError
    await _poll(hass, freezer)

    assert hass.states.get(ENTITY_1).state == STATE_UNAVAILABLE
    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1
    assert flows[0]["context"]["source"] == SOURCE_REAUTH
    assert flows[0]["context"]["entry_id"] == mock_config_entry.entry_id


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_host_key_mismatch(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    issue_registry: ir.IssueRegistry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test the repair issue for a changed host key."""
    issue_id = f"host_key_mismatch_{mock_config_entry.entry_id}"
    mock_client.async_get_all.side_effect = CiscoHostKeyMismatchError(
        "SHA256:stored", None
    )
    await _poll(hass, freezer)

    assert hass.states.get(ENTITY_1).state == STATE_UNAVAILABLE
    issue = issue_registry.async_get_issue(DOMAIN, issue_id)
    assert issue is not None
    assert issue.translation_key == "host_key_mismatch"
    assert issue.translation_placeholders["presented"] == "unknown"
    assert mock_config_entry.state is ConfigEntryState.LOADED

    mock_client.async_get_all.side_effect = None
    await _poll(hass, freezer)
    assert hass.states.get(ENTITY_1).state == STATE_HOME
    assert issue_registry.async_get_issue(DOMAIN, issue_id) is None


@pytest.mark.usefixtures("mock_device_registry_devices", "init_integration")
async def test_remove_device_and_rediscover(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test that a removed client is added again when it becomes active."""
    entity_entry = entity_registry.async_get(ENTITY_1)
    assert entity_entry is not None
    assert entity_entry.device_id is not None

    mock_client.async_get_all.return_value = (DEVICE_INFO, [])
    entity_registry.async_remove(ENTITY_1)
    await hass.async_block_till_done()
    assert hass.states.get(ENTITY_1) is None

    await _poll(hass, freezer)
    assert entity_registry.async_get(ENTITY_1) is None

    mock_client.async_get_all.return_value = (DEVICE_INFO, list(ARP_ENTRIES))
    await _poll(hass, freezer)
    assert entity_registry.async_get(ENTITY_1) is not None
    assert hass.states.get(ENTITY_1).state == STATE_HOME

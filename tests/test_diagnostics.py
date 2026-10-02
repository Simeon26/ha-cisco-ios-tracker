"""Tests for the Cisco IOS Tracker diagnostics."""

from dataclasses import replace
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.components.diagnostics import (
    get_diagnostics_for_config_entry,
)
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator
from syrupy.assertion import SnapshotAssertion
from syrupy.filters import props

from custom_components.cisco_ios_tracker.const import (
    AUTH_KEY_FILE,
    AUTH_PRIVATE_KEY,
    CONF_AUTH_METHOD,
    CONF_KEY_FILE,
    CONF_PASSPHRASE,
    CONF_PRIVATE_KEY,
    DOMAIN,
)
from homeassistant.components.diagnostics import REDACTED
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .conftest import (
    ARP_ENTRIES,
    DEVICE_INFO,
    ENTRY_DATA,
    ENTRY_OPTIONS,
    HOST,
    HOST_KEY,
    MAC_1,
    PASSWORD,
    SERIAL,
    USERNAME,
)

PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0secretkeydata\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
PASSPHRASE = "key-passphrase"
KEY_FILE = "/config/.ssh/cisco_ha"
BASE_MAC = "00:1d:ec:00:00:99"

PASSWORD_DATA = ENTRY_DATA
KEY_DATA = {key: value for key, value in ENTRY_DATA.items() if key != CONF_PASSWORD}
PRIVATE_KEY_DATA = {
    **KEY_DATA,
    CONF_AUTH_METHOD: AUTH_PRIVATE_KEY,
    CONF_PRIVATE_KEY: PRIVATE_KEY,
    CONF_PASSPHRASE: PASSPHRASE,
}
KEY_FILE_DATA = {
    **KEY_DATA,
    CONF_AUTH_METHOD: AUTH_KEY_FILE,
    CONF_KEY_FILE: KEY_FILE,
    CONF_PASSPHRASE: PASSPHRASE,
}
# Data that must never appear in the diagnostics.
SECRETS = [
    HOST,
    USERNAME,
    PASSWORD,
    PRIVATE_KEY.strip(),
    "secretkeydata",
    PASSPHRASE,
    KEY_FILE,
    HOST_KEY,
    HOST_KEY.split()[1],
    SERIAL,
    BASE_MAC,
    MAC_1,
    "10.1.10.20",
    "router1",
]


@pytest.mark.parametrize(
    "data",
    [PASSWORD_DATA, PRIVATE_KEY_DATA, KEY_FILE_DATA],
    ids=["password", "private_key", "key_file"],
)
@pytest.mark.usefixtures("mock_device_registry_devices", "mock_load_private_key")
async def test_diagnostics(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    mock_client: MagicMock,
    snapshot: SnapshotAssertion,
    data: dict[str, Any],
) -> None:
    """Test that the diagnostics contain no credentials or personal data."""
    mock_client.async_get_all.return_value = (
        replace(DEVICE_INFO, base_mac=BASE_MAC),
        list(ARP_ENTRIES),
    )
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="router1",
        data=data,
        options=dict(ENTRY_OPTIONS),
        unique_id=SERIAL,
        entry_id="01JCISCO0000000000000000AB",
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    diagnostics = await get_diagnostics_for_config_entry(hass, hass_client, entry)

    # Checked without the snapshot, which is regenerated for older releases.
    dumped = json.dumps(diagnostics)
    for secret in SECRETS:
        assert secret not in dumped
    entry_data = diagnostics["entry"]["data"]
    for key in (
        CONF_HOST,
        CONF_USERNAME,
        CONF_PASSWORD,
        CONF_PRIVATE_KEY,
        CONF_PASSPHRASE,
        CONF_KEY_FILE,
        "host_key",
    ):
        if key in data:
            assert entry_data[key] == REDACTED
    assert diagnostics["entry"]["title"] == REDACTED
    assert diagnostics["entry"]["unique_id"] == REDACTED
    assert diagnostics["device"]["base_mac"] == REDACTED
    assert diagnostics["device"]["serial"] == REDACTED
    assert diagnostics["host_key_pinned"] is True
    assert diagnostics["host_key_type"] == "ssh-rsa"

    assert diagnostics == snapshot(exclude=props("created_at", "modified_at"))

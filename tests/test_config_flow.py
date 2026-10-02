"""Tests for the Cisco IOS Tracker config flow."""

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cisco_ios_tracker.client import (
    CiscoAuthenticationError,
    CiscoCommandError,
    CiscoConnectionError,
    CiscoHostKeyMismatchError,
    CiscoInvalidKeyError,
    CiscoKeyExchangeError,
    CiscoKeyFileNotFoundError,
    CiscoPassphraseError,
)
from custom_components.cisco_ios_tracker.const import (
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
    DOMAIN,
)
from homeassistant.components.device_tracker import CONF_CONSIDER_HOME
from homeassistant.config_entries import SOURCE_USER
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult, FlowResultType

from .conftest import (
    DEVICE_INFO,
    ENTRY_DATA,
    HOST,
    HOST_KEY,
    MAC_1,
    NEW_HOST_KEY,
    PASSWORD,
    SERIAL,
    USERNAME,
)

PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
)
USER_INPUT = {CONF_HOST: f" {HOST} ", CONF_PORT: 22, CONF_USERNAME: USERNAME}

pytestmark = pytest.mark.usefixtures("mock_setup_entry", "mock_fingerprint")


async def _start_user_flow(hass: HomeAssistant, method: str) -> FlowResult:
    """Fill in the user step and choose a login method."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )
    assert result["type"] is FlowResultType.MENU
    assert result["step_id"] == "auth"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": method}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == method
    return result


async def test_user_flow_password(
    hass: HomeAssistant, mock_client: MagicMock, mock_setup_entry: AsyncMock
) -> None:
    """Test setting up the integration with a password."""
    result = await _start_user_flow(hass, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "router1"
    assert result["data"] == ENTRY_DATA
    assert result["options"] == {CONF_CONSIDER_HOME: 180, CONF_MAX_ARP_AGE: 0}
    assert result["result"].unique_id == SERIAL
    assert len(mock_setup_entry.mock_calls) == 1
    mock_client.async_probe.assert_awaited_once()


async def test_user_flow_private_key(
    hass: HomeAssistant, mock_client: MagicMock, mock_load_private_key: MagicMock
) -> None:
    """Test setting up the integration with a pasted, encrypted key."""
    result = await _start_user_flow(hass, AUTH_PRIVATE_KEY)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_PRIVATE_KEY: PRIVATE_KEY, CONF_PASSPHRASE: "passphrase"},
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_HOST: HOST,
        CONF_PORT: 22,
        CONF_USERNAME: USERNAME,
        CONF_AUTH_METHOD: AUTH_PRIVATE_KEY,
        CONF_PRIVATE_KEY: PRIVATE_KEY,
        CONF_PASSPHRASE: "passphrase",
        CONF_HOST_KEY: HOST_KEY,
        CONF_LEGACY_ALGORITHMS: False,
    }
    mock_load_private_key.assert_called_once_with(PRIVATE_KEY, None, "passphrase")


@pytest.mark.parametrize(
    ("key_file", "expected"),
    [
        ("/config/.ssh/id_ed25519", "/config/.ssh/id_ed25519"),
        (" .ssh/id_ed25519 ", "{config}/.ssh/id_ed25519"),
    ],
)
async def test_user_flow_key_file(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_load_private_key: MagicMock,
    key_file: str,
    expected: str,
) -> None:
    """Test setting up the integration with a key file."""
    expected = expected.format(config=hass.config.config_dir)
    result = await _start_user_flow(hass, AUTH_KEY_FILE)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_KEY_FILE: key_file}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_AUTH_METHOD] == AUTH_KEY_FILE
    assert result["data"][CONF_KEY_FILE] == expected
    assert CONF_PASSPHRASE not in result["data"]
    mock_load_private_key.assert_called_once_with(None, expected, None)


async def test_user_flow_legacy_algorithms(
    hass: HomeAssistant, mock_client: MagicMock
) -> None:
    """Test that legacy algorithms detected by the probe are stored."""

    async def _probe() -> object:
        mock_client.legacy_algorithms = True
        return DEVICE_INFO, []

    mock_client.async_probe.side_effect = _probe
    result = await _start_user_flow(hass, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_LEGACY_ALGORITHMS] is True


async def test_user_flow_without_serial(
    hass: HomeAssistant, mock_client: MagicMock
) -> None:
    """Test a device without serial number or hostname."""
    mock_client.async_probe.return_value = (
        replace(DEVICE_INFO, serial=None, hostname=None),
        [],
    )
    result = await _start_user_flow(hass, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == HOST
    assert result["result"].unique_id is None


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        (CiscoAuthenticationError, "invalid_auth"),
        (CiscoKeyExchangeError, "no_common_algorithms"),
        (CiscoCommandError, "command_failed"),
        (CiscoConnectionError, "cannot_connect"),
        (CiscoHostKeyMismatchError("SHA256:a", "SHA256:b"), "host_key_mismatch"),
        (RuntimeError, "unknown"),
    ],
)
async def test_user_flow_errors(
    hass: HomeAssistant,
    mock_client: MagicMock,
    side_effect: Exception | type[Exception],
    error: str,
) -> None:
    """Test connection errors and recovery."""
    mock_client.async_probe.side_effect = side_effect
    result = await _start_user_flow(hass, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == AUTH_PASSWORD
    assert result["errors"] == {"base": error}

    mock_client.async_probe.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize(
    ("side_effect", "errors"),
    [
        (CiscoKeyFileNotFoundError, {CONF_KEY_FILE: "key_file_not_found"}),
        (CiscoPassphraseError, {CONF_PASSPHRASE: "invalid_passphrase"}),
        (CiscoInvalidKeyError, {"base": "invalid_key"}),
    ],
)
async def test_user_flow_key_errors(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_load_private_key: MagicMock,
    side_effect: type[Exception],
    errors: dict[str, str],
) -> None:
    """Test key loading errors and recovery."""
    mock_load_private_key.side_effect = side_effect
    result = await _start_user_flow(hass, AUTH_KEY_FILE)
    user_input = {CONF_KEY_FILE: "/config/.ssh/id_rsa", CONF_PASSPHRASE: "wrong"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == AUTH_KEY_FILE
    assert result["errors"] == errors
    # The path is kept, the passphrase is not shown again.
    suggested = {
        str(key): key.description["suggested_value"]
        for key in result["data_schema"].schema
        if key.description and "suggested_value" in key.description
    }
    assert suggested == {CONF_KEY_FILE: "/config/.ssh/id_rsa"}
    mock_client.async_probe.assert_not_called()

    mock_load_private_key.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**user_input, CONF_PASSPHRASE: "right"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PASSPHRASE] == "right"


async def test_user_flow_already_configured_host(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test that the same host and port is only configured once."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_user_flow_already_configured_serial(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that a known device at a new address updates the entry."""
    mock_config_entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**USER_INPUT, CONF_HOST: "192.0.2.2", CONF_PORT: 2222}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": AUTH_PASSWORD}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: PASSWORD}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert mock_config_entry.data[CONF_HOST] == "192.0.2.2"
    assert mock_config_entry.data[CONF_PORT] == 2222


async def _start_reauth_flow(
    hass: HomeAssistant, entry: MockConfigEntry, method: str
) -> FlowResult:
    """Start a reauth flow and choose a login method."""
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["type"] is FlowResultType.MENU
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": method}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == method
    return result


async def test_reauth_password(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_client_class: MagicMock,
    mock_config_entry: MockConfigEntry,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test reauthentication with a new password and username."""
    result = await _start_reauth_flow(hass, mock_config_entry, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: "admin", CONF_PASSWORD: "new-password"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert mock_config_entry.data == {
        **ENTRY_DATA,
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "new-password",
    }
    # The stored host key is used to verify the device.
    assert mock_client.async_probe.await_count == 1
    assert mock_client_class.call_args.kwargs["host_key"] == HOST_KEY
    # The entry is reloaded with the new credentials.
    assert len(mock_setup_entry.mock_calls) == 1


@pytest.mark.parametrize(
    ("method", "user_input", "expected"),
    [
        (
            AUTH_PRIVATE_KEY,
            {CONF_PRIVATE_KEY: PRIVATE_KEY},
            {CONF_PRIVATE_KEY: PRIVATE_KEY},
        ),
        (
            AUTH_KEY_FILE,
            {CONF_KEY_FILE: "/config/.ssh/id_ecdsa", CONF_PASSPHRASE: "secret"},
            {CONF_KEY_FILE: "/config/.ssh/id_ecdsa", CONF_PASSPHRASE: "secret"},
        ),
    ],
)
async def test_reauth_switch_to_key(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_load_private_key: MagicMock,
    mock_config_entry: MockConfigEntry,
    method: str,
    user_input: dict[str, str],
    expected: dict[str, str],
) -> None:
    """Test that switching to key login removes the password."""
    result = await _start_reauth_flow(hass, mock_config_entry, method)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: USERNAME, **user_input}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert mock_config_entry.data == {
        CONF_HOST: HOST,
        CONF_PORT: 22,
        CONF_USERNAME: USERNAME,
        CONF_AUTH_METHOD: method,
        CONF_HOST_KEY: HOST_KEY,
        CONF_LEGACY_ALGORITHMS: False,
        **expected,
    }


async def test_reauth_host_key_mismatch(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that reauthentication checks the stored host key."""
    mock_client.async_probe.side_effect = CiscoHostKeyMismatchError(
        "SHA256:stored", "SHA256:other"
    )
    result = await _start_reauth_flow(hass, mock_config_entry, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: USERNAME, CONF_PASSWORD: "new"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "host_key_mismatch"}

    mock_client.async_probe.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: USERNAME, CONF_PASSWORD: "new"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert mock_config_entry.data[CONF_PASSWORD] == "new"


async def test_reauth_wrong_device(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that reauthentication aborts for another device."""
    mock_client.async_probe.return_value = (
        replace(DEVICE_INFO, serial="FOC0000X000"),
        [],
    )
    result = await _start_reauth_flow(hass, mock_config_entry, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: USERNAME, CONF_PASSWORD: "new"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "wrong_device"
    assert mock_config_entry.data[CONF_PASSWORD] == PASSWORD


async def test_reauth_entry_without_unique_id(
    hass: HomeAssistant, mock_client: MagicMock
) -> None:
    """Test reauthentication of an entry for a device without serial number."""
    entry = MockConfigEntry(domain=DOMAIN, data=dict(ENTRY_DATA), unique_id=None)
    result = await _start_reauth_flow(hass, entry, AUTH_PASSWORD)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_USERNAME: USERNAME, CONF_PASSWORD: "new"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert entry.unique_id is None


async def _start_reconfigure_flow(
    hass: HomeAssistant, entry: MockConfigEntry
) -> FlowResult:
    """Start a reconfigure flow."""
    entry.add_to_hass(hass)
    result = await entry.start_reconfigure_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    return result


async def test_reconfigure_unchanged_host_key(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_client_class: MagicMock,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test reconfiguring the address of the device."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={**ENTRY_DATA, CONF_LEGACY_ALGORITHMS: True},
        unique_id=SERIAL,
    )
    result = await _start_reconfigure_flow(hass, entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.5 ", CONF_PORT: 22}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data == {**ENTRY_DATA, CONF_HOST: "192.0.2.5"}
    # The stored host key is pinned, so the device must prove it has that
    # key before the credentials are sent. Legacy algorithms are detected
    # again, so they are dropped after a software upgrade.
    mock_client_class.assert_called_once()
    assert mock_client_class.call_args.args[0] == "192.0.2.5"
    assert mock_client_class.call_args.kwargs["host_key"] == HOST_KEY
    assert mock_client_class.call_args.kwargs["legacy_algorithms"] is False
    mock_client.async_probe.assert_awaited_once()
    mock_client.async_fetch_host_key.assert_not_called()
    assert len(mock_setup_entry.mock_calls) == 1


async def test_reconfigure_changed_host_key(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_client_class: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test that a changed host key is confirmed before logging in."""
    mock_client.async_probe.side_effect = [
        CiscoHostKeyMismatchError("SHA256:toredkey", "SHA256:QCnewkey"),
        (DEVICE_INFO, []),
    ]
    mock_client.presented_host_key = NEW_HOST_KEY
    result = await _start_reconfigure_flow(hass, mock_config_entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: 22}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure_confirm_host_key"
    assert result["errors"] == {}
    assert result["description_placeholders"] == {
        "host": HOST,
        "old_fingerprint": "SHA256:toredkey",
        "new_fingerprint": "SHA256:QCnewkey",
    }
    assert mock_config_entry.data[CONF_HOST_KEY] == HOST_KEY
    # Only the connection with the stored key pinned was made so far.
    assert mock_client_class.call_count == 1
    assert mock_client_class.call_args.kwargs["host_key"] == HOST_KEY

    mock_client.legacy_algorithms = True
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert mock_config_entry.data[CONF_HOST_KEY] == NEW_HOST_KEY
    assert mock_config_entry.data[CONF_LEGACY_ALGORITHMS] is True
    # After the confirmation, the login pins the confirmed key.
    assert mock_client_class.call_count == 2
    assert mock_client_class.call_args.kwargs["host_key"] == NEW_HOST_KEY


async def test_reconfigure_confirm_errors(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that a failed login after the confirmation can be retried."""
    mock_client.async_probe.side_effect = [
        CiscoHostKeyMismatchError("SHA256:toredkey", "SHA256:QCnewkey"),
        CiscoAuthenticationError,
        (DEVICE_INFO, []),
    ]
    mock_client.presented_host_key = NEW_HOST_KEY
    result = await _start_reconfigure_flow(hass, mock_config_entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: 22}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure_confirm_host_key"
    assert result["errors"] == {"base": "invalid_auth"}
    assert result["description_placeholders"]["new_fingerprint"] == "SHA256:QCnewkey"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert mock_config_entry.data[CONF_HOST_KEY] == NEW_HOST_KEY


async def test_reconfigure_without_stored_host_key(
    hass: HomeAssistant, mock_client: MagicMock, mock_client_class: MagicMock
) -> None:
    """Test that the host key is fetched without logging in if none is stored."""
    entry = MockConfigEntry(
        domain=DOMAIN, data={**ENTRY_DATA, CONF_HOST_KEY: None}, unique_id=SERIAL
    )
    mock_client.async_fetch_host_key.return_value = NEW_HOST_KEY
    mock_client.presented_host_key = NEW_HOST_KEY
    result = await _start_reconfigure_flow(hass, entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: 22}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure_confirm_host_key"
    assert result["description_placeholders"]["old_fingerprint"] == "none"
    assert result["description_placeholders"]["new_fingerprint"] == "SHA256:QCnewkey"
    mock_client.async_probe.assert_not_called()

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data[CONF_HOST_KEY] == NEW_HOST_KEY
    assert mock_client_class.call_args.kwargs["host_key"] == NEW_HOST_KEY


async def test_reconfigure_mismatch_without_presented_key(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test a host key mismatch when the client reports no presented key."""
    mock_client.async_probe.side_effect = CiscoHostKeyMismatchError(
        "SHA256:toredkey", None
    )
    mock_client.presented_host_key = None
    result = await _start_reconfigure_flow(hass, mock_config_entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: 22}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert result["errors"] == {"base": "host_key_mismatch"}


@pytest.mark.parametrize("confirm", [False, True])
async def test_reconfigure_wrong_device(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_config_entry: MockConfigEntry,
    confirm: bool,
) -> None:
    """Test that reconfiguring to another device aborts."""
    other_device = (replace(DEVICE_INFO, serial="FOC0000X000"), [])
    if confirm:
        mock_client.async_probe.side_effect = [
            CiscoHostKeyMismatchError("SHA256:toredkey", "SHA256:QCnewkey"),
            other_device,
        ]
        mock_client.presented_host_key = NEW_HOST_KEY
    else:
        mock_client.async_probe.return_value = other_device
    result = await _start_reconfigure_flow(hass, mock_config_entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.9", CONF_PORT: 22}
    )
    if confirm:
        assert result["step_id"] == "reconfigure_confirm_host_key"
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "wrong_device"
    assert mock_config_entry.data[CONF_HOST] == HOST
    assert mock_config_entry.data[CONF_HOST_KEY] == HOST_KEY


async def test_reconfigure_already_configured(
    hass: HomeAssistant, mock_client: MagicMock, mock_config_entry: MockConfigEntry
) -> None:
    """Test that the address of another entry cannot be used."""
    MockConfigEntry(
        domain=DOMAIN,
        data={**ENTRY_DATA, CONF_HOST: "192.0.2.9"},
        unique_id="FOC0000X000",
    ).add_to_hass(hass)
    result = await _start_reconfigure_flow(hass, mock_config_entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.9", CONF_PORT: 22}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reconfigure_errors(
    hass: HomeAssistant,
    mock_client: MagicMock,
    mock_load_private_key: MagicMock,
) -> None:
    """Test that reconfigure shows key errors as general errors and recovers."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            **{k: v for k, v in ENTRY_DATA.items() if k != CONF_PASSWORD},
            CONF_AUTH_METHOD: AUTH_KEY_FILE,
            CONF_KEY_FILE: "/config/.ssh/id_rsa",
        },
        unique_id=SERIAL,
    )
    mock_load_private_key.side_effect = CiscoKeyFileNotFoundError
    result = await _start_reconfigure_flow(hass, entry)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.7", CONF_PORT: 2222}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert result["errors"] == {"base": "key_file_not_found"}

    mock_load_private_key.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: "192.0.2.7", CONF_PORT: 2222}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data[CONF_HOST] == "192.0.2.7"
    assert entry.data[CONF_PORT] == 2222


async def test_options_flow(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test changing the options."""
    links = {MAC_1: "device-id"}
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        options={**mock_config_entry.options, CONF_DEVICE_LINKS: links},
    )
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    assert result["type"] is FlowResultType.MENU
    assert result["step_id"] == "init"
    assert result["menu_options"] == ["settings", "link_device", "unlink_device"]

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {"next_step_id": "settings"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "settings"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_CONSIDER_HOME: 300.0, CONF_MAX_ARP_AGE: 2.0}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    # The links are kept.
    assert mock_config_entry.options == {
        CONF_CONSIDER_HOME: 300,
        CONF_MAX_ARP_AGE: 2,
        CONF_DEVICE_LINKS: links,
    }
    assert isinstance(mock_config_entry.options[CONF_CONSIDER_HOME], int)

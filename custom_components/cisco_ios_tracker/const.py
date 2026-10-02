"""Constants for the Cisco IOS Tracker integration."""

from datetime import timedelta
import logging
from typing import Final

DOMAIN: Final = "cisco_ios_tracker"
LOGGER = logging.getLogger(__package__)

CONF_AUTH_METHOD: Final = "auth_method"
AUTH_PASSWORD: Final = "password"
AUTH_PRIVATE_KEY: Final = "private_key"
AUTH_KEY_FILE: Final = "key_file"

CONF_PRIVATE_KEY: Final = "private_key"
CONF_KEY_FILE: Final = "key_file"
CONF_PASSPHRASE: Final = "passphrase"
CONF_HOST_KEY: Final = "host_key"
CONF_LEGACY_ALGORITHMS: Final = "legacy_algorithms"

CONF_MAX_ARP_AGE: Final = "max_arp_age"
DEFAULT_MAX_ARP_AGE: Final = 0
MAX_ARP_AGE_LIMIT: Final = 240
MAX_CONSIDER_HOME: Final = 900

DEFAULT_PORT: Final = 22

# Fixed polling interval; ARP ages only have a resolution of one minute.
SCAN_INTERVAL: Final = timedelta(seconds=30)

ATTR_INTERFACE: Final = "interface"

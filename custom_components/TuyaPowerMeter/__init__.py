"""Support for Tuya Power Meter devices."""

from __future__ import annotations

import logging
import threading
import time

from .tinytuya import ( TuyaPowerMeter )

import voluptuous as vol

from .const import (
    DOMAIN,
    DPS_2_MONITOR,
    UPDATE_TOPICS,
    OFFLINE_TOPIC
)
from homeassistant.const import (
    CONF_HOST,
    CONF_ID,
    CONF_API_KEY,
    EVENT_HOMEASSISTANT_START,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import Event, HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.dispatcher import dispatcher_send
from homeassistant.helpers.typing import ConfigType

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_HOST): cv.string,
                vol.Required(CONF_ID): cv.string,
                vol.Required(CONF_API_KEY): cv.string
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


def setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up TuyaPowerMeter platform."""
    host = config[DOMAIN][CONF_HOST]
    dev_id = config[DOMAIN][CONF_ID]
    local_key = config[DOMAIN][CONF_API_KEY]

    processor = TuyaPowerMeterProcessor(hass, host, dev_id, local_key)
    hass.data[DOMAIN] = processor
    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, processor.start_listen)
    hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, processor.shutdown)
    _LOGGER.debug("TuyaPowerMeterProcessor %s:%i initialized", host, dev_id)
    return True


class TuyaPowerMeterProcessor(threading.Thread):
    """TuyaPowerMeter event processor thread."""

    KEEPALIVE_TIMER = 15
    OFFLINE_TIMER = 5 * 60

    def __init__(self, hass: HomeAssistant, host: str, dev_id: str, local_key: str) -> None:
        """Initialize the data object."""
        super().__init__(daemon=True)
        self._hass = hass
        self._host = host
        self._dev_id = dev_id
        self._local_key = local_key
        self._shutdown = False
        self._stored_dps = {}

    def start_listen(self, event: Event) -> None:
        """Start event-processing thread."""
        _LOGGER.debug("Event processing thread started")
        self.start()

    def shutdown(self, event: Event) -> None:
        """Signal shutdown of processing event."""
        _LOGGER.debug("Event processing signaled exit")
        self._shutdown = True

    def run(self) -> None:
        """Event thread."""

        self._device = TuyaPowerMeter(self._dev_id, self._host, self._local_key, persist=True)   #d = tinytuya.TuyaPowerMeter('bf45e66d762501adaftyu8', '192.168.0.101', "qjOg:<Pt'J3QgX9[", persist=True)
        self._device._get_socket(False)
        self._heartbeat_time = time.time() + self.KEEPALIVE_TIMER
        self._update_time = time.time() + self.OFFLINE_TIMER
        while True:
            if self._shutdown:
                return
            
            if time.time() >= self._heartbeat_time:
                # send a keep-alive
                data = self._device.heartbeat(nowait=False)
                self._heartbeat_time = time.time() + self.KEEPALIVE_TIMER
            else:
                # no need to send anything, just listen for an asynchronous update
                data = self._device.receive()

            if data and 'Err' in data:
                # rate limit retries so we don't hammer the device
                time.sleep(5)
            elif data and 'data' in data and 'dps' in data['data']:
                dpsl = data['data']['dps']
                dpsid = list(dpsl.keys())
                for dp in DPS_2_MONITOR:
                    if dp in dpsid:
                        self._stored_dps[dp] = dpsl[dp]
                        self._update_time = time.time() + self.OFFLINE_TIMER
                        dispatcher_send(self._hass, UPDATE_TOPICS[dp])

            if time.time() >= self._update_time:
                dispatcher_send(self._hass, OFFLINE_TOPIC)

    @property
    def dps(self):
        return self._stored_dps

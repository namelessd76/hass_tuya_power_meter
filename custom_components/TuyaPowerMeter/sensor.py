"""Support for Tuya Power Meter sensors."""

from __future__ import annotations

import base64

from dataclasses import dataclass

import voluptuous as vol

from homeassistant.components.sensor import (
    PLATFORM_SCHEMA as SENSOR_PLATFORM_SCHEMA,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
)
from homeassistant.const import (
    CONF_MONITORED_CONDITIONS,
    PERCENTAGE,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant, callback
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from . import DOMAIN, UPDATE_TOPICS, TuyaPowerMeterProcessor


@dataclass(frozen=True)
class TPMSensorEntityDescription(SensorEntityDescription):
    """Describes AquaLogic sensor entity."""

    dpid: str | None = None
    offset: int | None = None

# keys correspond to property names in aqualogic.core.AquaLogic
SENSOR_TYPES: tuple[TPMSensorEntityDescription, ...] = (
    TPMSensorEntityDescription(
        key="tuya_pm_phase_a",
        name="Tuya Power Meter Phase A power",
        dpid="101",
        offset=8,
        unit_of_measurement = UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
    ),
    TPMSensorEntityDescription(
        key="tuya_pm_phase_b",
        name="Tuya Power Meter Phase B power",
        dpid="102",
        offset=8,
        unit_of_measurement = UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
    ),
    TPMSensorEntityDescription(
        key="tuya_pm_phase_c",
        name="Tuya Power Meter Phase C power",
        dpid="103",
        offset=8,
        unit_of_measurement = UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
    ),
    TPMSensorEntityDescription(
        key="tuya_pm_ch1_power",
        name="Tuya Power Meter Ch 1 power",
        dpid="105",
        offset=2,
        unit_of_measurement = UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
    ),
    TPMSensorEntityDescription(
        key="tuya_pm_ch2_power",
        name="Tuya Power Meter Ch 2 power",
        dpid="105",
        offset=7,
        unit_of_measurement = UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
    ),
)

SENSOR_KEYS: list[str] = [desc.key for desc in SENSOR_TYPES]

PLATFORM_SCHEMA = SENSOR_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_MONITORED_CONDITIONS, default=SENSOR_KEYS): vol.All(
            cv.ensure_list, [vol.In(SENSOR_KEYS)]
        )
    }
)


async def async_setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    async_add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    """Set up the sensor platform."""
    processor: TuyaPowerMeterProcessor = hass.data[DOMAIN]
    monitored_conditions = config[CONF_MONITORED_CONDITIONS]

    entities = [
        TPMSensor(processor, description)
        for description in SENSOR_TYPES
        if description.key in monitored_conditions
    ]

    async_add_entities(entities)


class TPMSensor(SensorEntity):
    """Sensor implementation for the TPM component."""

    entity_description: TPMSensorEntityDescription
    _attr_should_poll = False

    def __init__(
        self,
        processor: TuyaPowerMeterProcessor,
        description: TPMSensorEntityDescription,
    ) -> None:
        """Initialize sensor."""
        self.entity_description = description
        self._processor = processor
        self._attr_name = f"{description.name}"

    async def async_added_to_hass(self) -> None:
        """Register callbacks."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, UPDATE_TOPICS[self.entity_description.dpid], self.async_update_callback
            )
        )

    @callback
    def async_update_callback(self) -> None:
        """Update callback."""
        if (dps := self._processor.dps) is not None and dps[self.entity_description.dpid] is not None:
            b64str = dps[self.entity_description.dpid]
            offset = self.entity_description.offset
            self._attr_native_value = int.from_bytes(base64.b64decode(b64str)[offset:offset+4], byteorder="little", signed=False)
            self.async_write_ha_state()

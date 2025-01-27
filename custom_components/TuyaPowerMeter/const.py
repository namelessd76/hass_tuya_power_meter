DOMAIN = "TuyaPowerMonitor"
DPS_2_MONITOR = ('101', '102', '103', '105')

UPDATE_TOPICS: dict[str:str] = { t : f"{DOMAIN}_ch_{t}_update" for t in DPS_2_MONITOR }

OFFLINE_TOPIC = f"{DOMAIN}_offline"

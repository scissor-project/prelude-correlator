from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
from preludecorrelator.context import Context
from preludecorrelator import log

ID_PORT_SCAN_DETECTED = "D1"
ID_PORT_SCAN_MONITORING = "D0"

PORT_SCAN_DETECTED = "Port Scan Detected"
PORT_SCAN_MONITORING = "Port Scan Monitoring"

EVENT_ID = "event.id"

IP_SRC = "event.network.ip_src"
IP_DST = "event.network.ip_dst"

EXPIRATION = 30
THRESHOLD = 5

logger = log.getLogger(__name__)

class AlwaysPlugin(Plugin):

    def __init__(self, env):
        logger.info("Loading %s", AlwaysPlugin)

    def _PortScan(self, idmef):

        source = self._getDataByMeaning(idmef, IP_SRC)
        dest = self._getDataByMeaning(idmef, IP_DST)

        ctx = Context(("PORT_SCAN_STORM", source, dest), \
        {}, \
        update = True, \
        idmef = idmef)
        ctx.set("alert.correlation_alert.name", "Always Correlation")
        ctx.set("alert.classification.text", "AlwaysCorrelation")
        ctx.set("alert.assessment.impact.severity", "info")
        ctx.alert()
        ctx.destroy()

    def _getDataByMeaning(self,idmef,meaning):
        meanings = idmef.get("alert.additional_data(*).meaning")
        m_len = len(meanings)
        for m in range(m_len):
            if meanings[m] == meaning:
                to_search = "alert.additional_data({}).data".format(m)
                d = idmef.get(to_search)
                return d
        return None

    def run(self, idmef):
        ev_id = self._getDataByMeaning(idmef,EVENT_ID)
        if ev_id is None:
        	return
        if  ev_id == ID_PORT_SCAN_DETECTED:
        	self._PortScan(idmef)

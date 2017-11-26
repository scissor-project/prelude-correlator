from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.contexthelpers.WeakWindowHelper import WeakWindowHelper
from preludecorrelator import log

LEVEL = 2
NUMBER = 1
context_id = "IdmefLackPlugin"
logger = log.getLogger(__name__)

class ExtendedWindowHelper(WeakWindowHelper):

    def corrConditions(self):
        alert_received = self.countAlertsReceivedInWindow()
        return alert_received >= self._ctx.getOptions()["threshold"]

class IdmefLackPlugin(Plugin):

    def __init__(self, env):
        super(AdvancedLevelCorrelator, self).__init__(env)
        self.processIdmefLack = True
        logger.info("Loading %s", self.__class__.__name__)

    def run(self, idmef):
        corr_name = None
        if idmef is not None:
            corr_name = idmef.get("alert.correlation_alert.name")
        # We are not interested in simple alerts
        if corr_name is None:
         return
        # We only want correlation alerts from exactly the layer below
        if corr_name != "Layer {} Correlation".format(LEVEL - 1):
         return

        correlator = self.getContextHelper(context_id,ExtendedWindowHelper)


        if correlator.isEmpty():

            options = { "expire": 30, "threshold": 5 ,"alert_on_expire": False, "window": 30, "reset_ctx_on_window_expiration": True, "check_burst": False, "check_on_window_expiration": True }
            initial_attrs = {"alert.correlation_alert.name": "Layer {} Correlation".format(LEVEL), "alert.classification.text": "MyFirstIdmefLackScan{}".format(NUMBER), "alert.assessment.impact.severity": "high"}

            correlator.bindContext(options, initial_attrs)

        if correlator.checkCorrelation():
          correlator.generateCorrelationAlert(send=True, destroy_ctx=False)

        if idmef.get("alert.correlation_alert.name") != "My Classification":
            correlator.processIdmef(idmef=idmef, addAlertReference=True)

from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.contexthelpers.StrongWindowHelper import StrongWindowHelper
from preludecorrelator import log


LEVEL = 1
NUMBER = 1
#The context should be unique, it's better add the class name since we know it's unique
context_id = "{}Layer{}Correlation{}".format("EntryLevelCorrelator", LEVEL, NUMBER)
logger = log.getLogger(__name__)

class ExtendedStrongWindowHelper(StrongWindowHelper):

    def corrConditions(self):
        counter = len(self.getAlertsReceivedInWindow())
        return counter >= self._options["threshold"]

class EntryLevelCorrelator(Plugin):

    def __init__(self, env):
        super(EntryLevelCorrelator, self).__init__(env)
        logger.info("Loading %s", self.__class__.__name__)

    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef.get("alert.correlation_alert.name") is not None:
         return

        correlator = self.getContextHelper(context_id,ExtendedStrongWindowHelper)

        if correlator.isEmpty():
         options = { "expire": 5, "threshold": 5 ,"alert_on_expire": False, "window": 5}
         initial_attrs = {"alert.correlation_alert.name": "Layer {} Correlation".format(LEVEL),"alert.classification.text": "MyFirstEntryLevelScan{}".format(NUMBER),"alert.assessment.impact.severity": "high"}

         #Create a context that:
         #- expires after 5 seconds of inactivity
         #- generates a correlation alert after 5 msg received
         #- checks for the threshold in a window of 5 seconds
         correlator.bindContext(options, initial_attrs)

        correlator.processIdmef(idmef=idmef, addAlertReference=True)

        if correlator.checkCorrelation():
          correlator.generateCorrelationAlert(send=True, destroy_ctx=False)

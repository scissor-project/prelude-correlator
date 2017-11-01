from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
from preludecorrelator.context import Context
from preludecorrelator.context import search as context_search
from preludecorrelator.windows.StrongWindowHelper import StrongWindowHelper

LEVEL = 1
NUMBER = 3
print("{}, {} Level Correlation{}".format("EntryLevelCorrelator", LEVEL, NUMBER))
#The context should be unique, it's better add the class name since we know it's unique
context_id = "{}Layer{}Correlation{}".format("EntryLevelCorrelator", LEVEL, NUMBER)

class TwoCountersWindowHelper(StrongWindowHelper):

    def corrConditions(self, params={}):
        counter = len(self.getAlertsReceivedInWindow())
        print("I am {} : reaching threshold with counter {}".format(self._name, counter))
        return counter >= self._options["threshold"]

class EntryLevelCorrelator13(Plugin):
    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef.get("alert.correlation_alert.name") is not None:
         return

        window = self.getWindowHelper(TwoCountersWindowHelper, context_id)
        if window.isEmpty():
         options = { "expire": 5, "threshold": 5 ,"alert_on_expire": False }
         initial_attrs = {"alert.correlation_alert.name": "Layer {} Correlation".format(LEVEL),"alert.classification.text": "MyFirstEntryLevelScan{}".format(NUMBER),"alert.assessment.impact.severity": "high"}

         #Create a context that:
         #- expires after 1 seconds of inactivity
         #- generates a correlation alert after 5 msg received
         #- checks for the threshold in a window of 1 second, if the window expires the correlation period restarts
         window.bindContext(options, initial_attrs)

        window.addIdmef(idmef)

        if window.checkCorrelationWindow():
          print("Hello from %s" % self.__class__.__name__)
          print(window.getIdmefField("alert.classification.text"))
          window.generateCorrelationAlert()
          print("%s Alert finished" % self.__class__.__name__)

from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
from preludecorrelator.context import Context
from preludecorrelator.context import search as ctx_search
from preludecorrelator.windows.StrongWindowHelper import StrongWindowHelper

LEVEL = 2
NUMBER = 0
print("{}, Layer {} Correlation{}".format("AdvancedLevelCorrelator", LEVEL))
context_id = "{}Layer{}Correlation{}".format("AdvancedLevelCorrelator", LEVEL)


class AdvancedLevelCorrelator(Plugin):

    def run(self, idmef):
        corr_name = idmef.get("alert.correlation_alert.name")
        # We are not interested in simple alerts
        if corr_name is None:
         return
        # We do not want correlation alerts from upper layers
        if corr_name != "Layer {} Correlation".format(LEVEL - 1):
         return

        print("{} received correlation".format(self.__class__.__name__))
        print(corr_name)
        print(idmef)

        window = self.getWindowHelper(StrongWindowHelper, context_id)

        if window.isEmpty():
            options = { "expire": 1, "threshold": 2 ,"alert_on_expire": False }
            initial_attrs = {"alert.correlation_alert.name": "Layer {} Correlation".format(LEVEL),
            "alert.classification.text": "MyFirstAdvancedLevelScan{}".format(NUMBER),
            "alert.assessment.impact.severity": "high"}

            window.bindContext(options, initial_attrs)


        window.addIdmef(idmef)

        #if ctx.getWindowHelper().checkCorrelationWindow():
        if window.checkCorrelationWindow():
          print("Hello from %s" % self.__class__.__name__)
          print(window.getIdmefField("alert.classification.text"))
          window.generateCorrelationAlert()
          print("Alert Finished %s" % self.__class__.__name__)

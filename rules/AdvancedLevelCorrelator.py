from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
from preludecorrelator.context import Context
from preludecorrelator.context import search as context_search
import time

LEVEL = 2
print("{}, Layer {} Correlation".format("AdvancedLevelCorrelator", LEVEL))
context_id = "{}Layer{}Correlation".format("AdvancedLevelCorrelator", LEVEL)
time_now = time.time()

analyzerid = ''
#saved_idmef = None

class AdvancedLevelCorrelator(Plugin):

    def save_msg(self, idmef):
     global analyzerid
     #saving analyzerid
     analyzerid = idmef.get("alert.analyzer(0).analyzerid")

    def restore_msg(self, idmef):
     #restoring analyzerid
     idmef.set("alert.analyzer(0).analyzerid", analyzerid)


    def run(self, idmef):
        corr_name = idmef.get("alert.correlation_alert.name")
        if corr_name is None:
         return
        if corr_name != "Layer {} Correlation".format(LEVEL - 1):
         return

        print("{} received correlation".format(self.__class__.__name__))
        print(corr_name)

        global time_now
        if context_search( context_id) is None:
         time_now = time.time()

        ctx = Context( context_id, { "expire": 5, "threshold": 2, "window" : 1 ,"alert_on_expire": False }, update = True, idmef=idmef)

        if ctx.getUpdateCount() == 0:
         #ctx.set("alert.correlation_alert.name", "Layer 2 Correlation4")
         ctx.set("alert.correlation_alert.name", "Layer 2 Correlation")
         ctx.set("alert.classification.text", "MyFirstAdvancedLevelScan")
         ctx.set("alert.assessment.impact.severity", "high")
        now = time.time()

        if now - time_now < ctx.getOptions()["window"]:
         # remember that when we have a threshold of x reached, we have updated the context exactly x - 1 times
         if ctx.getUpdateCount() >= ctx.getOptions()["threshold"] - 1:
          print("Hello from %s" % self.__class__.__name__)
          print(ctx.get("alert.classification.text"))
          #print(idmef)
          #reset counter to a new correlation period
          #time_now = time.time()
          #ctx.resetCount()
          ctx_copy = ctx
          ctx.destroy()
          self.save_msg(idmef)
          ctx_copy.alert()
          self.restore_msg(idmef)
          #ctx.alert()
          print("Alert Finished MyFourthPlugin")
          #print(idmef)
          del ctx_copy
        else:
          time_now = time.time()

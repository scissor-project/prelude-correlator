from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.idmef import IDMEF
from preludecorrelator.context import Context
from preludecorrelator.context import search as context_search
import time

LEVEL = 1
print("{}, {} Level Correlation".format("EntryLevelCorrelator", LEVEL))
#The context should be unique, it's better add the class name since we know it's unique
context_id = "{}Layer{}Correlation".format("EntryLevelCorrelator", LEVEL)
time_now = time.time()

class EntryLevelCorrelator(Plugin):
    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef.get("alert.correlation_alert.name") is not None:
         return

        global time_now
        if context_search(context_id) is None:
         time_now = time.time()
        #Create a context that:
        #- expires after 5 seconds of inactivity
        #- generates a correlation alert after 5 msg received
        #- checks for the threshold in a window of 1 second, if the window expires the correlation period restarts
        ctx = Context(context_id, { "expire": 5, "threshold": 5, "window" : 1 ,"alert_on_expire": False }, update = True, idmef=idmef)
        if ctx.getUpdateCount() == 0:
         ctx.set("alert.correlation_alert.name", "Layer {} Correlation".format(LEVEL))
         ctx.set("alert.classification.text", "MyFirstEntryLevelScan")
         ctx.set("alert.assessment.impact.severity", "high")
        now = time.time()

        if now - time_now < ctx.getOptions()["window"]:
         # remember that when we have a threshold of x reached, we have updated the context exactly x - 1 times
         if ctx.getUpdateCount() >= ctx.getOptions()["threshold"] - 1:
          print("Hello from {}".format(self.__class__.__name__))
          print(ctx.get("alert.classification.text"))
          #reset counter to a new correlation period, but maybe not necessary because when a ctx is destroyed the counter is reset
          #time_now = time.time()
          ctx_copy = ctx
          ctx.destroy()
          ctx_copy.alert()
          print("{} Alert finished".format(self.__class__.__name__))
          #print(idmef)
          del ctx_copy
        else:
          time_now = time.time()

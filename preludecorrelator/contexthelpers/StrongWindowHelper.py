import time
from ..contexthelper import ContextHelper
from ..context import Context
from ..idmef import AnalyzerContents
from ..context import search as ctx_search


class StrongWindowHelper(ContextHelper):


    def __init__(self, name):
        super(StrongWindowHelper, self).__init__(name)
        self._timestamps = []

    def isEmpty(self):
        #return len(self._timestamps) == 0
        return ctx_search(self._name) is None

    def bindContext(self, options, initial_attrs):
        res = ctx_search(self._name)
        if res is None:
         self._ctx = Context(self._name, options, update=False)
         self._timestamps = []
        else:
         self._ctx = res
        self._options = options
        self.initialAttrs = initial_attrs
        for key,value in self.initialAttrs.iteritems():
         self._ctx.set(key,value)

    def unbindContext(self):
        self._ctx = None

    def getIdmefField(self, idmef_field):
        #return self._initialAttrs[idmef_field]
        return self._ctx.get(idmef_field)

    def setIdmefField(self, idmef_field, value):
        #self._initialAttrs[idmef_field] = value
        self._ctx.set(idmef_field, value)

    def rst(self):
        self._timestamps = []

    def processIdmef(self, idmef, addAlertReference=True):
        self._ctx.update()
        now = time.time()
        len_timestamps = len(self._timestamps)
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] >= self._ctx.getOptions()["window"]:
               #print("I am {} : del timestamps[{}]".format(self._name, t))
               #self._timestamps[t][2].restoreAnalyzerContents(self._timestamps[t][1])
               #self.onIdmefRemoval(self._timestamps[t][1])
               self._timestamps.pop(t)

        tmp_analyzer = AnalyzerContents()
        tmp_analyzer.saveAnalyzerContents(idmef)
        self._timestamps.append([now, idmef, tmp_analyzer, addAlertReference])
        #self.onIdmefAddition(idmef)

    def corrConditions(self):
        counter = len(self.getAlertsReceivedInWindow())
        #print("I am {} : reaching threshold with counter {}".format(self._name, counter))
        return counter >= self._ctx.getOptions()["threshold"]

    def getAlertsReceivedInWindow(self):
        now = time.time()
        len_timestamps = len(self._timestamps)
        #print("I am {} : len timestamps {}".format(self._name, len_timestamps))
        alerts = []
        for t in range(len_timestamps-1,-1,-1):
            #if now - self._timestamps[t][0] < self._options["expire"]:
            if now - self._timestamps[t][0] < self._ctx.getOptions()["window"]:
             #print("I am {} : timestamps[{}] < {}".format(self._name, t, self._ctx.getOptions()["window"]))
             self._timestamps[t][2].restoreAnalyzerContents(self._timestamps[t][1])

             alerts.append(self._timestamps[t][1])

        return alerts

    def checkCorrelation(self):
        return self._checkCorrelationWindow()

    def _checkCorrelationWindow(self):
     if self.corrConditions():
         #print("I am {} : threshold reached".format(self._name))

         alerts = self.getAlertsReceivedInWindow()
         for a in reversed(alerts):
             self._ctx.update(options=self._ctx.getOptions(), idmef=a, timer_rst=False)
         return True
     return False

    def generateCorrelationAlert(self, send=True, destroy_ctx=False):
        tmp_ctx = ctx_search(self._name)
        if destroy_ctx:
         self._ctx.destroy()
         self.unbindContext()
        self.rst()
        if send:
            tmp_ctx.alert()
        else:
            return tmp_ctx

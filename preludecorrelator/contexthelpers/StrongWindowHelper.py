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
        return len(self._timestamps) == 0
'''
    def bindContext(self, options, initial_attrs):
        self._options = options
        self._initialAttrs = initial_attrs
'''
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
        return self._initialAttrs[idmef_field]

    def setIdmefField(self, idmef_field, value):
        self._initialAttrs[idmef_field] = value

    def rst(self):
        self._timestamps = []

    def update(self, idmef=None):
        now = time.time()
        len_timestamps = len(self._timestamps)
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] >= self._options["expire"]:
               print("I am {} : del timestamps[{}]".format(self._name, t))
               self._timestamps.pop(t)
        tmp_analyzer = None
        if idmef is not None:
            tmp_analyzer = AnalyzerContents()
            tmp_analyzer.saveAnalyzerContents(idmef)

        self._timestamps.append([time.time(),idmef, tmp_analyzer])

    def addIdmef(self, idmef):
        now = time.time()
        len_timestamps = len(self._timestamps)
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] >= self._options["expire"]:
               print("I am {} : del timestamps[{}]".format(self._name, t))
               self._timestamps.pop(t)
        tmp_analyzer = AnalyzerContents()
        tmp_analyzer.saveAnalyzerContents(idmef)
        self._timestamps.append([time.time(),idmef, tmp_analyzer])

    def corrConditions(self):
        counter = len(self.getAlertsReceivedInWindow())
        print("I am {} : reaching threshold with counter {}".format(self._name, counter))
        return counter >= self._options["threshold"]

    def getAlertsReceivedInWindow(self):
        now = time.time()
        len_timestamps = len(self._timestamps)
        print("I am {} : len timestamps {}".format(self._name, len_timestamps))
        alerts = []
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] < self._options["expire"]:
             print("I am {} : timestamps[{}] < {}".format(self._name, t, self._options["expire"]))
             self._timestamps[t][2].restoreAnalyzerContents(self._timestamps[t][1])

             alerts.append(self._timestamps[t][1])

        return alerts

    def checkCorrelation(self):
        return self._checkCorrelationWindow()

    def _checkCorrelationWindow(self):
     if self.corrConditions():
         print("I am {} : threshold reached".format(self._name))
         self._ctx = Context(self._name, self._options, self._initialAttrs)
         for key, value in self._initialAttrs.iteritems():
             self._ctx.set(key,value)

         alerts = self.getAlertsReceivedInWindow()
         for a in reversed(alerts):
             self._ctx.update(options=self._options, idmef=a, timer_rst=False)
         return True
     return False

    def generateCorrelationAlert(self, send=True):
        tmp_ctx = ctx_search(self._name)
        self._ctx.destroy()
        self.unbindContext()
        self.rst()
        if send:
            tmp_ctx.alert()
        else:
            return tmp_ctx

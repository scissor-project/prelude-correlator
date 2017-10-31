import time
from ..windowhelper import WindowHelper
from ..context import Context
from ..idmef import AnalyzerContents
from ..context import search as ctx_search


class StrongWindowHelper(WindowHelper):


    def __init__(self, name):
        super(StrongWindowHelper, self).__init__(name)
        self._timestamps = []

    def isEmpty(self):
        return len(self._timestamps) == 0

    def bindContext(self, options, initial_attrs):
        self._options = options
        self._initialAttrs = initial_attrs

    def unbindContext(self):
        self._ctx = None

    def getIdmefField(self, idmef_field):
        return self.initialAttrs[idmef_field]

    def setIdmefField(self, idmef_field, value):
        self.initialAttrs[idmef_field] = value

    def rst(self):
        self._timestamps = []

    def addIdmef(self, idmef):
        tmp_analyzer = AnalyzerContents()
        tmp_analyzer.saveAnalyzerContents(idmef)
        self._timestamps.append([time.time(),idmef, tmp_analyzer])

    def checkCorrelationWindow(self):

        now = time.time()
        len_timestamps = len(self._timestamps)
        print("I am {} : len timestamps {}".format(self._name, len_timestamps))
        counter = 0
        for t in range(len_timestamps-1,-1,-1):
            print("I am {} : timestamps[{}] < {}".format(self._name, t, self._options["expire"]))
            if now - self._timestamps[t][0] < self._options["expire"]:
             counter = counter + 1
             print("I am {} : reaching threshold with counter {}".format(self._name, counter))
             if counter >= self._options["threshold"]:
                 print("I am {} : threshold reached".format(self._name))
                 self._ctx = Context(self._name, self._options, self._initialAttrs)
                 for c in range(t,t+counter):
                     self._timestamps[t][2].restoreAnalyzerContents(self._timestamps[t][1])
                     self._ctx.update(options=self._options, idmef=self._timestamps[t][1], timer_rst=False)
                 #self._ctx.destroy()
                 #self.unbindContext()
                 return True
            else:
              print("I am {} : del timestamps[{}]".format(self._name, t))
              self._timestamps.pop(t)

        return False

    def generateCorrelationAlert(self):
        tmp_ctx = ctx_search(self._name)
        self._ctx.destroy()
        self.unbindContext()
        self.rst()
        tmp_ctx.alert()

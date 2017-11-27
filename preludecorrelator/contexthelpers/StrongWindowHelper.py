import time
from ..contexthelper import ContextHelper
from ..context import Context
from ..idmef import AnalyzerContents
from ..context import search as ctx_search
from preludecorrelator import log

logger = log.getLogger(__name__)

class StrongWindowHelper(ContextHelper):


    def __init__(self, name):
        super(StrongWindowHelper, self).__init__(name)
        self._timestamps = []
        self._oldestTimestamp = None

    def isEmpty(self):
        return ctx_search(self._name) is None or (ctx_search(self._name) is not None and self._ctx is None)

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
        return self._ctx.get(idmef_field)

    def setIdmefField(self, idmef_field, value):
        self._ctx.set(idmef_field, value)

    def rst(self):
        self._timestamps = []

    def processIdmef(self, idmef, addAlertReference=True, idmefLack=False):
        now = time.time()
        if self._ctx.getOptions()["check_burst"]:
            in_window = self._oldestTimestamp is not None and (now - self._oldestTimestamp) < self._ctx.getOptions()["window"]
            if in_window:
                return
            else:
                self._oldestTimestamp = None

        len_timestamps = len(self._timestamps)
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] >= self._ctx.getOptions()["window"]:
               logger.debug("[%s] : del timestamps[%s]", self._name, t, level=3)
               self._timestamps.pop(t)

        if not idmefLack:
            if idmef is not None:
                tmp_analyzer = AnalyzerContents()
                tmp_analyzer.saveAnalyzerContents(idmef)

                if addAlertReference:
                 self._ctx.update(options=self._ctx.getOptions(), idmef=idmef, timer_rst=True)
                self._timestamps.append([now, idmef, tmp_analyzer, not addAlertReference])
            else:
                self._ctx.update()
                self._timestamps.append([now, None, None, False])
            logger.debug("[%s] : append timestamp", self._name, level=3)
        else:
            self._ctx.update()

    def corrConditions(self):
        counter = len(self.getAlertsReceivedInWindow())
        logger.debug("[%s] : trying to reach threshold %s with counter %s", self._name, self._ctx.getOptions()["threshold"], counter, level=3)
        return counter >= self._ctx.getOptions()["threshold"]

    def getAlertsReceivedInWindow(self):
        now = time.time()
        len_timestamps = len(self._timestamps)
        logger.debug("[%s] : len timestamps %s", self._name, len_timestamps, level=3)

        alerts = []
        for t in range(len_timestamps-1,-1,-1):
            if now - self._timestamps[t][0] < self._ctx.getOptions()["window"]:
             logger.debug("[%s] : timestamps[%s] < %s", self._name, t, self._ctx.getOptions()["window"], level=3)
             if self._timestamps[t][2] is not None:
                 self._timestamps[t][2].restoreAnalyzerContents(self._timestamps[t][1])
             alerts.append(self._timestamps[t][1])

        return alerts

    def checkCorrelation(self):
        return self._checkCorrelationWindow()

    def _checkCorrelationWindow(self):
        if self.corrConditions():
            logger.debug("[%s] : threshold %s reached", self._name, self._ctx.getOptions()["threshold"], level=3)
            for t in self._timestamps:
                if t[2] is not None:
                    t[2].restoreAnalyzerContents(t[1])
                    if t[3]:
                        self._ctx.update(options=self._ctx.getOptions(), idmef=t[1], timer_rst=False)
            return True
        return False

    def generateCorrelationAlert(self, send=True, destroy_ctx=False, rst=True):
        self._oldestTimestamp = self._timestamps[0][0]
        tmp_ctx = ctx_search(self._name)
        if destroy_ctx:
         self._ctx.destroy()
         self.unbindContext()
        if rst:
            self.rst()
        if send:
            tmp_ctx.alert()
        else:
            return tmp_ctx

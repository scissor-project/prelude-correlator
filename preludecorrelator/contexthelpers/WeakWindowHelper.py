import time
from ..contexthelper import ContextHelper
from..context import Context
from ..context import search as ctx_search
from preludecorrelator import log

logger = log.getLogger(__name__)

class WeakWindowHelper(ContextHelper):

    def __init__(self, name):
        super(WeakWindowHelper, self).__init__(name)
        self._origTime = time.time()
        self._received = 0
        self._oldestTimestamp = None
        self._windowExpirationCache = None

    def _WindowExpirationCache(object):

        def __init__(self, ctx, origTime, received):
            self._ctx = ctx
            self._origTime = origTime
            self._received = received

        def getCtx(self):
            return self._ctx

        def getOrigTime(self):
            return self._origTime

        def getReceived(self):
            return self._received

        def rst(self):
            self._ctx = None
            self._origTime = None
            self._received = None

    def isEmpty(self):
        return ctx_search(self._name) is None


    def bindContext(self, options, initial_attrs):
        res = ctx_search(self._name)
        if res is None:
         self._ctx = Context(self._name, options, update=False)
         self._origTime = time.time()
         self._received = 0
         self._windowExpirationCache = None
        else:
         self._ctx = res
        self._options = options
        self._initialAttrs = initial_attrs
        for key,value in self._initialAttrs.iteritems():
         self._ctx.set(key,value)


    def _restoreContext(self, options, initial_attrs):
         self._ctx = Context(self._name, options, update=False)

         for key,value in initial_attrs.iteritems():
             self._ctx.set(key,value)

    def unbindContext(self):
        self._ctx = None

    def getIdmefField(self, idmef_field):
        return self._ctx.get(idmef_field)

    def setIdmefField(self, idmef_field, value):
        self._ctx.set(idmef_field, value)

    def rst(self):
        self._origTime = time.time()
        self._received = 0

    def processIdmef(self, idmef, addAlertReference=True, idmefLack=False):
        now = time.time()
        if self._ctx.getOptions()["check_burst"]:
            in_window = self._oldestTimestamp is not None and (now - self._oldestTimestamp) < self._ctx.getOptions()["window"]
            if in_window:
                return
            else:
                self._oldestTimestamp = None

        if now - self._origTime >= self._ctx.getOptions()["window"]:
            if self._ctx.getOptions()["reset_ctx_on_window_expiration"]:
                if self._ctx.getOptions()["check_on_window_expiration"]:
                    self._windowExpirationCache = self._WindowExpirationCache(self._ctx, self._origTime, self._received)
                self._ctx.destroy()
                self._restoreContext(self._options, self._initialAttrs)
            self.rst()
        if not idmefLack:
            self._received = self._received + 1

        if idmef is not None and addAlertReference:
            self._ctx.update(options=self._ctx.getOptions(), idmef=idmef, timer_rst=True)
        else:
            self._ctx.update(options=self._ctx.getOptions(), idmef=None, timer_rst=True)

    def countAlertsReceivedInWindow(self):
        r = self._received
        if self._windowExpirationCache is not None:
            r = self._windowExpirationCache.getReceived()
        return r

    def corrConditions(self):
        alert_received = self.countAlertsReceivedInWindow()
        logger.debug("[%s] : alert received %s", self._name, alert_received, level=3)
        return alert_received >= self._ctx.getOptions()["threshold"]

    def checkCorrelation(self):
        if "check_on_window_expiration" in self._ctx.getOptions() and self._ctx.getOptions()["check_on_window_expiration"]:
            now = time.time()
            ot = self._origTime
            if self._windowExpirationCache is not None:
                ot = self._windowExpirationCache.getOrigTime()
            if now - ot >= self._ctx.getOptions()["window"]:
                if not self._checkCorrelationWindow():
                    self._windowExpirationCache = None
                    return False
                else:
                    return True
            return False
        else:
            return self._checkCorrelationWindow()

    def _checkCorrelationWindow(self):
         return self.corrConditions()

    def generateCorrelationAlert(self, send=True, destroy_ctx=False, rst=True):
        self._oldestTimestamp = self._origTime
        tmp_ctx = None
        if self._windowExpirationCache is None:
            tmp_ctx = ctx_search(self._name)
        else:
            tmp_ctx = self._windowExpirationCache.getCtx()
            self._windowExpirationCache = None
        if destroy_ctx:
            self._ctx.destroy()
            self.unbindContext()
        if rst:
            self.rst()
        if send:
            tmp_ctx.alert()
        else:
            return tmp_ctx

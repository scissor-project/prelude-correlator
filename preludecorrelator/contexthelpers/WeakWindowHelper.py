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
        self._categories = {}
        self._oldestTimestamp = None

    def isEmpty(self):
        return ctx_search(self._name) is None

    def bindContext(self, options, initial_attrs):
        res = ctx_search(self._name)
        if res is None:
            self._ctx = Context(self._name, options, update=False)
            self._origTime = time.time()
            self._resetCategories()
        else:
            self._ctx = res
        self._options = options
        self.initialAttrs = initial_attrs
        for key,value in self.initialAttrs.iteritems():
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

    def _resetCategories(self):
        options = self._ctx.getOptions()
        self._categories = {}
        if not ("categories" in options) or not options["categories"]:
            logger.error("[%s] This Context Helper must have at least one category", self._name)
            return
        for cc in options["categories"]:
            self._categories[cc] = 0

    def rst(self):
        self._origTime = time.time()
        if self._ctx is not None:
            self._resetCategories()

    def processIdmef(self, idmef, addAlertReference=True, additional_params={}):
        now = time.time()
        if self._ctx.getOptions()["check_burst"]:
            in_window = self._oldestTimestamp is not None and (now - self._oldestTimestamp) < self._ctx.getOptions()["window"]
            if in_window:
                return
            else:
                self._oldestTimestamp = None

        if not additional_params or not (additional_params["category"] in self._categories):
            logger.error("[%s] This Context Helper must have at least one category, or a category previously added in additional_params", self._name)
            return
        self._categories[additional_params["category"]] = self._categories[additional_params["category"]] + 1
        if now - self._origTime >= self._ctx.getOptions()["window"]:
            if self._ctx.getOptions()["reset_ctx_on_window_expiration"]:
                self._ctx.destroy()
                self._restoreContext(self._options, self._initialAttrs)
            self.rst()

        if idmef is not None and addAlertReference:
            self._ctx.update(options=self._ctx.getOptions(), idmef=idmef, timer_rst=True)
        else:
            self._ctx.update(options=self._ctx.getOptions(), idmef=None, timer_rst=True)

    def countAlertsReceivedInWindow(self):
        return self._categories

    def corrConditions(self):
        ar = self.countAlertsReceivedInWindow()
        if not ar:
            logger.error("[%s] This Context Helper must have at least one category", self._name)
            return False
        alert_received = 0
        for a in ar:
            alert_received = alert_received + ar[a]
        logger.debug("[%s] : alert received %s", self._name, alert_received, level=3)
        return alert_received >= self._ctx.getOptions()["threshold"]

    def checkCorrelation(self):
        return self._checkCorrelationWindow()

    def _checkCorrelationWindow(self):
         return self.corrConditions()

    def generateCorrelationAlert(self, send=True, destroy_ctx=False):
        self._oldestTimestamp = self._origTime
        tmp_ctx = ctx_search(self._name)
        if destroy_ctx:
            self._ctx.destroy()
            self.unbindContext()
        self.rst()
        if send:
            tmp_ctx.alert()
        else:
            return tmp_ctx

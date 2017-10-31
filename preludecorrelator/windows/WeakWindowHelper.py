import time
from ..windowhelper import WindowHelper
from..context import Context
from ..context import search as ctx_search

class WeakWindowHelper(WindowHelper):

    def __init__(self, name):
        super(WeakWindowHelper, self).__init__(name)
        #self._origTime = time.time()


    def isEmpty(self):
        return ctx_search(self._name) is None

    def bindContext(self, options, initial_attrs):
        res = ctx_search(self._name)
        if res is None:
         self._ctx = Context(self._name, options, update=False)
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
        pass

    def addIdmef(self, idmef):
        self._ctx.update(options=self._ctx.getOptions(), idmef=idmef, timer_rst=False)


    def _countAlertReceived(self):
     alert_received = self._ctx.get("alert.correlation_alert.alertident(*).analyzerid")
     if alert_received is None:
         alert_received = 0
     else:
         alert_received = len(alert_received)
     return alert_received

    def checkCorrelationWindow(self):

         alert_received = self._countAlertReceived()

         if alert_received >= self._ctx.getOptions()["threshold"]:
             return True

        return False

    def generateCorrelationAlert(self):
        tmp_ctx = ctx_search(self._name)
        self._ctx.destroy()
        self.unbindContext()
        self.rst()
        tmp_ctx.alert()

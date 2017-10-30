from ..context import Context
import time

class StrongContextHelper(Context):

    def __new__(self, name, options={}, idmef=None):
        super(WeakContextHelper, self).__new__(name, options, overwrite=False, update=False, idmef=None)
        ctxRes = Context.search(name)
        if ctxRes is not None:
            ctx.reset()
            if idmef is not None:
                ctxRes._addTimeStamp(idmef)

    def __init__(self, name, options={}, idmef=None):
        super(WeakContextHelper, self).__init__(name, options, overwrite=False, update=False, idmef=None)
        self._timestamps = []
        if idmef is not None:
            self._addTimeStamp(idmef)

    def _addTimeStamp(self, idmef):
        self._timestamps.append([time.time(),idmef])

    def checkCorrelationAlert(self):
            now = time.time()
            len_timestamps = len(self._timestamps)
            counter = 0
            for t in range(len_timestamps-1,-1,-1):
                if now - self._timestamps[t][0] < self.getOptions()["expire"]:
                 counter = counter + 1
                 if counter >= self.getOptions()["threshold"]:
                     for c in range(t,t+counter):
                         self.update(options=self.getOptions(), idmef=self._timestamps[t][1])
                     self.destroy()
                     return True
                else:
                  del self._timestamps[t]

                return False

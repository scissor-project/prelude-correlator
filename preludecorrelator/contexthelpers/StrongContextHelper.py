from ..context import Context
from ..context import search as ctx_search
import time
from ..idmef import AnalyzerContents

class StrongContextHelper(Context):

    def __new__(cls, name, options={}, idmef=None):
        ctxRes = ctx_search(name)
        if ctxRes is not None:
            ctxRes.reset()
            if idmef is not None:
                ctxRes._addTimeStamp(idmef)
        return super(StrongContextHelper, cls).__new__(cls, name, options, overwrite=False, update=False, idmef=None)

    def __init__(self, name, options={}, idmef=None):
        #check if already initialized
        if not hasattr(self, "_name"):
         self._timestamps = []
         if idmef is not None:
          self._addTimeStamp(idmef)
        return super(StrongContextHelper, self).__init__(name, options, overwrite=False, update=False, idmef=None)

    def _addTimeStamp(self, idmef):
        print(dir(idmef))
        self._timestamps.append([time.time(),idmef])

    def checkCorrelationAlert(self):
            now = time.time()
            len_timestamps = len(self._timestamps)
            print("I am {} : len timestamps {}".format(self._name, len_timestamps))
            counter = 0
            for t in range(len_timestamps-1,-1,-1):
                print("I am {} : timestamps[{}] < {}".format(self._name, t,self.getOptions()["expire"]))
                if now - self._timestamps[t][0] < self.getOptions()["expire"]:
                 counter = counter + 1
                 print("I am {} : reaching threshold with counter {}".format(self._name, counter))
                 if counter >= self.getOptions()["threshold"]:
                     print("I am {} : threshold reached".format(self._name))
                     for c in range(t,t+counter):
                         self.update(options=self.getOptions(), idmef=self._timestamps[t][1])
                     self.destroy()
                     return True
                else:
                  print("I am {} : del timestamps[{}]".format(self._name, t))
                  del self._timestamps[t]

            return False

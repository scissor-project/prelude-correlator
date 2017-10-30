from ..context import Context
import time

class WeakContextHelper(Context):

    def __init__(self, name, options={}, overwrite=True, update=False, idmef=None):
        super(WeakContextHelper, self).__init__(name, options, overwrite, update, idmef)
        self._origTime = time.time()

    def checkCorrelationAlert(self):
            now = time.time()

            if now - self._origTime < self.getOptions()["expire"]:
             # remember that when we have a threshold of x reached, we have updated the context exactly x - 1 times
             if self.getUpdateCount() >= self.getOptions()["threshold"] - 1:
                 self.destroy()
                 return True
            else:
              self.destroy()
            return False

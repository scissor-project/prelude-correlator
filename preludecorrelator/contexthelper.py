from context import search as ctx_search
from context import getName as getCtxName
from context import Context

class ContextHelper(object):

    def __init__(self, name):
        self._name = getCtxName(name)
        self._options = {}
        self._initialAttrs = {}
        self._ctx = None

    def getOptions(self):
        if self._ctx is None:
         return self._options
        else:
         return self._ctx.getOptions()

    def setOptions(self, options):
        if self._ctx is not None:
            self._ctx.setOptions(options)

    def setOption(self, option, value):
        if self._ctx is not None:
            opts = self._ctx.getOptions()
            opts[option] = value
            self._ctx.setOptions(opts)


    def getInitialAttrs(self):
        return self._initialAttrs

    def setInitialAttrs(self, initial_attrs):
        self._initialAttrs = initial_attrs


    def getCtx(self):
        return self._ctx

    def isEmpty(self):
        pass

    def getIdmefField(self, idmef_field):
        pass

    def setIdmefField(self, idmef_field, value):
        pass

    def getName(self):
        return self._name

    def checkCorrelation(self):
        pass

    def generateCorrelationAlert(self, send=True, destroy_ctx=False, rst=True):
        pass

    def rst(self):
        pass

    def processIdmef(self, idmef, addAlertReference=True, idmefLack=False):
        pass

    def bindContext(self, options, initial_attrs):
        pass

    def unbindContext(self):
        pass

    def corrConditions(self):
        pass

class ContextHelperHolder(object):

    def __init__(self):
        self._contextHelpers = []

    def getContextHelper(self, ctx_name, class_name):
        for w in self._contextHelpers:
            if w.getName() == getCtxName(ctx_name):
                return w
        new_inst = class_name(ctx_name)
        self.addContextHelper(new_inst)
        return new_inst

    def getContextHelpers(self):
        return self._contextHelpers()

    def addContextHelper(self, context_helper):
        self._contextHelpers.append(context_helper)

from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.contexthelpers.TimestampsWeakWindowHelper import TimestampsWeakWindowHelper
from preludecorrelator import log
import time

LEVEL = 1
NUMBER = 1
#The context should be unique, it's better add the class name since we know it's unique
context_id = "{}Layer{}Correlation{}".format("AnomalousAccessPlugin", LEVEL, NUMBER)
logger = log.getLogger(__name__)

SYSTEM = "ASS_testbed"
DOOR_OPEN = "Entrance Door Open"
PERSON_ENTERED = "1"

FILTERS = (DOOR_OPEN)

START = "start"
WATCHING = "watching"

TOO_OLD = 60
TIMESTAMP_EXPIRATION = 30

class ExtendedWindowHelper(TimestampsWeakWindowHelper):

    def corrConditions(self):
        person_entered = self._windowExpirationCache.getCtx().getOptions().get(PERSON_ENTERED)

        return person_entered < 1


class AnomalousAccessPlugin(Plugin):

    def __init__(self, env):
        super(AnomalousAccessPlugin, self).__init__(env)
        self.processIdmefLack = True
        self._current_state = START
        self._last_person_entered = None
        self._start_timestamp = None
        logger.info("Loading %s", self.__class__.__name__)

    class _Start(object):

        def __init__(self, context):
            self.context = context

        def getName(self):
            return "start"

        def getNextState(self):
            return "watching"

        def execState(self, idmef):
            if idmef is not None and \
            idmef.get("alert.classification.text") == DOOR_OPEN and \
            self.context.is_last_person_entered_too_old():
                return True
            return False

    class _Watching(object):

        def __init__(self, context):
            self.context = context
            self.generate_correlation_alert = False

        def getName(self):
            return "watching"

        def getNextState(self):
            return "start"

        def execState(self, idmef):
            correlator = self.context.getContextHelper(context_id, ExtendedWindowHelper)

            if idmef is not None:
                correlator.setCurrentSendTimestamp(\
                int(self.context._getDataByMeaning(idmef, "event.sendtime_ms")))

            return self.watchWindow(idmef, correlator)


        def watchWindow(self, idmef, correlator):
            if idmef is not None:
                correlator.setCurrentSendTimestamp(\
                int(self.context._getDataByMeaning(idmef, "event.sendtime_ms")))

            if idmef is not None and \
            idmef.get("alert.classification.text") == PERSON_ENTERED and \
            correlator.getCtx().getOptions().get(PERSON_ENTERED) == 0:
                correlator.setOption(PERSON_ENTERED, 1)

            window_end = self.context.get_window_end(correlator)

            correlator.processIdmef(idmef=idmef, \
            addAlertReference=False, idmefLack=idmef is None)
            if correlator.checkCorrelation():
                self.generate_correlation_alert = True
                return True
            else:
                if window_end:
                    return True

    def generate_correlation_alert(self):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)
        correlator.generateCorrelationAlert(send=True, destroy_ctx=True)

    def from_start_to_watching(self, idmef):
        self.set_current_state(self._Watching(self))
        self.init_window(idmef)

    def from_watching_to_start(self, idmef):
        to_gen = self.get_current_state().generate_correlation_alert

        self.set_current_state(self._Start(self))
        if idmef.get("alert.classification.text") == DOOR_OPEN:
            time_exceeded = self.timestamp_exceeded(idmef)
            #This is the case in which i received DOOR_OPEN
            #and timestamp is exceeded
            self.set_start_timestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))
            if to_gen:
                self.generate_correlation_alert()
            if time_exceeded:
                self.check_state_transitions(idmef)
        else:
            self.set_start_timestamp(None)
            if to_gen:
                self.generate_correlation_alert()

    def get_start_timestamp(self):
        return self._start_timestamp

    def set_start_timestamp(self, start_timestamp):
        self._start_timestamp = start_timestamp

    def get_current_state(self):
        return self._current_state

    def set_current_state(self, new_state):
        self._current_state = new_state

    def get_last_person_entered(self):
        return self._last_person_entered

    def set_last_person_entered(self, last_person_entered_timestamp=None):
        self._last_person_entered = time.time() if last_person_entered_timestamp is None \
        else last_person_entered_timestamp

    def rst_last_person_entered(self):
        self._last_person_entered = None

    def is_last_person_entered_too_old(self):
        if self._last_person_entered is not None:
            return self.get_last_person_entered() - \
        self._start_timestamp > TOO_OLD*1000 or \
        self._start_timestamp - self.get_last_person_entered() > TOO_OLD*1000
        return True

    def process_idmef(self, idmef):
        if idmef is not None and self._start_timestamp is None and \
        idmef.get("alert.classification.text") == DOOR_OPEN:
            self.set_start_timestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if idmef is not None and \
        idmef.get("alert.classification.text") == PERSON_ENTERED:
            self.set_last_person_entered()

    def check_state_transitions(self, idmef):
        current_state = self.get_current_state()
        if current_state.execState(idmef):
            metname = "from_{}_to_{}".format(current_state.getName(), \
            current_state.getNextState())
            getattr(self, metname)(idmef)

    def check_transitions(self, idmef):
        if idmef is not None and self._start_timestamp is None and \
        idmef.get("alert.classification.text") == DOOR_OPEN:
            self.set_start_timestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if idmef is not None and \
        idmef.get("alert.classification.text") == PERSON_ENTERED:
            self.set_last_person_entered()
        if self.get_current_state() == START and \
        idmef is not None and \
        idmef.get("alert.classification.text") == DOOR_OPEN and \
        self.is_last_person_entered_too_old():
            self.set_current_state(WATCHING)
            self.init_window(idmef)
            self.watch_window(idmef)
            return
        elif self.get_current_state() == WATCHING:
            if self.timestamp_exceeded(idmef):
                if idmef.get("alert.classification.text") == DOOR_OPEN:
                    #This is the case in which i received DOOR_OPEN
                    #and timestamp is exceeded
                    self.watch_window(idmef)
                    self.set_start_timestamp(\
                    int(self._getDataByMeaning(idmef, "event.sendtime_ms")))
                    if self.is_last_person_entered_too_old():
                        self.set_current_state(WATCHING)
                        self.init_window(idmef)
                        self.watch_window(idmef)
                        return
                    return
                    #self.set_current_state(START)
                    #self.end_window(idmef)
                    #self.set_current_state(WATCHING)
                    #self.init_window(idmef)
                else:
                    #This is the case in which i received event not filtered
                    #but timestamp is exceeded
                    self.watch_window(idmef)
                    self.set_start_timestamp(None)
                    #self.set_current_state(START)
                    #self.end_window(idmef)
                    return

            self.watch_window(idmef)

    def get_window_end(self, correlator):
        return correlator.isWindowEnd()

    def timestamp_exceeded(self, idmef):
        return int(self._getDataByMeaning(idmef, "event.sendtime_ms")) - \
    self._start_timestamp > TIMESTAMP_EXPIRATION*1000 if idmef is not None else \
    False

    def init_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)

        if correlator.isEmpty():
            options = {"expire": 40, "threshold": 2, "alert_on_expire": False, \
            "window": 30, "check_burst": False, "check_on_window_expiration": True, \
            "reset_ctx_on_window_expiration": True, PERSON_ENTERED: 0}
            initial_attrs = {\
            "alert.correlation_alert.name": "Anomalous Access", \
            "alert.classification.text": "Anomalous Access", \
            "alert.assessment.impact.severity": "info"}

            correlator.bindContext(options, initial_attrs)
            correlator.setStartSendTimestamp(self._start_timestamp)
            correlator.setCurrentSendTimestamp(self._start_timestamp)

    def watch_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)
        if idmef is not None:
            correlator.setCurrentSendTimestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if idmef is not None and \
        idmef.get("alert.classification.text") == PERSON_ENTERED and \
        correlator.getCtx().getOptions().get(PERSON_ENTERED) == 0:
            correlator.setOption(PERSON_ENTERED, 1)

        window_end = self.get_window_end(correlator)

        correlator.processIdmef(idmef=idmef, \
        addAlertReference=False, idmefLack=idmef is None)
        if correlator.checkCorrelation():
            self.set_current_state(START)
            self.set_start_timestamp(None)
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)
        else:
            if window_end:
                self.set_current_state(START)
                self.set_start_timestamp(None)


    def end_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)

        if idmef is not None:
            correlator.setCurrentSendTimestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if correlator.checkCorrelation():
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)

    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef is not None:
            if idmef.get("alert.correlation_alert.name") is not None or \
            self._getDataByMeaning(idmef, "identity.system") != SYSTEM or \
            idmef.get("alert.classification.text") not in FILTERS:
                return

        self.check_transitions(idmef)

    def _getDataByMeaning(self, idmef, meaning):
        meanings = idmef.get("alert.additional_data(*).meaning")
        m_len = len(meanings)
        for m in range(m_len):
            if meanings[m] == meaning:
                to_search = "alert.additional_data({}).data".format(m)
                d = idmef.get(to_search)
                return d
        return None

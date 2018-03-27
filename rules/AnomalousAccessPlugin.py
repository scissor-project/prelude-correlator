from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.contexthelpers.WeakWindowHelper import WeakWindowHelper
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

class ExtendedWindowHelper(WeakWindowHelper):

    def corrConditions(self):
        person_entered = self._windowExpirationCache.getCtx().getOptions().get(PERSON_ENTERED)

        return person_entered < 1


class AnomalousAccessPlugin(Plugin):

    def __init__(self, env):
        super(AnomalousAccessPlugin, self).__init__(env)
        self.processIdmefLack = True
        self._current_state = START
        self._last_person_entered = None
        logger.info("Loading %s", self.__class__.__name__)

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
            return time.time() - self.get_last_person_entered() > TOO_OLD
        return True

    def check_transitions(self, idmef):
        if idmef is not None and \
        self.is_person_entered_id(idmef):
            self.set_last_person_entered()
        if self.get_current_state() == START and \
        idmef is not None and \
        idmef.get("alert.classification.text") == DOOR_OPEN and \
        self.is_last_person_entered_too_old():
            self.set_current_state(WATCHING)
            self.watch_window(idmef)
            return
        elif self.get_current_state() == WATCHING:
            self.watch_window(idmef)

    def get_window_end(self, correlator):
        return time.time() - correlator._origTime >= correlator.getCtx().getOptions()["window"]

    def watch_window(self, idmef):
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

        if idmef is not None and \
        self.is_person_entered_id(idmef) and \
        correlator.getCtx().getOptions().get(PERSON_ENTERED) == 0:
            correlator.setOption(PERSON_ENTERED, 1)

        if self.get_window_end(correlator):
            self.set_current_state(START)

        correlator.processIdmef(idmef=idmef, \
        addAlertReference=False, idmefLack=idmef is None)

        if correlator.checkCorrelation():
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)

    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef is not None:
            if self.is_correlation_alert(idmef) or \
            self.is_not_in_system(idmef) or \
            self.is_invalid_event(idmef):
                print("EVENT {} FILTERED".format(idmef.get("alert.classification.text")))
                return

        self.check_transitions(idmef)

    def is_correlation_alert(self, idmef):
        return idmef.get("alert.correlation_alert.name") is not None

    def is_not_in_system(self, idmef):
        return self._getDataByMeaning(idmef, "identity.system") != SYSTEM

    def is_invalid_event(self, idmef):
        return (idmef.get("alert.classification.text") not in FILTERS) and not self.is_person_entered_id(idmef)

    def is_person_entered_id(self, idmef):
        ev_id = self._getDataByMeaning(idmef, "event.id")
        return (ev_id is not None) and ev_id == PERSON_ENTERED

    def _getDataByMeaning(self, idmef, meaning):
        meanings = idmef.get("alert.additional_data(*).meaning")
        m_len = len(meanings)
        for m in range(m_len):
            if meanings[m] == meaning:
                to_search = "alert.additional_data({}).data".format(m)
                d = idmef.get(to_search)
                return d
        return None

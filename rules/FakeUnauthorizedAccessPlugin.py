from preludecorrelator.pluginmanager import Plugin
from preludecorrelator.contexthelpers.WeakWindowHelper import WeakWindowHelper
from preludecorrelator import log
import time

LEVEL = 1
NUMBER = 1
#The context should be unique, it's better add the class name since we know it's unique
context_id = "{}Layer{}Correlation{}".format("UnauthorizedAccessPlugin", LEVEL, NUMBER)
logger = log.getLogger(__name__)

TAMPERING = "Unauthorized Access with Tampering"

SYSTEM = "ASS_testbed"
DOOR_OPEN = "Entrance Door Open"
BADGE_DETECTED = "Badge Recognized"
CABINET_OPEN = "Cabinet Door Open"

FILTERS = (DOOR_OPEN, BADGE_DETECTED, CABINET_OPEN)

START = "start"
WATCHING = "watching"

TOO_OLD = 60

CABINET_OPEN_TOO_OLD = 60

class ExtendedWindowHelper(WeakWindowHelper):

    def corrConditions(self):
        badge_detected = self._windowExpirationCache.getCtx().getOptions().get(BADGE_DETECTED)

        return badge_detected < 1


class UnauthorizedAccessPlugin(Plugin):

    def __init__(self, env):
        super(UnauthorizedAccessPlugin, self).__init__(env)
        self.processIdmefLack = True
        self._current_state = START
        self._last_badge_recognized = None
        self._last_cabinet_open = None
        logger.info("Loading %s", self.__class__.__name__)

    def get_current_state(self):
        return self._current_state

    def set_current_state(self, new_state):
        self._current_state = new_state

    def get_last_badge_recognized(self):
        return self._last_badge_recognized

    def set_last_badge_recognized(self, last_badge_timestamp=None):
        self._last_badge_recognized = time.time() if last_badge_timestamp is None \
        else last_badge_timestamp

    def rst_last_badge_recognized(self):
        self._last_badge_recognized = None

    def is_last_badge_too_old(self):
        if self._last_badge_recognized is not None:
            return time.time() - self.get_last_badge_recognized() > TOO_OLD
        return True

    def get_last_cabinet_open(self):
        return self._last_cabinet_open

    def set_last_cabinet_open(self, last_cabinet_timestamp=None):
        self._last_cabinet_open = time.time() if last_cabinet_timestamp is None \
        else last_cabinet_timestamp

    def rst_last_cabinet_open(self):
        self._last_cabinet_open = None

    def is_last_cabinet_open_too_old(self):
        if self._last_cabinet_open is not None:
            return time.time() - self.get_last_cabinet_open() > CABINET_OPEN_TOO_OLD
        return True

    def check_transitions(self, idmef):
        if idmef is not None and \
        self._getDataByMeaning(idmef, "event.text") == BADGE_DETECTED:
            print("update BADGE_DETECTED timestamp")
            self.set_last_badge_recognized()
        elif idmef is not None and \
        self._getDataByMeaning(idmef, "event.text") == CABINET_OPEN:
            print("update CABINET_OPEN timestamp")
            self.set_last_cabinet_open()
        if self.get_current_state() == START and \
        idmef is not None and \
        self._getDataByMeaning(idmef, "event.text") == DOOR_OPEN and \
        self.is_last_badge_too_old():
            print("going to WATCHING")
            self.set_current_state(WATCHING)
            self.watch_window(idmef)
            return
        elif self.get_current_state() == WATCHING:
            print("already in WATCHING")
            self.watch_window(idmef)

    def get_window_end(self, correlator):
        return time.time() - correlator._origTime >= correlator.getCtx().getOptions()["window"]

    def watch_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)

        if correlator.isEmpty():
            options = {"expire": 40, "threshold": 2, "alert_on_expire": False, \
            "window": 30, "check_burst": False, "check_on_window_expiration": True, \
            "reset_ctx_on_window_expiration": True, BADGE_DETECTED: 0, CABINET_OPEN: 0}
            initial_attrs = {\
            "alert.correlation_alert.name": "Unauthorized Access", \
            "alert.classification.text": "Unauthorized Access", \
            "alert.assessment.impact.severity": "info"}

            correlator.bindContext(options, initial_attrs)

        if idmef is not None and \
        self._getDataByMeaning(idmef, "event.text") == BADGE_DETECTED and \
        correlator.getCtx().getOptions().get(BADGE_DETECTED) == 0:
            print("update BADGE_DETECTED")
            correlator.setOption(BADGE_DETECTED, 1)
        elif idmef is not None and \
        self._getDataByMeaning(idmef, "event.text") == CABINET_OPEN and \
        correlator.getCtx().getOptions().get(CABINET_OPEN) == 0:
            print("update CABINET_OPEN")
            correlator.setOption(CABINET_OPEN, 1)

        if self.get_window_end(correlator):
            print("going to START")
            self.set_current_state(START)

        correlator.processIdmef(idmef=idmef, \
        addAlertReference=False, idmefLack=idmef is None)

        if correlator.checkCorrelation():
            if not self.is_last_cabinet_open_too_old():
                print("generating TAMPERING")
                correlator.getCtx().set("alert.correlation_alert.name", TAMPERING)
                correlator.getCtx().set("alert.classification.text", TAMPERING)
            print("CORRELATION ALERT {}".format(correlator.getCtx().get("alert.correlation_alert.name")))
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)

    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef is not None:
            if idmef.get("alert.correlation_alert.name") is not None or \
            self._getDataByMeaning(idmef, "identity.system") != SYSTEM or \
            self._getDataByMeaning(idmef, "event.text") not in FILTERS:
                return

        if idmef is not None:
            print(self._getDataByMeaning(idmef, "event.text"))
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
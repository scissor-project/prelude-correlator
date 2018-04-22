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
PERSON_ENTERED = "Person entered a restricted area"

FILTERS = (DOOR_OPEN, PERSON_ENTERED)

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
        self._consider_idmef_timestamp = time.time()
        logger.info("Loading %s", self.__class__.__name__)

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

    def check_transitions(self, idmef):
        if idmef is not None and self._start_timestamp is None and \
        idmef.get("alert.classification.text") == DOOR_OPEN:
            print("setting timestamp {}".format(int(self._getDataByMeaning(idmef, "event.sendtime_ms"))))
            self.set_start_timestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if idmef is not None and \
        idmef.get("alert.classification.text") == PERSON_ENTERED:
            print("setting PERSON_ENTERED {}".format(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms"))))
            self.set_last_person_entered(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if self.get_current_state() == START:
            if idmef is not None and idmef.get("alert.classification.text") == DOOR_OPEN:
                print("I am in START and received DOOR_OPEN, \
                setting timestamp anyway {}\
                ".format(int(self._getDataByMeaning(idmef, "event.sendtime_ms"))))
                self.set_start_timestamp(\
                int(self._getDataByMeaning(idmef, "event.sendtime_ms")))
            if idmef is not None and \
            idmef.get("alert.classification.text") == DOOR_OPEN and \
            self.is_last_person_entered_too_old():
                print("going to WATCHING {}".format((
                int(self._getDataByMeaning(idmef, "event.sendtime_ms")) - \
                self._start_timestamp)/1000))
                self.set_current_state(WATCHING)
                print("init_window")
                self.init_window(idmef)
                print("watch_window")
                self.watch_window(idmef)
                return
            return
        elif self.get_current_state() == WATCHING:
            if self.timestamp_exceeded(idmef):
                print("timestamp exceeded {} - {} = {}".format(\
                int(self._getDataByMeaning(idmef, "event.sendtime_ms")),
                self._start_timestamp, (int(self._getDataByMeaning(idmef, "event.sendtime_ms"))- \
                self._start_timestamp)/1000))

                if idmef.get("alert.classification.text") == DOOR_OPEN:
                    #This is the case in which i received DOOR_OPEN
                    #and timestamp is exceeded
                    self.watch_window(idmef)
                    print("DOOR_OPEN received, so setting start_timestamp to {}".format(\
                    int(self._getDataByMeaning(idmef, "event.sendtime_ms"))))
                    self.set_start_timestamp(\
                    int(self._getDataByMeaning(idmef, "event.sendtime_ms")))
                    if self.is_last_person_entered_too_old():
                        print("last person entered too old, restart window")
                        print("going to WATCHING")
                        self.set_current_state(WATCHING)
                        print("init_window")
                        self.init_window(idmef)
                        print("watch_window")
                        self.watch_window(idmef)
                        return
                else:
                    #This is the case in which i received event not filtered
                    #but timestamp is exceeded
                    self.watch_window(idmef)
                    print("received {}, so setting start_timestamp to None".\
                    format(idmef.get("alert.classification.text")))
                    self.set_start_timestamp(None)
                    return

            if idmef is not None and self._start_timestamp is not None:
                print("timestamp NOT exceeded {} - {} = {}".format(\
                int(self._getDataByMeaning(idmef, "event.sendtime_ms")),
                self._start_timestamp, (int(self._getDataByMeaning(idmef, "event.sendtime_ms"))- \
                self._start_timestamp)/1000))
            print("so watching window")
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
            "alert.assessment.impact.severity": "medium"}

            correlator.bindContext(options, initial_attrs)
            print("setting correlator start_timestamp {}".format(self._start_timestamp))
            correlator.setStartSendTimestamp(self._start_timestamp)

            print("setting timestamp to correlator, {} \
            seconds elapsed".format(\
            (int(self._getDataByMeaning(idmef, "event.sendtime_ms")) - \
            self._start_timestamp)/1000))
            correlator.setCurrentSendTimestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

    def watch_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)

        if idmef is not None:
            print("setting timestamp to correlator, {} \
            seconds elapsed".format(\
            (int(self._getDataByMeaning(idmef, "event.sendtime_ms")) - \
            self._start_timestamp)/1000))
            correlator.setCurrentSendTimestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if idmef is not None and \
        idmef.get("alert.classification.text") == PERSON_ENTERED and \
        correlator.getCtx().getOptions().get(PERSON_ENTERED) == 0:
            print("update PERSON_ENTERED +1")
            correlator.setOption(PERSON_ENTERED, 1)

        window_end = self.get_window_end(correlator)

        correlator.processIdmef(idmef=idmef, \
        addAlertReference=True, idmefLack=idmef is None)
        if correlator.checkCorrelation():
            print("CORRELATION ALERT, ANOMALOUS ACCESS")
            print("and going to START, \
            start_timestamp will be set to None")
            self.set_current_state(START)
            self.set_start_timestamp(None)
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)
        else:
            if window_end:
                print("correlator says WINDOW END, going to START, \
                start_timestamp will be set to None")
                self.set_current_state(START)
                self.set_start_timestamp(None)


    def end_window(self, idmef):
        correlator = self.getContextHelper(context_id, ExtendedWindowHelper)

        if idmef is not None:
            print("setting timestamp to correlator, {}".format( \
            self._getDataByMeaning(idmef, "event.sendtime_ms")))
            correlator.setCurrentSendTimestamp(\
            int(self._getDataByMeaning(idmef, "event.sendtime_ms")))

        if correlator.checkCorrelation():
            print("CORRELATION ALERT, ANOMALOUS ACCESS")
            correlator.generateCorrelationAlert(send=True, destroy_ctx=True)

    def run(self, idmef):
        #Receive only simple alerts, not correlation alerts
        if idmef is not None:
            if idmef.get("alert.correlation_alert.name") is not None or \
            self._getDataByMeaning(idmef, "identity.system") != SYSTEM or \
            idmef.get("alert.classification.text") not in FILTERS:
                time_now = time.time()
                if time_now - self._consider_idmef_timestamp < 1:
                    return
                else:
                    self._consider_idmef_timestamp = time_now
                    idmef = None
            else:
                print("received {}, {}".format(idmef.get("alert.classification.text"),\
                int(self._getDataByMeaning(idmef, "event.sendtime_ms"))))
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

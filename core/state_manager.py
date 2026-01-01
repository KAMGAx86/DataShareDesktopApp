from enum import Enum
import threading


class State(Enum):
    READY = "L'appareil est pret a recevoir"
    BUSY = "Un tranfert est deja en cours"
    OFFLINE = "Le service est deconnecte"


class StateManager:
    def __init__(self):
        # ✅ CORRECTION : Démarrer en mode OFFLINE
        self._current_state: State = State.OFFLINE
        self._lock = threading.Lock()

    def set_state(self, new_state: State):
        with self._lock:
            print(f"[StateManager] Changement d'état : {self._current_state.name} → {new_state.name}")
            self._current_state = new_state

    def get_state(self) -> State:
        with self._lock:
            return self._current_state

    def is_busy(self) -> bool:
        return self._current_state == State.BUSY
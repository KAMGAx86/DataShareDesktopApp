from .state_manager import StateManager
import socket

SECRET_KEY : bytes = b'cDs2AUeNR4YdZmHzzBNtsEqFzg4qhJMxz60NO3ELnGM='
MANAGER: StateManager = StateManager()
HOSTNAME: str = socket.gethostname() 
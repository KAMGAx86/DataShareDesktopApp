import os
import threading
import time
import socket
import cryptography
import json
from cryptography.fernet import Fernet
import logging
from .state_manager import State
from .config import MANAGER, SECRET_KEY, HOSTNAME

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def dict_to_json_bytes(data: dict) -> bytes:
    json_string: str = json.dumps(data, ensure_ascii=False)
    json_bytes: bytes = json_string.encode('utf-8')
    return json_bytes


class Phare:
    """Classe permettant d'annoncer sa présence sur le réseau"""

    def __init__(self):
        self.port_tcp: int = 32000
        # ✅ CORRECTION : Créer un nouveau socket à chaque fois pour éviter les conflits
        self.sock_udp: socket = None
        self.service_name: str = "DATASHAREV1"
        self.pc_name: str = HOSTNAME
        self.port_udp = 32001
        self.state_manager = MANAGER

    def _build_packet(self) -> bytes:
        timestamp: float = time.time()

        json_byte: bytes = dict_to_json_bytes({
            'timestamp': timestamp,
            'port': self.port_tcp,
            'service': self.service_name,
            'pc': self.pc_name,
            'status': self.state_manager.get_state().name
        })

        f: Fernet = Fernet(SECRET_KEY)
        json_chiffre: bytes = f.encrypt(json_byte)

        return json_chiffre

    def shouting(self):
        """Diffuse la présence sur le réseau"""
        try:
            # ✅ Créer le socket ici pour éviter les conflits
            self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            logging.info(f"[Phare] Démarrage - Broadcast sur port {self.port_udp}")

            while True:
                if self.state_manager.get_state() == State.OFFLINE:
                    logging.info("[Phare] Arrêt demandé (OFFLINE)")
                    break

                try:
                    self.sock_udp.sendto(self._build_packet(), ('<broadcast>', self.port_udp))
                except Exception as e:
                    logging.error(f"[Phare] Erreur envoi : {e}")

                time.sleep(2)

        except Exception as e:
            logging.exception(f"[Phare] Erreur fatale : {e}")
        finally:
            if self.sock_udp:
                try:
                    self.sock_udp.close()
                except:
                    pass


class Scanner:
    """Classe permettant d'écouter la présence d'autres machines sur le réseau"""

    def __init__(self):
        self.sock_up = None
        self.port_upd = 32001
        self.device_list = {}
        self.running = False
        # ✅ AJOUT : Mémoriser l'IP locale pour filtrer (optionnel)
        self.local_ip = self.get_local_ip()

    def get_local_ip(self):
        """Récupère l'adresse IP locale"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _verify_data_integrity(self, data: dict) -> bool:
        """Vérifie l'intégrité du paquet"""
        dt: float = time.time() - data['timestamp']
        if int(dt) > 5:
            logging.warning("[Scanner] Paquet trop vieux, rejeté")
            return False
        return True

    def _append_in_list_device(self, ip: str, data: dict):
        """Ajoute un appareil à la liste"""
        last_seen = time.time()
        data.update({'last_seen': last_seen})

        # if ip == self.local_ip: # pour que le scanner ne voyent pas sa propre machine
        #     logging.debug(f"[Scanner] Ignoré : propre machine ({ip})")
        #     return

        # ✅ IMPORTANT : Toujours ajouter, même si c'est notre propre IP
        self.device_list[ip] = data
        logging.info(f"[Scanner] Appareil détecté : {data['pc']} ({ip}) - Status: {data['status']}")

    def _clean_devices(self) -> bool:
        """
        Supprime les appareils qui ne sont plus en ligne.
        Retourne True si des appareils ont été supprimés
        """
        del_ip = []
        now = time.time()

        for key, value in self.device_list.items():
            if now - value['last_seen'] > 10:
                del_ip.append(key)

        for ip in del_ip:
            self.device_list.pop(ip)
            logging.info(f"[Scanner] Appareil retiré : {ip}")

        return len(del_ip) > 0

    def listening(self, callback_update):
        """Écoute le réseau et met à jour via callback"""
        try:
            # ✅ Créer le socket ici
            self.sock_up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock_up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # ✅ CRITIQUE : Permettre la réception de broadcast sur Windows
            if os.name == 'nt':  # Windows
                self.sock_up.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            self.sock_up.bind(('', self.port_upd))  # ✅ Bind sur '' au lieu de '0.0.0.0'
            self.sock_up.settimeout(0.5)
            self.running = True

            f = Fernet(SECRET_KEY)

            logging.info(f"[Scanner] Écoute sur port {self.port_upd} (IP locale: {self.local_ip})")

            while self.running:
                try:
                    data, addr = self.sock_up.recvfrom(1024)

                    try:
                        JSON: bytes = f.decrypt(data)
                    except cryptography.fernet.InvalidToken:
                        logging.warning(f"[Scanner] Paquet malveillant de {addr[0]}")
                        continue

                    message_original: dict = json.loads(JSON.decode('utf-8'))

                    if not self._verify_data_integrity(message_original):
                        continue

                    # ✅ IMPORTANT : Accepter tous les paquets, même de notre propre IP
                    self._append_in_list_device(addr[0], message_original)
                    self._clean_devices()
                    callback_update(list(self.device_list.items()))

                except socket.timeout:
                    if self._clean_devices():
                        callback_update(list(self.device_list.items()))

        except Exception as e:
            logging.error(f"[Scanner] Erreur : {e}")
        finally:
            self.running = False
            if self.sock_up:
                try:
                    self.sock_up.close()
                except:
                    pass
            logging.info("[Scanner] Arrêté")


def test_discovery():
    """Test du module de découverte"""
    print("=== TEST DU MODULE DISCOVERY ===")

    # 1. Lancement du Phare dans un Thread
    try:
        phare = Phare()
        MANAGER.set_state(State.READY)

        thread_phare = threading.Thread(target=phare.shouting, daemon=True)
        thread_phare.start()
        print("[*] Phare lancé : Il diffuse sa présence sur le port 32001...")
    except Exception as e:
        print(f"[!] Erreur Phare: {e}")

    # 2. Lancement du Scanner
    print("[*] Scanner lancé : Recherche d'appareils (Ctrl+C pour arrêter)...")
    scanner = Scanner()

    def print_devices(devices):
        print(f"\n[{time.strftime('%H:%M:%S')}] Appareils trouvés : {len(devices)}")
        for ip, info in devices:
            print(f"  - {info['pc']} ({ip}) - Port {info['port']} - Status: {info['status']}")

    try:
        scanner.listening(print_devices)
    except KeyboardInterrupt:
        print("\n[*] Test arrêté par l'utilisateur.")
    except Exception as e:
        print(f"[!] Erreur Scanner: {e}")


if __name__ == "__main__":
    test_discovery()
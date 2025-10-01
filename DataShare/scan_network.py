"""
Module de découverte d'appareils réseau pour DataShare

Ce module permet de:
- Découvrir automatiquement les autres appareils DataShare sur le réseau
- Annoncer la présence de cet appareil aux autres
- Maintenir une liste des appareils disponibles
- Gérer les timeouts et la suppression d'appareils déconnectés

Utilise UDP broadcast pour la découverte réseau automatique.

Auteur: DataShare Team
Version: 2.0
"""

import socket
import time
import threading
import logging
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

# Configuration
PORT = 32000  # Port UDP pour la communication de découverte
BROADCAST_INTERVAL = 5  # Intervalle d'annonce en secondes
DEVICE_TIMEOUT = 15  # Timeout pour considérer un appareil comme déconnecté
MAX_MESSAGE_SIZE = 1024  # Taille maximale des messages UDP

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceInfo:
    """
    Classe pour représenter les informations d'un appareil sur le réseau.
    """
    
    def __init__(self, hostname: str, ip_address: str, port: int = PORT):
        """
        Initialise les informations d'un appareil.
        
        Args:
            hostname (str): Nom de l'ordinateur
            ip_address (str): Adresse IP locale
            port (int): Port d'écoute pour DataShare
        """
        self.hostname = hostname
        self.ip_address = ip_address
        self.port = port
        self.last_seen = datetime.now()  # Dernière fois que l'appareil a été vu
        self.is_online = True
    
    def update_last_seen(self):
        """Met à jour le timestamp de dernière activité."""
        self.last_seen = datetime.now()
        self.is_online = True
    
    def is_expired(self, timeout_seconds: int = DEVICE_TIMEOUT) -> bool:
        """
        Vérifie si l'appareil est considéré comme déconnecté.
        
        Args:
            timeout_seconds (int): Délai d'expiration en secondes
            
        Returns:
            bool: True si l'appareil est expiré
        """
        return datetime.now() - self.last_seen > timedelta(seconds=timeout_seconds)
    
    def to_dict(self) -> Dict:
        """Convertit l'objet en dictionnaire pour sérialisation."""
        return {
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'port': self.port,
            'last_seen': self.last_seen.isoformat(),
            'is_online': self.is_online
        }
    
    def __str__(self) -> str:
        """Représentation string de l'appareil."""
        status = "🟢 En ligne" if self.is_online else "🔴 Hors ligne"
        return f"{self.hostname} ({self.ip_address}) - {status}"
    
    def __eq__(self, other) -> bool:
        """Comparaison d'égalité basée sur hostname et IP."""
        if not isinstance(other, DeviceInfo):
            return False
        return self.hostname == other.hostname and self.ip_address == other.ip_address


class NetworkDiscovery:
    """
    Gestionnaire principal pour la découverte d'appareils réseau.
    """
    
    def __init__(self, custom_port: int = PORT):
        """
        Initialise le gestionnaire de découverte réseau.
        
        Args:
            custom_port (int): Port personnalisé pour la communication
        """
        self.port = custom_port
        self.devices: Dict[str, DeviceInfo] = {}  # Dictionnaire des appareils découverts
        self.devices_lock = threading.Lock()  # Verrou pour l'accès concurrent
        
        # Informations de l'appareil local
        self.local_hostname, self.local_ip = self._get_computer_information()
        self.local_device = DeviceInfo(self.local_hostname, self.local_ip, self.port)
        
        # Threads de gestion
        self.shouter_thread = None
        self.listener_thread = None
        self.cleaner_thread = None
        self.is_running = False
        
        logger.info(f"NetworkDiscovery initialisé - {self.local_hostname} ({self.local_ip}:{self.port})")
    
    def _get_computer_information(self) -> Tuple[str, str]:
        """
        Récupère les informations de l'ordinateur local.
        
        Returns:
            tuple: (nom_machine, adresse_ip)
        """
        try:
            # Récupération du nom de la machine
            hostname = socket.gethostname()
            
            # Méthode fiable pour obtenir l'IP locale en se connectant à une adresse externe
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Connexion vers DNS Google pour détecter l'interface réseau active
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
            
            logger.info(f"Informations locales détectées: {hostname} - {ip_address}")
            return hostname, ip_address
            
        except socket.error as e:
            # En cas d'erreur de connexion, se rabattre sur gethostbyname
            logger.warning(f"Erreur de connexion externe, utilisation de gethostbyname: {e}")
            try:
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                return hostname, ip_address
            except socket.error as e2:
                logger.error(f"Impossible de déterminer les informations réseau: {e2}")
                return "Unknown", "127.0.0.1"
    
    def _create_announcement_message(self) -> bytes:
        """
        Crée le message d'annonce à diffuser sur le réseau.
        
        Returns:
            bytes: Message encodé en JSON
        """
        message_data = {
            'type': 'datashare_announcement',
            'hostname': self.local_hostname,
            'ip_address': self.local_ip,
            'port': self.port,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0'
        }
        
        return json.dumps(message_data).encode('utf-8')
    
    def _parse_announcement_message(self, message_bytes: bytes, sender_address: Tuple[str, int]) -> Optional[DeviceInfo]:
        """
        Parse un message d'annonce reçu.
        
        Args:
            message_bytes (bytes): Message reçu
            sender_address (tuple): Adresse de l'expéditeur
            
        Returns:
            DeviceInfo: Informations de l'appareil ou None si invalide
        """
        try:
            message_str = message_bytes.decode('utf-8')
            
            # Gestion des anciens formats (rétrocompatibilité)
            if ':' in message_str and '{' not in message_str:
                # Format ancien: "hostname : ip_address"
                parts = message_str.split(' : ')
                if len(parts) == 2:
                    hostname, ip_address = parts[0].strip(), parts[1].strip()
                    return DeviceInfo(hostname, ip_address, self.port)
            
            # Format JSON moderne
            message_data = json.loads(message_str)
            
            # Validation du message
            if (message_data.get('type') == 'datashare_announcement' and
                'hostname' in message_data and 'ip_address' in message_data):
                
                hostname = message_data['hostname']
                ip_address = message_data['ip_address']
                port = message_data.get('port', self.port)
                
                # Ignore les messages de nous-mêmes
                if hostname == self.local_hostname and ip_address == self.local_ip:
                    return None
                
                return DeviceInfo(hostname, ip_address, port)
            
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as e:
            logger.debug(f"Message invalide reçu de {sender_address}: {e}")
        
        return None
    
    def _shouting_presence(self):
        """
        Thread qui diffuse périodiquement la présence de cet appareil.
        Envoie toutes les BROADCAST_INTERVAL secondes un message sur le réseau
        permettant aux autres machines DataShare de détecter cette instance.
        """
        logger.info("Démarrage du service d'annonce de présence")
        
        try:
            # Création du socket UDP pour diffusion
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as shouting_socket:
                # Activation du mode broadcast
                shouting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                
                # Préparation du message d'annonce
                message = self._create_announcement_message()
                
                while self.is_running:
                    try:
                        # Envoi du message de diffusion
                        shouting_socket.sendto(message, ('<broadcast>', self.port))
                        logger.debug(f"Message d'annonce envoyé: {self.local_hostname} ({self.local_ip})")
                        
                    except socket.error as e:
                        logger.error(f"Erreur lors de l'envoi d'annonce: {e}")
                        # Tentative de recréation du message au cas où les infos réseau auraient changé
                        self.local_hostname, self.local_ip = self._get_computer_information()
                        message = self._create_announcement_message()
                    
                    # Attendre avant le prochain envoi
                    time.sleep(BROADCAST_INTERVAL)
                    
        except Exception as e:
            logger.error(f"Erreur critique dans le service d'annonce: {e}")
        
        logger.info("Service d'annonce de présence arrêté")
    
    def _listening_for_presence(self):
        """
        Thread qui écoute les messages de diffusion sur le réseau.
        Détecte la présence d'autres appareils DataShare et les ajoute à la liste.
        """
        logger.info(f"Démarrage du service d'écoute sur le port {self.port}")
        
        try:
            # Création du socket UDP pour écoute
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener_socket:
                # Configuration du socket
                listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener_socket.settimeout(5.0)  # Timeout pour permettre l'arrêt propre
                
                # Liaison sur toutes les interfaces au port spécifié
                listener_socket.bind(('', self.port))
                
                logger.info("En attente de messages de présence...")
                
                while self.is_running:
                    try:
                        # Réception des données de présence
                        message_bytes, sender_address = listener_socket.recvfrom(MAX_MESSAGE_SIZE)
                        
                        # Parse du message reçu
                        device_info = self._parse_announcement_message(message_bytes, sender_address)
                        
                        if device_info:
                            # Mise à jour thread-safe de la liste des appareils
                            with self.devices_lock:
                                device_key = f"{device_info.hostname}_{device_info.ip_address}"
                                
                                if device_key in self.devices:
                                    # Mise à jour d'un appareil existant
                                    self.devices[device_key].update_last_seen()
                                    if not self.devices[device_key].is_online:
                                        logger.info(f"Appareil reconnecté: {device_info}")
                                        self.devices[device_key].is_online = True
                                else:
                                    # Nouvel appareil découvert
                                    self.devices[device_key] = device_info
                                    logger.info(f"Nouvel appareil détecté: {device_info}")
                    
                    except socket.timeout:
                        # Timeout normal, continue la boucle
                        continue
                    except socket.error as e:
                        if self.is_running:  # Ne log que si on n'est pas en cours d'arrêt
                            logger.error(f"Erreur lors de la réception: {e}")
                        break
                    except Exception as e:
                        logger.error(f"Erreur inattendue dans l'écoute: {e}")
                        
        except Exception as e:
            logger.error(f"Erreur critique dans le service d'écoute: {e}")
        
        logger.info("Service d'écoute arrêté")
    
    def _cleanup_expired_devices(self):
        """
        Thread qui nettoie périodiquement les appareils expirés.
        Marque comme hors ligne les appareils qui n'ont pas donné signe de vie.
        """
        logger.info("Démarrage du service de nettoyage des appareils expirés")
        
        while self.is_running:
            try:
                current_time = datetime.now()
                expired_devices = []
                
                with self.devices_lock:
                    for device_key, device_info in self.devices.items():
                        if device_info.is_expired(DEVICE_TIMEOUT):
                            if device_info.is_online:
                                device_info.is_online = False
                                expired_devices.append(device_info)
                
                # Log des appareils expirés (hors du lock pour éviter les blocages)
                for device in expired_devices:
                    logger.info(f"Appareil marqué comme déconnecté: {device}")
                
                # Attendre avant le prochain nettoyage
                time.sleep(DEVICE_TIMEOUT // 2)  # Nettoie deux fois plus souvent que le timeout
                
            except Exception as e:
                logger.error(f"Erreur dans le nettoyage des appareils: {e}")
                time.sleep(5)
        
        logger.info("Service de nettoyage arrêté")
    
    def start_discovery(self):
        """
        Démarre tous les services de découverte réseau.
        Lance les threads d'annonce, d'écoute et de nettoyage.
        """
        if self.is_running:
            logger.warning("La découverte réseau est déjà en cours")
            return
        
        logger.info("Démarrage de la découverte réseau DataShare...")
        self.is_running = True
        
        # Création et démarrage des threads
        self.shouter_thread = threading.Thread(
            target=self._shouting_presence,
            name="DataShare-Announcer",
            daemon=True
        )
        
        self.listener_thread = threading.Thread(
            target=self._listening_for_presence,
            name="DataShare-Listener",
            daemon=True
        )
        
        self.cleaner_thread = threading.Thread(
            target=self._cleanup_expired_devices,
            name="DataShare-Cleaner",
            daemon=True
        )
        
        # Démarrage des threads
        self.shouter_thread.start()
        self.listener_thread.start()
        self.cleaner_thread.start()
        
        logger.info("Tous les services de découverte sont démarrés")
    
    def stop_discovery(self):
        """
        Arrête tous les services de découverte réseau.
        """
        if not self.is_running:
            return
        
        logger.info("Arrêt de la découverte réseau...")
        self.is_running = False
        
        # Attendre la fin des threads (avec timeout)
        threads = [self.shouter_thread, self.listener_thread, self.cleaner_thread]
        for thread in threads:
            if thread and thread.is_alive():
                thread.join(timeout=2.0)
        
        logger.info("Découverte réseau arrêtée")
    
    def get_discovered_devices(self, online_only: bool = True) -> List[DeviceInfo]:
        """
        Récupère la liste des appareils découverts.
        
        Args:
            online_only (bool): Si True, ne retourne que les appareils en ligne
            
        Returns:
            List[DeviceInfo]: Liste des appareils découverts
        """
        with self.devices_lock:
            if online_only:
                return [device for device in self.devices.values() if device.is_online]
            else:
                return list(self.devices.values())
    
    def get_device_by_ip(self, ip_address: str) -> Optional[DeviceInfo]:
        """
        Recherche un appareil par son adresse IP.
        
        Args:
            ip_address (str): Adresse IP à rechercher
            
        Returns:
            DeviceInfo: Appareil trouvé ou None
        """
        with self.devices_lock:
            for device in self.devices.values():
                if device.ip_address == ip_address:
                    return device
        return None
    
    def get_device_count(self, online_only: bool = True) -> int:
        """
        Compte le nombre d'appareils découverts.
        
        Args:
            online_only (bool): Si True, ne compte que les appareils en ligne
            
        Returns:
            int: Nombre d'appareils
        """
        return len(self.get_discovered_devices(online_only))
    
    def clear_devices(self):
        """Vide la liste des appareils découverts."""
        with self.devices_lock:
            self.devices.clear()
        logger.info("Liste des appareils vidée")
    
    def get_discovery_info(self) -> Dict:
        """
        Récupère les informations complètes sur la découverte.
        
        Returns:
            dict: Informations détaillées
        """
        with self.devices_lock:
            online_devices = [d for d in self.devices.values() if d.is_online]
            offline_devices = [d for d in self.devices.values() if not d.is_online]
            
            return {
                'local_device': self.local_device.to_dict(),
                'is_running': self.is_running,
                'port': self.port,
                'total_devices': len(self.devices),
                'online_devices': len(online_devices),
                'offline_devices': len(offline_devices),
                'devices': [device.to_dict() for device in self.devices.values()]
            }


def main():
    """
    Fonction principale de démonstration du module de découverte.
    Teste toutes les fonctionnalités du système de découverte d'appareils.
    """
    print("=" * 60)
    print("🔍 DATASHARE - MODULE DE DÉCOUVERTE D'APPAREILS")
    print("=" * 60)
    
    # Initialisation du gestionnaire de découverte
    try:
        discovery = NetworkDiscovery(custom_port=32000)
        print(f"✅ Gestionnaire initialisé")
        print(f"📱 Appareil local: {discovery.local_device}")
        print(f"🔌 Port d'écoute: {discovery.port}")
        
    except Exception as e:
        print(f"❌ Erreur d'initialisation: {e}")
        return
    
    # Démarrage de la découverte
    print(f"\n🚀 Démarrage de la découverte réseau...")
    discovery.start_discovery()
    
    print(f"📡 Services actifs:")
    print(f"   • Annonce de présence (toutes les {BROADCAST_INTERVAL}s)")
    print(f"   • Écoute des autres appareils")
    print(f"   • Nettoyage automatique (timeout: {DEVICE_TIMEOUT}s)")
    
    print(f"\n💡 Instructions:")
    print(f"   • Lancez ce script sur d'autres machines du même réseau")
    print(f"   • Les appareils se découvriront automatiquement")
    print(f"   • Appuyez sur Ctrl+C pour arrêter")
    
    # Boucle de surveillance
    try:
        loop_count = 0
        while True:
            time.sleep(5)  # Mise à jour toutes les 5 secondes
            loop_count += 1
            
            # Récupération des informations de découverte
            devices = discovery.get_discovered_devices(online_only=True)
            total_devices = discovery.get_device_count(online_only=False)
            online_devices = len(devices)
            
            # Affichage du statut
            print(f"\n📊 Statut de découverte (cycle {loop_count}):")
            print(f"   🟢 Appareils en ligne: {online_devices}")
            print(f"   📱 Total découverts: {total_devices}")
            
            # Liste détaillée des appareils (toutes les 3 cycles)
            if loop_count % 3 == 0:
                print(f"\n📋 Appareils découverts:")
                if devices:
                    for i, device in enumerate(devices, 1):
                        elapsed = (datetime.now() - device.last_seen).total_seconds()
                        print(f"   {i}. {device} (vu il y a {elapsed:.0f}s)")
                else:
                    print(f"   🔍 Recherche d'appareils en cours...")
                    print(f"   💡 Lancez DataShare sur d'autres machines pour les voir apparaître")
            
            # Affichage détaillé toutes les 6 cycles
            if loop_count % 6 == 0:
                info = discovery.get_discovery_info()
                print(f"\n🔧 Informations techniques:")
                print(f"   • Services actifs: {'✅ Oui' if info['is_running'] else '❌ Non'}")
                print(f"   • Port: {info['port']}")
                print(f"   • Appareils hors ligne: {info['offline_devices']}")
    
    except KeyboardInterrupt:
        print(f"\n\n🛑 Arrêt demandé par l'utilisateur")
    
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
    
    finally:
        # Nettoyage et arrêt
        print(f"🧹 Arrêt des services de découverte...")
        discovery.stop_discovery()
        
        # Résumé final
        final_info = discovery.get_discovery_info()
        print(f"\n📈 Résumé de la session:")
        print(f"   • Appareils découverts: {final_info['total_devices']}")
        print(f"   • Appareils en ligne à la fin: {final_info['online_devices']}")
        print(f"   • Durée approximative: {loop_count * 5}s")
        
        print(f"\n✅ Module de découverte arrêté proprement")
        print(f"🎉 Merci d'avoir utilisé DataShare!")


if __name__ == "__main__":
    main()
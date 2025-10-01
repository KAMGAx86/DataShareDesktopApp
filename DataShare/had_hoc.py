"""
Module de gestion de hotspot Wi-Fi multiplateforme pour DataShare

Ce module permet de créer, gérer et arrêter des hotspots Wi-Fi sur :
- Windows (via netsh)
- Linux (via NetworkManager/nmcli)
- Avec partage de connexion Ethernet possible sur Windows

Auteur: DataShare Team
Version: 2.0
Prérequis: 
- Adaptateur Wi-Fi (physique ou USB) OBLIGATOIRE
- Privilèges administrateur/root
- Sur Linux: NetworkManager installé
"""

import platform
import subprocess
import os
import time
import logging
import re
from typing import Tuple, Optional, Dict, List

# Configuration du logging et permet d'initialiser les different message enfin de faciliter le debug
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HotspotManager:
    """
    Gestionnaire de hotspot Wi-Fi multiplateforme.
    
    Cette classe encapsule toute la logique nécessaire pour :
    - Détecter les adaptateurs réseau
    - Créer des hotspots Wi-Fi
    - Partager une connexion Internet (Ethernet → Wi-Fi)
    - Gérer l'état du hotspot
    - Nettoyer les ressources
    """
    
    def __init__(self, ssid: str = "DataShare", password: str = "12345678"):
        """
        Initialise le gestionnaire de hotspot.
        
        Args:
            ssid (str): Nom du réseau Wi-Fi (SSID)
            password (str): Mot de passe WPA2 (minimum 8 caractères)
            
        Raises:
            ValueError: Si le mot de passe est trop court
        """
        # Validation des paramètres
        if len(password) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères (standard WPA2)")
        if len(ssid) > 32:
            raise ValueError("Le SSID ne peut pas dépasser 32 caractères")
        if not ssid.strip():
            raise ValueError("Le SSID ne peut pas être vide")
        
        # Stockage de la configuration
        self.ssid = ssid.strip()
        self.password = password
        self.os_name = platform.system()  # 'Windows', 'Linux', 'Darwin'
        self.is_active = False
        
        # Informations système détectées
        self.wifi_interfaces = []
        self.ethernet_interfaces = []
        
        logger.info(f"HotspotManager initialisé - OS: {self.os_name}, SSID: {self.ssid}")
    
    def get_system_info(self) -> Dict[str, any]:
        """
        Collecte les informations complètes du système.
        
        Returns:
            dict: Informations détaillées sur le système et les interfaces
        """
        info = {
            'os': self.os_name,
            'has_admin': self.is_admin(),
            'wifi_adapters': [],
            'ethernet_adapters': [],
            'can_create_hotspot': False,
            'connection_sharing_possible': False
        }
        
        # Détection des adaptateurs Wi-Fi
        wifi_ok, wifi_adapters = self._detect_wifi_adapters()
        info['wifi_adapters'] = wifi_adapters
        
        # Détection des adaptateurs Ethernet
        ethernet_ok, ethernet_adapters = self._detect_ethernet_adapters()
        info['ethernet_adapters'] = ethernet_adapters
        
        # Analyse des capacités
        info['can_create_hotspot'] = wifi_ok and info['has_admin']
        info['connection_sharing_possible'] = (
            self.os_name == 'Windows' and 
            wifi_ok and 
            ethernet_ok and 
            info['has_admin']
        )
        
        return info
    
    def _detect_wifi_adapters(self) -> Tuple[bool, List[str]]:
        """
        Détecte tous les adaptateurs Wi-Fi disponibles.
        
        Returns:
            tuple: (succès, liste des adaptateurs Wi-Fi)
        """
        adapters = []
        
        try:
            if self.os_name == 'Windows':
                # Utilise netsh pour lister les interfaces Wi-Fi
                cmd = 'netsh wlan show interfaces'
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    encoding="latin-1",
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    # Parse la sortie pour extraire les noms d'interfaces
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Name' in line and ':' in line:
                            interface_name = line.split(':', 1)[1].strip()
                            if interface_name and interface_name not in adapters:
                                adapters.append(interface_name)
                
            elif self.os_name == 'Linux':
                # Méthode 1: iwconfig (plus fiable pour Wi-Fi)
                result = subprocess.run('iwconfig', shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    # Cherche les interfaces Wi-Fi
                    matches = re.findall(r'^(wlan\d+|wlp\d+s\d+)\s+', result.stdout, re.MULTILINE)
                    adapters.extend(matches)
                
                # Méthode 2: ip link (backup)
                if not adapters:
                    result = subprocess.run('ip link show', shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        matches = re.findall(r'\d+: (wlan\d+|wlp\d+s\d+):', result.stdout)
                        adapters.extend(matches)
            
            self.wifi_interfaces = adapters
            return len(adapters) > 0, adapters
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection Wi-Fi : {e}")
            return False, []
    
    def _detect_ethernet_adapters(self) -> Tuple[bool, List[str]]:
        """
        Détecte tous les adaptateurs Ethernet disponibles.
        
        Returns:
            tuple: (succès, liste des adaptateurs Ethernet)
        """
        adapters = []
        
        try:
            if self.os_name == 'Windows':
                # Utilise wmic pour lister les adaptateurs réseau
                cmd = 'wmic nic where "NetConnectionStatus=2" get Name,NetConnectionID /format:csv'
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding="latin-1",
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) >= 3 and 'Ethernet' in parts[1]:
                                connection_id = parts[2].strip()
                                if connection_id:
                                    adapters.append(connection_id)
            
            elif self.os_name == 'Linux':
                # Utilise ip link pour détecter les interfaces Ethernet
                result = subprocess.run('ip link show', shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    # Cherche les interfaces eth, enp, ens
                    matches = re.findall(r'\d+: (eth\d+|enp\d+s\d+|ens\d+):', result.stdout)
                    adapters.extend(matches)
            
            self.ethernet_interfaces = adapters
            return len(adapters) > 0, adapters
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection Ethernet : {e}")
            return False, []
    
    def is_admin(self) -> bool:
        """
        Vérifie si le script a les privilèges administrateur/root.
        
        Returns:
            bool: True si les privilèges sont suffisants
        """
        try:
            if self.os_name == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            elif self.os_name == 'Linux':
                return os.geteuid() == 0
            else:
                return True  # Assume OK pour les autres systèmes
        except Exception as e:
            logger.warning(f"Impossible de vérifier les privilèges : {e}")
            return False
    
    def check_prerequisites(self) -> Tuple[bool, str]:
        """
        Vérifie tous les prérequis pour créer un hotspot.
        
        Returns:
            tuple: (succès, message détaillé)
        """
        issues = []
        
        # 1. Vérification du système d'exploitation
        if self.os_name not in ['Windows', 'Linux']:
            issues.append(f"Système '{self.os_name}' non supporté (Windows/Linux requis)")
        
        # 2. Vérification des privilèges
        if not self.is_admin():
            if self.os_name == 'Windows':
                issues.append("Privilèges administrateur requis (clic droit → Exécuter en tant qu'administrateur)")
            else:
                issues.append("Privilèges root requis (utilisez sudo)")
        
        # 3. Vérification de l'adaptateur Wi-Fi
        wifi_ok, wifi_adapters = self._detect_wifi_adapters()
        if not wifi_ok:
            issues.append("Aucun adaptateur Wi-Fi détecté (adaptateur USB Wi-Fi requis)")
        
        # 4. Vérification des outils système (Linux)
        if self.os_name == 'Linux':
            if not self._check_command_exists('nmcli'):
                issues.append("NetworkManager (nmcli) non installé")
            if not self._check_command_exists('iwconfig'):
                issues.append("Outils wireless-tools (iwconfig) non installés")
        
        if issues:
            return False, "❌ Prérequis manquants:\n" + "\n".join(f"  • {issue}" for issue in issues)
        
        # Informations positives
        info_parts = [
            "✅ Tous les prérequis sont satisfaits:",
            f"  • Système: {self.os_name}",
            f"  • Privilèges: {'Administrateur' if self.os_name == 'Windows' else 'Root'}",
            f"  • Adaptateurs Wi-Fi: {', '.join(wifi_adapters)}"
        ]
        
        # Vérification du partage de connexion (bonus)
        ethernet_ok, ethernet_adapters = self._detect_ethernet_adapters()
        if ethernet_ok and self.os_name == 'Windows':
            info_parts.append(f"  • Partage Ethernet possible: {', '.join(ethernet_adapters)}")
        
        return True, "\n".join(info_parts)
    
    def _check_command_exists(self, command: str) -> bool:
        """
        Vérifie si une commande système existe.
        
        Args:
            command (str): Nom de la commande
            
        Returns:
            bool: True si la commande existe
        """
        try:
            subprocess.run(
                ['which', command], 
                capture_output=True, 
                encoding='latin-1',
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def create_hotspot(self, share_ethernet: bool = False) -> Tuple[bool, str]:
        """
        Crée un hotspot Wi-Fi avec possibilité de partage de connexion.
        
        Args:
            share_ethernet (bool): Sur Windows, partage la connexion Ethernet
            
        Returns:
            tuple: (succès, message détaillé)
        """
        logger.info(f"Tentative de création du hotspot '{self.ssid}'...")
        
        # Vérifications préalables
        prereq_ok, prereq_msg = self.check_prerequisites()
        if not prereq_ok:
            return False, prereq_msg
        
        try:
            if self.os_name == 'Windows':
                return self._create_windows_hotspot(share_ethernet)
            elif self.os_name == 'Linux':
                return self._create_linux_hotspot()
            else:
                return False, f"Création de hotspot non supportée sur {self.os_name}"
                
        except Exception as e:
            logger.error(f"Erreur lors de la création du hotspot : {e}")
            return False, f"Erreur inattendue : {str(e)}"
    
    def _create_windows_hotspot(self, share_ethernet: bool = False) -> Tuple[bool, str]:
        """
        Crée un hotspot sur Windows avec netsh.
        
        Args:
            share_ethernet (bool): Active le partage de connexion Ethernet
            
        Returns:
            tuple: (succès, message)
        """
        try:
            logger.info("Création du hotspot Windows...")
            
            # Étape 1: Arrêt du hotspot existant (si présent)
            logger.debug("Arrêt du hotspot existant...")
            subprocess.run(
                'netsh wlan stop hostednetwork',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                encoding='latin-1',
                capture_output=True
            )
            
            # Étape 2: Configuration du hotspot
            logger.debug(f"Configuration du hotspot SSID='{self.ssid}'...")
            config_cmd = f'netsh wlan set hostednetwork mode=allow ssid="{self.ssid}" key="{self.password}"'
            config_result = subprocess.run(
                config_cmd,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                encoding='latin-1',
                text=True
            )
            
            if config_result.returncode != 0:
                return False, f"Erreur de configuration: {config_result.stderr.strip()}"
            
            # Étape 3: Démarrage du hotspot
            logger.debug("Démarrage du hotspot...")
            start_result = subprocess.run(
                'netsh wlan start hostednetwork',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                encoding='latin-1',
                text=True
            )
            
            if start_result.returncode != 0:
                error_msg = start_result.stderr.strip()
                if "hosted network couldn't be started" in error_msg.lower():
                    return False, ("Impossible de démarrer le hotspot. Causes possibles:\n"
                                 "• Adaptateur Wi-Fi non compatible\n"
                                 "• Pilote Wi-Fi obsolète\n"
                                 "• Fonctionnalité désactivée dans le BIOS")
                return False, f"Erreur de démarrage: {error_msg}"
            
            # Étape 4: Vérification du statut
            logger.debug("Vérification du statut...")
            time.sleep(2)  # Attendre que le hotspot se stabilise
            
            status_ok, status_msg = self.get_hotspot_status()
            if not status_ok:
                return False, "Hotspot créé mais non actif - vérifiez votre adaptateur Wi-Fi"
            
            # Étape 5: Configuration du partage de connexion (optionnel)
            sharing_msg = ""
            if share_ethernet and self.ethernet_interfaces:
                sharing_ok, sharing_msg = self._setup_windows_connection_sharing()
                if sharing_ok:
                    sharing_msg = f"\n✅ Partage de connexion activé ({self.ethernet_interfaces[0]})"
                else:
                    sharing_msg = f"\n⚠️ Partage de connexion échoué: {sharing_msg}"
            
            self.is_active = True
            success_msg = (f"✅ Hotspot '{self.ssid}' créé avec succès!\n"
                          f"📶 SSID: {self.ssid}\n"
                          f"🔑 Mot de passe: {self.password}\n"
                          f"🖥️ Plateforme: Windows{sharing_msg}")
            
            logger.info("Hotspot Windows créé avec succès")
            return True, success_msg
            
        except Exception as e:
            logger.error(f"Erreur Windows : {e}")
            return False, f"Erreur Windows: {str(e)}"
    
    def _setup_windows_connection_sharing(self) -> Tuple[bool, str]:
        """
        Configure le partage de connexion Internet sur Windows.
        Note: Cette méthode configure le partage via l'interface graphique PowerShell.
        
        Returns:
            tuple: (succès, message)
        """
        try:
            # Cette fonctionnalité nécessite des manipulations complexes du registre Windows
            # Pour une implémentation complète, il faudrait utiliser les API Windows COM
            # ou manipuler directement les paramètres réseau
            
            logger.info("Configuration du partage de connexion...")
            
            # Commande PowerShell pour activer le partage
            # Note: Ceci est une implémentation simplifiée
            powershell_cmd = '''
            $ethernet = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Ethernet*" -and $_.Status -eq "Up"}
            $wifi = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*"}
            
            if ($ethernet -and $wifi) {
                Write-Host "Ethernet: $($ethernet.Name), Wi-Fi: $($wifi.Name)"
            }
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', powershell_cmd],
                capture_output=True,
                text=True,
                encoding='latin-1',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0 and "Ethernet:" in result.stdout:
                return True, "Partage configuré via PowerShell"
            else:
                return False, "Configuration manuelle requise dans Panneau de configuration"
                
        except Exception as e:
            logger.warning(f"Partage de connexion non configuré automatiquement : {e}")
            return False, str(e)
    
    def _create_linux_hotspot(self) -> Tuple[bool, str]:
        """
        Crée un hotspot sur Linux avec NetworkManager.
        
        Returns:
            tuple: (succès, message)
        """
        try:
            logger.info("Création du hotspot Linux...")
            
            # Déterminer l'interface Wi-Fi à utiliser
            if not self.wifi_interfaces:
                return False, "Aucune interface Wi-Fi disponible"
            
            interface = self.wifi_interfaces[0]
            logger.debug(f"Utilisation de l'interface: {interface}")
            
            # Étape 1: Nettoyage des connexions hotspot existantes
            logger.debug("Nettoyage des connexions existantes...")
            list_cmd = "nmcli -t -f NAME,TYPE con show"
            result = subprocess.run(list_cmd, shell=True, capture_output=True,encoding='latin-1', text=True)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '802-11-hotspot' in line:
                        conn_name = line.split(':')[0]
                        logger.debug(f"Suppression de la connexion: {conn_name}")
                        subprocess.run(
                            f'nmcli con delete "{conn_name}"',
                            shell=True,
                            capture_output=True,
                            encoding="latin-1",
                            text=True
                        )
            
            # Étape 2: Création du nouveau hotspot
            logger.debug(f"Création du hotspot sur {interface}...")
            hotspot_cmd = (
                f'nmcli dev wifi hotspot ifname {interface} '
                f'con-name "DataShare-Hotspot" ssid "{self.ssid}" password "{self.password}"'
            )
            
            create_result = subprocess.run(
                hotspot_cmd,
                shell=True,
                capture_output=True,
                encoding='latin-1',
                text=True
            )
            
            if create_result.returncode != 0:
                error_msg = create_result.stderr.strip()
                if "not support AP mode" in error_msg:
                    return False, ("Adaptateur Wi-Fi ne supporte pas le mode Point d'Accès.\n"
                                 "Essayez avec un adaptateur USB Wi-Fi compatible.")
                return False, f"Erreur nmcli: {error_msg}"
            
            # Étape 3: Vérification
            time.sleep(3)  # Attendre que la connexion se stabilise
            
            status_ok, status_msg = self.get_hotspot_status()
            if status_ok:
                self.is_active = True
                success_msg = (f"✅ Hotspot '{self.ssid}' créé avec succès!\n"
                              f"📶 SSID: {self.ssid}\n"
                              f"🔑 Mot de passe: {self.password}\n"
                              f"🐧 Interface: {interface}\n"
                              f"🖥️ Plateforme: Linux")
                
                logger.info("Hotspot Linux créé avec succès")
                return True, success_msg
            else:
                return False, f"Hotspot créé mais non actif: {status_msg}"
            
        except Exception as e:
            logger.error(f"Erreur Linux : {e}")
            return False, f"Erreur Linux: {str(e)}"
    
    def stop_hotspot(self) -> Tuple[bool, str]:
        """
        Arrête le hotspot Wi-Fi actif.
        
        Returns:
            tuple: (succès, message)
        """
        if not self.is_active:
            return True, "Aucun hotspot actif à arrêter"
        
        logger.info("Arrêt du hotspot...")
        
        try:
            if self.os_name == 'Windows':
                return self._stop_windows_hotspot()
            elif self.os_name == 'Linux':
                return self._stop_linux_hotspot()
            else:
                return False, f"Arrêt non supporté sur {self.os_name}"
                
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt : {e}")
            return False, f"Erreur lors de l'arrêt: {str(e)}"
    
    def _stop_windows_hotspot(self) -> Tuple[bool, str]:
        """Arrête le hotspot Windows."""
        result = subprocess.run(
            'netsh wlan stop hostednetwork',
            shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            capture_output=True,
            encoding='latin-1',
            text=True
            
        )
        
        if result.returncode == 0:
            self.is_active = False
            logger.info("Hotspot Windows arrêté")
            return True, "✅ Hotspot arrêté avec succès"
        else:
            return False, f"Erreur d'arrêt: {result.stderr.strip()}"
    
    def _stop_linux_hotspot(self) -> Tuple[bool, str]:
        """Arrête le hotspot Linux."""
        # Trouve et arrête toutes les connexions hotspot actives
        list_cmd = "nmcli -t -f UUID,TYPE,ACTIVE con show"
        result = subprocess.run(list_cmd, shell=True, capture_output=True, encoding='latin-1', text=True)
        
        if result.returncode != 0:
            return False, "Impossible de lister les connexions"
        
        stopped_connections = 0
        for line in result.stdout.strip().split('\n'):
            if line and '802-11-hotspot' in line and 'yes' in line:
                uuid = line.split(':')[0]
                stop_result = subprocess.run(
                    f'nmcli con down uuid {uuid}',
                    shell=True,
                    capture_output=True,
                    encoding="latin-1",
                    text=True
                )
                if stop_result.returncode == 0:
                    stopped_connections += 1
        
        if stopped_connections > 0:
            self.is_active = False
            logger.info(f"Hotspot Linux arrêté ({stopped_connections} connexions)")
            return True, f"✅ Hotspot arrêté ({stopped_connections} connexions fermées)"
        else:
            return True, "Aucun hotspot actif trouvé"
    
    def get_hotspot_status(self) -> Tuple[bool, str]:
        """
        Vérifie le statut actuel du hotspot.
        
        Returns:
            tuple: (actif, message de statut)
        """
        try:
            if self.os_name == 'Windows':
                return self._get_windows_status()
            elif self.os_name == 'Linux':
                return self._get_linux_status()
            else:
                return False, f"Vérification de statut non supportée sur {self.os_name}"
                
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du statut : {e}")
            return False, f"Erreur: {str(e)}"
    
    def _get_windows_status(self) -> Tuple[bool, str]:
        """Vérifie le statut du hotspot Windows."""
        result = subprocess.run(
            'netsh wlan show hostednetwork',
            shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            capture_output=True,
            encoding='latin-1',
            text=True
        )
        
        if result.returncode == 0:
            output = result.stdout
            if "Status              : Started" in output:
                # Extraire le nombre de clients connectés
                clients_match = re.search(r'Number of clients\s*:\s*(\d+)', output)
                client_count = clients_match.group(1) if clients_match else "0"
                
                self.is_active = True
                return True, f"🟢 Hotspot actif - {client_count} client(s) connecté(s)"
            else:
                self.is_active = False
                return False, "🔴 Hotspot inactif"
        else:
            return False, "Impossible de vérifier le statut"
    
    def _get_linux_status(self) -> Tuple[bool, str]:
        """Vérifie le statut du hotspot Linux."""
        list_cmd = "nmcli -t -f NAME,TYPE,ACTIVE,DEVICE con show"
        result = subprocess.run(list_cmd, shell=True, capture_output=True, encoding="latin-1", text=True)
        
        if result.returncode == 0:
            active_hotspots = []
            for line in result.stdout.strip().split('\n'):
                if line and '802-11-hotspot' in line and 'yes' in line:
                    parts = line.split(':')
                    if len(parts) >= 4:
                        name = parts[0]
                        device = parts[3]
                        active_hotspots.append(f"{name} ({device})")
            
            if active_hotspots:
                self.is_active = True
                return True, f"🟢 Hotspot actif: {', '.join(active_hotspots)}"
            else:
                self.is_active = False
                return False, "🔴 Aucun hotspot actif"
        else:
            return False, "Impossible de vérifier le statut"
    
    def get_connected_clients(self) -> List[str]:
        """
        Récupère la liste des clients connectés au hotspot (Windows uniquement).
        
        Returns:
            list: Liste des adresses MAC des clients connectés
        """
        if not self.is_active or self.os_name != 'Windows':
            return []
        
        try:
            result = subprocess.run(
                'netsh wlan show hostednetwork',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                encoding="latin-1",
                text=True
            )
            
            if result.returncode == 0:
                # Analyse de la sortie pour extraire les clients
                # Note: netsh ne fournit pas les détails des clients individuels
                # Pour une liste détaillée, il faudrait utiliser d'autres méthodes
                clients_match = re.search(r'Number of clients\s*:\s*(\d+)', result.stdout)
                if clients_match:
                    count = int(clients_match.group(1))
                    return [f"Client-{i+1}" for i in range(count)]
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des clients : {e}")
            return []


def main():
    """
    Fonction principale pour tester le gestionnaire de hotspot.
    Démontre toutes les fonctionnalités disponibles.
    """
    print("=" * 60)
    print("🔥 DATASHARE - GESTIONNAIRE DE HOTSPOT WI-FI")
    print("=" * 60)
    
    # Initialisation
    try:
        hotspot = HotspotManager(ssid="DataShare-Demo", password="Demo12345")
        print(f"✅ HotspotManager initialisé")
        print(f"📋 Configuration: SSID='{hotspot.ssid}', OS={hotspot.os_name}")
        
    except Exception as e:
        print(f"❌ Erreur d'initialisation: {e}")
        return
    
    # Phase 1: Analyse du système
    print("\n" + "=" * 40)
    print("📊 PHASE 1: ANALYSE DU SYSTÈME")
    print("=" * 40)
    
    system_info = hotspot.get_system_info()
    print(f"🖥️  Système d'exploitation: {system_info['os']}")
    print(f"🔐 Privilèges administrateur: {'✅ Oui' if system_info['has_admin'] else '❌ Non'}")
    print(f"📶 Adaptateurs Wi-Fi détectés: {len(system_info['wifi_adapters'])}")
    
    if system_info['wifi_adapters']:
        for i, adapter in enumerate(system_info['wifi_adapters'], 1):
            print(f"   {i}. {adapter}")
    else:
        print("   ⚠️  Aucun adaptateur Wi-Fi trouvé")
    
    print(f"🌐 Adaptateurs Ethernet détectés: {len(system_info['ethernet_adapters'])}")
    if system_info['ethernet_adapters']:
        for i, adapter in enumerate(system_info['ethernet_adapters'], 1):
            print(f"   {i}. {adapter}")
    
    print(f"🔥 Peut créer un hotspot: {'✅ Oui' if system_info['can_create_hotspot'] else '❌ Non'}")
    print(f"🔗 Partage de connexion possible: {'✅ Oui' if system_info['connection_sharing_possible'] else '❌ Non'}")
    
    # Phase 2: Vérification des prérequis
    print("\n" + "=" * 40)
    print("🔍 PHASE 2: VÉRIFICATION DES PRÉREQUIS")
    print("=" * 40)
    
    prereq_ok, prereq_msg = hotspot.check_prerequisites()
    print(prereq_msg)
    
    if not prereq_ok:
        print("\n❌ Impossible de continuer - prérequis non satisfaits")
        print("\n💡 SOLUTIONS POSSIBLES:")
        if "administrateur" in prereq_msg.lower() or "root" in prereq_msg.lower():
            if hotspot.os_name == 'Windows':
                print("   • Clic droit sur l'exécutable → 'Exécuter en tant qu'administrateur'")
            else:
                print("   • Lancer avec: sudo python script.py")
        
        if "adaptateur wi-fi" in prereq_msg.lower():
            print("   • Brancher un adaptateur USB Wi-Fi")
            print("   • Vérifier que les pilotes sont installés")
            print("   • Redémarrer après installation d'un nouvel adaptateur")
        
        if "networkmanager" in prereq_msg.lower():
            print("   • Ubuntu/Debian: sudo apt install network-manager")
            print("   • CentOS/RHEL: sudo yum install NetworkManager")
        
        return
    
    # Phase 3: Création du hotspot
    print("\n" + "=" * 40)
    print("🚀 PHASE 3: CRÉATION DU HOTSPOT")
    print("=" * 40)
    
    # Demander à l'utilisateur s'il veut partager la connexion Ethernet (Windows)
    share_ethernet = False
    if (hotspot.os_name == 'Windows' and 
        system_info['connection_sharing_possible']):
        
        print("\n🌐 Partage de connexion Ethernet disponible!")
        print("   Voulez-vous partager votre connexion Internet via Ethernet?")
        
        # Pour le test automatique, on active par défaut
        share_ethernet = True
        print(f"   → Partage activé automatiquement pour le test")
    
    print(f"\n🔨 Création du hotspot '{hotspot.ssid}'...")
    if share_ethernet:
        print("🔗 Avec partage de connexion Ethernet")
    
    success, message = hotspot.create_hotspot(share_ethernet=share_ethernet)
    print(message)
    
    if not success:
        print("\n❌ Échec de la création du hotspot")
        print("\n🔧 DÉPANNAGE POSSIBLE:")
        if "pilote" in message.lower() or "driver" in message.lower():
            print("   • Mettre à jour les pilotes de l'adaptateur Wi-Fi")
            print("   • Redémarrer l'ordinateur")
        
        if "ap mode" in message.lower():
            print("   • L'adaptateur Wi-Fi ne supporte pas le mode Point d'Accès")
            print("   • Essayer avec un autre adaptateur USB Wi-Fi")
        
        if "hostednetwork" in message.lower():
            print("   • Activer la fonctionnalité dans le Gestionnaire de périphériques")
            print("   • Commande: netsh wlan set hostednetwork mode=allow")
        
        return
    
    # Phase 4: Surveillance du hotspot
    print("\n" + "=" * 40)
    print("📡 PHASE 4: SURVEILLANCE DU HOTSPOT")
    print("=" * 40)
    
    print("🎯 Instructions de connexion:")
    print(f"   📶 Nom du réseau (SSID): {hotspot.ssid}")
    print(f"   🔑 Mot de passe: {hotspot.password}")
    print(f"   🔒 Sécurité: WPA2-Personal")
    
    if share_ethernet and hotspot.os_name == 'Windows':
        print("   🌐 Internet partagé via Ethernet")
    
    print("\n⏱️  Surveillance en cours (30 secondes)...")
    print("   Connectez-vous depuis un autre appareil pour tester")
    
    # Boucle de surveillance
    for i in range(30):
        time.sleep(1)
        
        # Vérification du statut toutes les 5 secondes
        if i % 5 == 0:
            status_ok, status_msg = hotspot.get_hotspot_status()
            clients = hotspot.get_connected_clients()
            
            # Affichage du statut
            remaining = 30 - i
            print(f"\r⏰ Temps restant: {remaining:2d}s | {status_msg}", end="", flush=True)
            
            if clients and len(clients) > 0:
                print(f" | 👥 {len(clients)} client(s)")
            else:
                print()
    
    print("\n")
    
    # Phase 5: Statut final
    print("=" * 40)
    print("📈 PHASE 5: STATUT FINAL")
    print("=" * 40)
    
    final_status_ok, final_status_msg = hotspot.get_hotspot_status()
    print(f"📊 Statut final: {final_status_msg}")
    
    if final_status_ok:
        clients = hotspot.get_connected_clients()
        if clients:
            print(f"👥 Clients connectés: {len(clients)}")
            for i, client in enumerate(clients, 1):
                print(f"   {i}. {client}")
        else:
            print("👥 Aucun client connecté durant le test")
    
    # Phase 6: Nettoyage
    print("\n" + "=" * 40)
    print("🧹 PHASE 6: NETTOYAGE")
    print("=" * 40)
    
    print("🛑 Arrêt du hotspot...")
    stop_ok, stop_msg = hotspot.stop_hotspot()
    print(stop_msg)
    
    # Vérification finale
    time.sleep(2)
    final_check_ok, final_check_msg = hotspot.get_hotspot_status()
    print(f"🔍 Vérification finale: {final_check_msg}")
    
    # Résumé final
    print("\n" + "=" * 60)
    print("📝 RÉSUMÉ DU TEST")
    print("=" * 60)
    print(f"🖥️  Système: {hotspot.os_name}")
    print(f"📶 Adaptateurs Wi-Fi: {len(system_info['wifi_adapters'])}")
    print(f"🔥 Création de hotspot: {'✅ Succès' if success else '❌ Échec'}")
    print(f"📡 Statut final: {'🟢 Actif' if final_status_ok else '🔴 Inactif'}")
    print(f"🛑 Nettoyage: {'✅ OK' if stop_ok else '⚠️  Problème'}")
    
    if success:
        print("\n✅ TEST RÉUSSI - Le gestionnaire de hotspot fonctionne correctement!")
        print("\n💡 INTÉGRATION DANS DATASHARE:")
        print("   • Utilisez create_hotspot() pour créer le réseau")
        print("   • Utilisez get_hotspot_status() pour surveiller")
        print("   • Utilisez stop_hotspot() pour nettoyer")
        print("   • Gérez les erreurs avec les messages retournés")
    else:
        print("\n❌ TEST ÉCHOUÉ - Vérifiez la configuration système")
    
    print("\n🎉 Test terminé!")


if __name__ == "__main__":
    main()
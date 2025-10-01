"""
Gestionnaire de paramètres et configuration pour DataShare

Ce module gère :
- Configuration utilisateur (nom, préférences)
- Paramètres réseau (ports, timeouts)
- Dossiers par défaut
- Historique des transferts
- Liste des contacts/appareils de confiance
- Paramètres de sécurité
- Thème et interface

Auteur: DataShare Team
Version: 1.0
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class UserProfile:
    """Profil utilisateur DataShare."""
    username: str = "DataShare User"
    user_id: str = ""
    avatar_path: str = ""
    created_at: float = 0.0
    last_active: float = 0.0
    total_files_sent: int = 0
    total_files_received: int = 0
    total_bytes_transferred: int = 0

@dataclass
class NetworkSettings:
    """Paramètres réseau."""
    discovery_port: int = 32000
    transfer_port: int = 32001
    hotspot_ssid_prefix: str = "DataShare"
    auto_create_hotspot: bool = True
    auto_accept_known_devices: bool = False
    connection_timeout: int = 30
    max_concurrent_transfers: int = 5
    chunk_size_auto_adjust: bool = True
    preferred_chunk_size: int = 1048576  # 1MB

@dataclass
class StorageSettings:
    """Paramètres de stockage."""
    default_download_folder: str = ""
    auto_organize_downloads: bool = False
    show_hidden_files: bool = False
    compression_threshold: int = 10485760  # 10MB
    auto_compression: bool = True
    keep_transfer_history: bool = True
    max_history_entries: int = 1000

@dataclass
class SecuritySettings:
    """Paramètres de sécurité."""
    require_confirmation: bool = True
    auto_accept_from_trusted: bool = False
    enable_file_validation: bool = True
    quarantine_unknown_files: bool = False
    max_file_size: int = 1073741824  # 1GB
    blocked_extensions: List[str] = field(default_factory=lambda: ['.exe', '.scr', '.bat'])

@dataclass
class InterfaceSettings:
    """Paramètres d'interface."""
    theme: str = "light"  # light, dark, auto
    language: str = "fr"
    show_notifications: bool = True
    minimize_to_tray: bool = True
    auto_start: bool = False
    window_width: int = 1200
    window_height: int = 800

@dataclass
class TrustedDevice:
    """Appareil de confiance."""
    device_id: str
    name: str
    ip_address: str
    last_seen: float
    trust_level: str = "trusted"  # trusted, blocked, unknown
    auto_accept: bool = False
    note: str = ""

class SettingsManager:
    """Gestionnaire principal des paramètres DataShare."""
    
    def __init__(self, config_dir: Optional[str] = None):
        # Déterminer le dossier de configuration
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = self._get_default_config_dir()
        
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Fichiers de configuration
        self.config_file = self.config_dir / "settings.json"
        self.devices_file = self.config_dir / "trusted_devices.json"
        self.history_file = self.config_dir / "transfer_history.json"
        
        # Paramètres par défaut
        self.user_profile = UserProfile()
        self.network_settings = NetworkSettings()
        self.storage_settings = StorageSettings()
        self.security_settings = SecuritySettings()
        self.interface_settings = InterfaceSettings()
        
        # Liste des appareils de confiance
        self.trusted_devices: Dict[str, TrustedDevice] = {}
        
        # Historique des transferts
        self.transfer_history: List[Dict[str, Any]] = []
        
        # Charger la configuration existante
        self._initialize_settings()
        
        logger.info(f"SettingsManager initialisé - Config: {self.config_dir}")
    
    def _get_default_config_dir(self) -> Path:
        """Obtient le dossier de configuration par défaut selon l'OS."""
        import platform
        
        system = platform.system()
        home = Path.home()
        
        if system == "Windows":
            # %APPDATA%/DataShare
            appdata = os.getenv('APPDATA', home / 'AppData' / 'Roaming')
            return Path(appdata) / 'DataShare'
        elif system == "Darwin":  # macOS
            # ~/Library/Application Support/DataShare
            return home / 'Library' / 'Application Support' / 'DataShare'
        else:  # Linux et autres Unix
            # ~/.config/DataShare
            config_home = os.getenv('XDG_CONFIG_HOME', home / '.config')
            return Path(config_home) / 'DataShare'
    
    def _initialize_settings(self):
        """Initialise les paramètres depuis les fichiers ou crée les défauts."""
        # Charger les paramètres principaux
        self.load_settings()
        
        # Charger les appareils de confiance
        self.load_trusted_devices()
        
        # Charger l'historique
        self.load_transfer_history()
        
        # Initialiser le profil utilisateur si nécessaire
        if not self.user_profile.user_id:
            self._generate_user_id()
            self._set_default_download_folder()
            self.user_profile.created_at = datetime.now().timestamp()
            self.save_settings()
    
    def _generate_user_id(self):
        """Génère un ID utilisateur unique."""
        import uuid
        import socket
        
        # Combinaison de plusieurs éléments pour unicité
        elements = [
            str(uuid.uuid4()),
            socket.gethostname(),
            str(datetime.now().timestamp())
        ]
        
        combined = ''.join(elements)
        self.user_profile.user_id = hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def _set_default_download_folder(self):
        """Définit le dossier de téléchargement par défaut."""
        if not self.storage_settings.default_download_folder:
            downloads_folder = Path.home() / "Downloads" / "DataShare"
            self.storage_settings.default_download_folder = str(downloads_folder)
    
    def load_settings(self) -> bool:
        """Charge les paramètres depuis le fichier."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Charger chaque section
                if 'user_profile' in data:
                    self.user_profile = UserProfile(**data['user_profile'])
                
                if 'network_settings' in data:
                    self.network_settings = NetworkSettings(**data['network_settings'])
                
                if 'storage_settings' in data:
                    self.storage_settings = StorageSettings(**data['storage_settings'])
                
                if 'security_settings' in data:
                    self.security_settings = SecuritySettings(**data['security_settings'])
                
                if 'interface_settings' in data:
                    self.interface_settings = InterfaceSettings(**data['interface_settings'])
                
                logger.info("Paramètres chargés depuis le fichier")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des paramètres : {e}")
        
        return False
    
    def save_settings(self) -> bool:
        """Sauvegarde les paramètres dans le fichier."""
        try:
            # Mettre à jour la dernière activité
            self.user_profile.last_active = datetime.now().timestamp()
            
            # Créer la structure de données
            data = {
                'user_profile': asdict(self.user_profile),
                'network_settings': asdict(self.network_settings),
                'storage_settings': asdict(self.storage_settings),
                'security_settings': asdict(self.security_settings),
                'interface_settings': asdict(self.interface_settings),
                'saved_at': datetime.now().isoformat()
            }
            
            # Sauvegarder
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info("Paramètres sauvegardés")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des paramètres : {e}")
            return False
    
    def load_trusted_devices(self) -> bool:
        """Charge la liste des appareils de confiance."""
        try:
            if self.devices_file.exists():
                with open(self.devices_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.trusted_devices = {}
                for device_id, device_data in data.get('devices', {}).items():
                    self.trusted_devices[device_id] = TrustedDevice(**device_data)
                
                logger.info(f"Chargé {len(self.trusted_devices)} appareils de confiance")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des appareils de confiance : {e}")
        
        return False
    
    def save_trusted_devices(self) -> bool:
        """Sauvegarde la liste des appareils de confiance."""
        try:
            data = {
                'devices': {device_id: asdict(device) 
                           for device_id, device in self.trusted_devices.items()},
                'saved_at': datetime.now().isoformat()
            }
            
            with open(self.devices_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info("Appareils de confiance sauvegardés")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des appareils de confiance : {e}")
            return False
    
    def add_trusted_device(self, device_id: str, name: str, ip_address: str, 
                          trust_level: str = "trusted", auto_accept: bool = False) -> bool:
        """Ajoute un appareil à la liste de confiance."""
        try:
            device = TrustedDevice(
                device_id=device_id,
                name=name,
                ip_address=ip_address,
                last_seen=datetime.now().timestamp(),
                trust_level=trust_level,
                auto_accept=auto_accept
            )
            
            self.trusted_devices[device_id] = device
            self.save_trusted_devices()
            
            logger.info(f"Appareil ajouté à la liste de confiance : {name}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de l'appareil de confiance : {e}")
            return False
    
    def update_device_last_seen(self, device_id: str, ip_address: Optional[str] = None):
        """Met à jour la dernière activité d'un appareil."""
        if device_id in self.trusted_devices:
            device = self.trusted_devices[device_id]
            device.last_seen = datetime.now().timestamp()
            if ip_address:
                device.ip_address = ip_address
            self.save_trusted_devices()
    
    def is_device_trusted(self, device_id: str) -> bool:
        """Vérifie si un appareil est de confiance."""
        device = self.trusted_devices.get(device_id)
        return device is not None and device.trust_level == "trusted"
    
    def is_device_blocked(self, device_id: str) -> bool:
        """Vérifie si un appareil est bloqué."""
        device = self.trusted_devices.get(device_id)
        return device is not None and device.trust_level == "blocked"
    
    def should_auto_accept_from_device(self, device_id: str) -> bool:
        """Vérifie si les transferts de cet appareil doivent être auto-acceptés."""
        device = self.trusted_devices.get(device_id)
        return (device is not None and 
                device.trust_level == "trusted" and 
                device.auto_accept and 
                self.security_settings.auto_accept_from_trusted)
    
    def load_transfer_history(self) -> bool:
        """Charge l'historique des transferts."""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.transfer_history = data.get('history', [])
                
                # Limiter la taille de l'historique
                max_entries = self.storage_settings.max_history_entries
                if len(self.transfer_history) > max_entries:
                    self.transfer_history = self.transfer_history[-max_entries:]
                
                logger.info(f"Historique chargé : {len(self.transfer_history)} entrées")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement de l'historique : {e}")
        
        return False
    
    def save_transfer_history(self) -> bool:
        """Sauvegarde l'historique des transferts."""
        if not self.storage_settings.keep_transfer_history:
            return True
        
        try:
            data = {
                'history': self.transfer_history,
                'saved_at': datetime.now().isoformat()
            }
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info("Historique des transferts sauvegardé")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de l'historique : {e}")
            return False
    
    def add_transfer_to_history(self, transfer_data: Dict[str, Any]):
        """Ajoute un transfert à l'historique."""
        if not self.storage_settings.keep_transfer_history:
            return
        
        # Ajouter timestamp si absent
        if 'timestamp' not in transfer_data:
            transfer_data['timestamp'] = datetime.now().timestamp()
        
        self.transfer_history.append(transfer_data)
        
        # Limiter la taille
        max_entries = self.storage_settings.max_history_entries
        if len(self.transfer_history) > max_entries:
            self.transfer_history = self.transfer_history[-max_entries:]
        
        # Mettre à jour les statistiques utilisateur
        if transfer_data.get('direction') == 'sent':
            self.user_profile.total_files_sent += transfer_data.get('file_count', 0)
        elif transfer_data.get('direction') == 'received':
            self.user_profile.total_files_received += transfer_data.get('file_count', 0)
        
        self.user_profile.total_bytes_transferred += transfer_data.get('total_bytes', 0)
        
        self.save_transfer_history()
        self.save_settings()
    
    def get_transfer_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques des transferts."""
        stats = {
            'total_transfers': len(self.transfer_history),
            'files_sent': self.user_profile.total_files_sent,
            'files_received': self.user_profile.total_files_received,
            'bytes_transferred': self.user_profile.total_bytes_transferred,
            'trusted_devices': len([d for d in self.trusted_devices.values() 
                                  if d.trust_level == "trusted"]),
            'blocked_devices': len([d for d in self.trusted_devices.values() 
                                  if d.trust_level == "blocked"])
        }
        
        # Statistiques récentes (30 derniers jours)
        thirty_days_ago = datetime.now().timestamp() - (30 * 24 * 3600)
        recent_transfers = [t for t in self.transfer_history 
                          if t.get('timestamp', 0) > thirty_days_ago]
        
        stats['recent_transfers'] = len(recent_transfers)
        stats['recent_bytes'] = sum(t.get('total_bytes', 0) for t in recent_transfers)
        
        return stats
    
    def reset_settings(self, section: Optional[str] = None):
        """Remet les paramètres par défaut."""
        if section is None or section == 'all':
            self.user_profile = UserProfile()
            self.network_settings = NetworkSettings()
            self.storage_settings = StorageSettings()
            self.security_settings = SecuritySettings()
            self.interface_settings = InterfaceSettings()
            self._generate_user_id()
            self._set_default_download_folder()
        elif section == 'network':
            self.network_settings = NetworkSettings()
        elif section == 'storage':
            self.storage_settings = StorageSettings()
            self._set_default_download_folder()
        elif section == 'security':
            self.security_settings = SecuritySettings()
        elif section == 'interface':
            self.interface_settings = InterfaceSettings()
        
        self.save_settings()
        logger.info(f"Paramètres remis par défaut : {section or 'tous'}")
    
    def export_settings(self, export_path: str) -> bool:
        """Exporte les paramètres vers un fichier."""
        try:
            export_data = {
                'datashare_settings_export': True,
                'export_date': datetime.now().isoformat(),
                'user_profile': asdict(self.user_profile),
                'network_settings': asdict(self.network_settings),
                'storage_settings': asdict(self.storage_settings),
                'security_settings': asdict(self.security_settings),
                'interface_settings': asdict(self.interface_settings),
                'trusted_devices': {device_id: asdict(device) 
                                  for device_id, device in self.trusted_devices.items()}
            }
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Paramètres exportés vers {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export : {e}")
            return False
    
    def import_settings(self, import_path: str) -> bool:
        """Importe les paramètres depuis un fichier."""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Vérifier que c'est bien un export DataShare
            if not data.get('datashare_settings_export'):
                raise ValueError("Fichier d'import invalide")
            
            # Importer les paramètres
            if 'user_profile' in data:
                # Garder l'ID utilisateur actuel
                current_user_id = self.user_profile.user_id
                self.user_profile = UserProfile(**data['user_profile'])
                self.user_profile.user_id = current_user_id
            
            if 'network_settings' in data:
                self.network_settings = NetworkSettings(**data['network_settings'])
            
            if 'storage_settings' in data:
                self.storage_settings = StorageSettings(**data['storage_settings'])
            
            if 'security_settings' in data:
                self.security_settings = SecuritySettings(**data['security_settings'])
            
            if 'interface_settings' in data:
                self.interface_settings = InterfaceSettings(**data['interface_settings'])
            
            if 'trusted_devices' in data:
                self.trusted_devices = {}
                for device_id, device_data in data['trusted_devices'].items():
                    self.trusted_devices[device_id] = TrustedDevice(**device_data)
            
            # Sauvegarder
            self.save_settings()
            self.save_trusted_devices()
            
            logger.info(f"Paramètres importés depuis {import_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'import : {e}")
            return False
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Récupère tous les paramètres sous forme de dictionnaire."""
        return {
            'user_profile': asdict(self.user_profile),
            'network_settings': asdict(self.network_settings),
            'storage_settings': asdict(self.storage_settings),
            'security_settings': asdict(self.security_settings),
            'interface_settings': asdict(self.interface_settings),
            'trusted_devices_count': len(self.trusted_devices),
            'history_entries_count': len(self.transfer_history),
            'config_directory': str(self.config_dir)
        }


# Fonction utilitaire pour obtenir une instance globale
_settings_instance = None

def get_settings() -> SettingsManager:
    """Récupère l'instance globale du gestionnaire de paramètres."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = SettingsManager()
    return _settings_instance

def main():
    """Fonction de test et démonstration."""
    print("🎛️ GESTIONNAIRE DE PARAMÈTRES DATASHARE")
    print("=" * 50)
    
    # Initialiser le gestionnaire
    settings = SettingsManager()
    
    print(f"✅ Gestionnaire initialisé")
    print(f"📁 Dossier de config : {settings.config_dir}")
    print(f"👤 ID utilisateur : {settings.user_profile.user_id}")
    print(f"📝 Nom d'utilisateur : {settings.user_profile.username}")
    
    # Afficher les paramètres actuels
    print(f"\n📊 PARAMÈTRES ACTUELS :")
    all_settings = settings.get_all_settings()
    for section, data in all_settings.items():
        if isinstance(data, dict):
            print(f"  {section} :")
            for key, value in data.items():
                print(f"    {key} : {value}")
        else:
            print(f"  {section} : {data}")
    
    # Statistiques
    stats = settings.get_transfer_statistics()
    print(f"\n📈 STATISTIQUES :")
    for key, value in stats.items():
        print(f"  {key} : {value}")
    
    print(f"\n✅ Test terminé")

if __name__ == "__main__":
    main()
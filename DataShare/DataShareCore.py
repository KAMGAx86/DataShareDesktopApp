"""
Classe principale DataShare Core - Version finale complète

Intégration de tous les modules DataShare avec les noms de fichiers réels.

Auteur: DataShare Team
Version: 2.0
"""

import logging
import threading
import time
import os
import hashlib
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from pathlib import Path

# Imports avec les noms de fichiers RÉELS du projet
from had_hoc import HotspotManager
from scan_network import NetworkDiscovery, DeviceInfo
from unified_file_transfer import DataShareFileTransfer, UnifiedTransferJob
from show_storage_content import StorageExplorer, StorageDevice, FileInfo
from user_config import SettingsManager, get_settings
from alert_windows import NotificationManager, DataShareNotifications, NotificationType
from stats import (
    StatisticsManager, 
    TransferRecord, 
    TransferDirection, 
    TransferStatus as StatsTransferStatus
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataShareCore:
    """Classe principale orchestrant tous les modules DataShare."""
    
    def __init__(self):
        """Initialise tous les composants DataShare."""
        logger.info("=" * 60)
        logger.info("INITIALISATION DATASHARE CORE v2.0")
        logger.info("=" * 60)
        
        self.is_running = False
        self.current_network_session = None
        self._lock = threading.Lock()
        
        # 1. Paramètres
        logger.info("Chargement des parametres...")
        self.settings = get_settings()
        
        # 2. Notifications
        logger.info("Initialisation des notifications...")
        self.notification_manager = NotificationManager(
            enable_system_notifications=self.settings.interface_settings.show_notifications
        )
        self.notifications = DataShareNotifications(self.notification_manager)
        
        # 3. Statistiques
        logger.info("Initialisation des statistiques...")
        self.statistics = StatisticsManager()
        
        # 4. Hotspot
        logger.info("Initialisation du hotspot...")
        hotspot_ssid = f"{self.settings.network_settings.hotspot_ssid_prefix}-{self.settings.user_profile.username[:8]}"
        self.hotspot = HotspotManager(ssid=hotspot_ssid)
        
        # 5. Découverte
        logger.info("Initialisation de la decouverte...")
        self.discovery = NetworkDiscovery(
            custom_port=self.settings.network_settings.discovery_port
        )
        
        # 6. Transferts UNIFIÉ
        logger.info("Initialisation du gestionnaire de transferts unifie...")
        self.transfer_manager = DataShareFileTransfer(
            port=self.settings.network_settings.transfer_port
        )
        self._setup_transfer_callbacks()
        
        # 7. Explorateur stockage
        logger.info("Initialisation de l'explorateur de stockage...")
        self.storage_explorer = StorageExplorer()
        
        # Callbacks UI
        self.on_device_discovered: Optional[Callable] = None
        self.on_device_lost: Optional[Callable] = None
        self.on_transfer_request: Optional[Callable] = None
        self.on_transfer_progress: Optional[Callable] = None
        self.on_network_status_change: Optional[Callable] = None
        
        logger.info("=" * 60)
        logger.info("DataShare Core initialise avec succes")
        logger.info(f"Utilisateur: {self.settings.user_profile.username}")
        logger.info(f"ID: {self.settings.user_profile.user_id}")
        logger.info("=" * 60)
    
    def _setup_transfer_callbacks(self):
        """Configure les callbacks du gestionnaire de transfert unifié."""
        self.transfer_manager.on_transfer_request = self._handle_transfer_request
        self.transfer_manager.on_progress_update = self._handle_transfer_progress
        self.transfer_manager.on_transfer_complete = self._handle_transfer_complete
        self.transfer_manager.on_file_received = self._handle_file_received
    
    def _handle_transfer_request(self, transfer_job: UnifiedTransferJob, socket):
        """Gère une demande de transfert entrante."""
        logger.info(f"Demande de transfert de {transfer_job.remote_name}")
        
        device_id = self._generate_device_id(
            transfer_job.remote_ip, 
            transfer_job.remote_name
        )
        
        if self.settings.should_auto_accept_from_device(device_id):
            default_folder = self.settings.storage_settings.default_download_folder
            self.transfer_manager.accept_transfer(transfer_job.transfer_id, default_folder)
            
            self.notifications.transfer_request_received(
                transfer_job.remote_name,
                len(transfer_job.files),
                self._format_size(transfer_job.total_size)
            )
            logger.info(f"Transfert auto-accepte de {transfer_job.remote_name}")
        
        elif self.settings.security_settings.require_confirmation:
            self.notifications.transfer_request_received(
                transfer_job.remote_name,
                len(transfer_job.files),
                self._format_size(transfer_job.total_size)
            )
            
            if self.on_transfer_request:
                self.on_transfer_request(transfer_job)
            else:
                default_folder = self.settings.storage_settings.default_download_folder
                self.transfer_manager.accept_transfer(transfer_job.transfer_id, default_folder)
        else:
            default_folder = self.settings.storage_settings.default_download_folder
            self.transfer_manager.accept_transfer(transfer_job.transfer_id, default_folder)
    
    def _handle_transfer_progress(self, transfer_job: UnifiedTransferJob):
        """Gère la progression d'un transfert."""
        if self.on_transfer_progress:
            self.on_transfer_progress(transfer_job)
    
    def _handle_transfer_complete(self, transfer_job: UnifiedTransferJob):
        """Gère la fin d'un transfert."""
        logger.info(f"Transfert termine: {transfer_job.transfer_id}")
        
        device_id = self._generate_device_id(
            transfer_job.remote_ip,
            transfer_job.remote_name
        )
        
        direction = TransferDirection.SENT if transfer_job.direction == 'sent' else TransferDirection.RECEIVED
        
        status_map = {
            'completed': StatsTransferStatus.COMPLETED,
            'failed': StatsTransferStatus.FAILED,
            'cancelled': StatsTransferStatus.CANCELLED
        }
        
        status_value = transfer_job.status.value if hasattr(transfer_job.status, 'value') else str(transfer_job.status)
        stats_status = status_map.get(status_value.lower(), StatsTransferStatus.FAILED)
        
        file_types = []
        for file_meta in transfer_job.files:
            if '.' in file_meta.name:
                ext = file_meta.name.split('.')[-1].lower()
                if ext not in file_types:
                    file_types.append(ext)
        
        duration = transfer_job.total_size / transfer_job.speed if transfer_job.speed > 0 else 0
        
        transfer_record = TransferRecord(
            id=transfer_job.transfer_id,
            timestamp=time.time(),
            direction=direction,
            status=stats_status,
            device_id=device_id,
            device_name=transfer_job.remote_name,
            device_ip=transfer_job.remote_ip,
            file_count=len(transfer_job.files),
            total_bytes=transfer_job.bytes_transferred,
            duration=duration,
            average_speed=transfer_job.speed,
            error_message="",
            file_types=file_types
        )
        
        self.statistics.record_transfer(transfer_record)
        
        if self.current_network_session:
            self.statistics.update_session_transfer(transfer_job.bytes_transferred)
        
        if stats_status == StatsTransferStatus.COMPLETED:
            self.notifications.transfer_completed(
                len(transfer_job.files),
                transfer_job.remote_name,
                transfer_job.direction
            )
        else:
            self.notifications.transfer_failed(
                "Transfert echoue",
                transfer_job.remote_name
            )
        
        if stats_status == StatsTransferStatus.COMPLETED:
            if direction == TransferDirection.SENT:
                self.settings.user_profile.total_files_sent += len(transfer_job.files)
            else:
                self.settings.user_profile.total_files_received += len(transfer_job.files)
            
            self.settings.user_profile.total_bytes_transferred += transfer_job.bytes_transferred
            self.settings.save_settings()
    
    def _handle_file_received(self, receive_job, file_name: str):
        """Gère la réception d'un fichier individuel."""
        logger.debug(f"Fichier recu: {file_name}")
    
    def _generate_device_id(self, ip: str, name: str) -> str:
        """Génère un ID unique pour un appareil."""
        combined = f"{ip}_{name}_{self.settings.user_profile.user_id}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def _format_size(self, size_bytes: int) -> str:
        """Formate une taille en bytes."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def start_services(self) -> bool:
        """Démarre tous les services DataShare."""
        if self.is_running:
            logger.warning("Services deja en cours")
            return True
        
        logger.info("=" * 60)
        logger.info("DEMARRAGE DES SERVICES DATASHARE")
        logger.info("=" * 60)
        
        try:
            with self._lock:
                logger.info("1/3 Demarrage de la decouverte d'appareils...")
                self.discovery.start_discovery()
                
                logger.info("2/3 Demarrage du serveur de transfert...")
                self.transfer_manager.start_server()
                
                if self.settings.network_settings.auto_create_hotspot:
                    logger.info("3/3 Creation du hotspot...")
                    success, message = self.hotspot.create_hotspot()
                    
                    if success:
                        self.notifications.network_created(
                            self.hotspot.ssid,
                            self.hotspot.password
                        )
                        
                        session_id = self.statistics.start_network_session(
                            "hotspot_created",
                            self.hotspot.ssid
                        )
                        self.current_network_session = session_id
                        
                        logger.info(f"Hotspot cree: {self.hotspot.ssid}")
                    else:
                        self.notifications.network_error(message)
                        logger.warning(f"Echec hotspot: {message}")
                else:
                    logger.info("3/3 Hotspot auto-creation desactive")
                
                self.is_running = True
                
                logger.info("=" * 60)
                logger.info("TOUS LES SERVICES SONT DEMARRES")
                logger.info("=" * 60)
                
                self._start_monitoring_thread()
                
                return True
        
        except Exception as e:
            logger.error(f"Erreur demarrage: {e}")
            self.stop_services()
            return False
    
    def stop_services(self):
        """Arrête tous les services DataShare."""
        if not self.is_running:
            return
        
        logger.info("=" * 60)
        logger.info("ARRET DES SERVICES DATASHARE")
        logger.info("=" * 60)
        
        with self._lock:
            self.is_running = False
            
            if self.hotspot.is_active:
                logger.info("Arret du hotspot...")
                self.hotspot.stop_hotspot()
            
            logger.info("Arret de la decouverte...")
            self.discovery.stop_discovery()
            
            logger.info("Arret du serveur de transfert...")
            self.transfer_manager.stop_server()
            
            if self.current_network_session:
                self.statistics.end_network_session()
                self.current_network_session = None
            
            logger.info("=" * 60)
            logger.info("TOUS LES SERVICES SONT ARRETES")
            logger.info("=" * 60)
    
    def _start_monitoring_thread(self):
        """Démarre le thread de monitoring des appareils."""
        def monitoring_loop():
            logger.info("Thread de monitoring demarre")
            last_devices = set()
            
            while self.is_running:
                try:
                    current_devices = set()
                    discovered_devices = self.discovery.get_discovered_devices()
                    
                    for device in discovered_devices:
                        device_key = f"{device.hostname}_{device.ip_address}"
                        current_devices.add(device_key)
                        
                        if device_key not in last_devices:
                            device_id = self._generate_device_id(
                                device.ip_address, 
                                device.hostname
                            )
                            
                            self.statistics.record_device_connection(
                                device_id, device.hostname, device.ip_address
                            )
                            
                            if self.current_network_session:
                                self.statistics.add_device_to_session(device_id)
                            
                            self.notifications.device_discovered(
                                device.hostname, 
                                device.ip_address
                            )
                            
                            if self.on_device_discovered:
                                self.on_device_discovered(device)
                            
                            logger.info(f"Nouvel appareil: {device.hostname} ({device.ip_address})")
                    
                    for lost_device_key in last_devices - current_devices:
                        device_name = lost_device_key.split('_')[0]
                        self.notifications.device_disconnected(device_name)
                        
                        if self.on_device_lost:
                            self.on_device_lost(lost_device_key)
                        
                        logger.info(f"Appareil deconnecte: {device_name}")
                    
                    last_devices = current_devices
                    
                    time.sleep(5)
                    
                except Exception as e:
                    logger.error(f"Erreur dans le monitoring: {e}")
                    time.sleep(10)
            
            logger.info("Thread de monitoring arrete")
        
        monitoring_thread = threading.Thread(
            target=monitoring_loop, 
            daemon=True, 
            name="DataShare-Monitor"
        )
        monitoring_thread.start()
    
    def send_files_to_device(self, device_ip: str, file_paths: List[str]) -> Optional[str]:
        """Envoie des fichiers vers un appareil."""
        try:
            logger.info(f"Envoi de {len(file_paths)} fichier(s) vers {device_ip}")
            
            transfer_id = self.transfer_manager.send_files(
                target_ip=device_ip,
                files_and_folders=file_paths,
                sender_name=self.settings.user_profile.username
            )
            
            device_name = self._get_device_name_by_ip(device_ip)
            self.notifications.show_notification(
                NotificationType.TRANSFER_STARTED,
                data={'device_name': device_name, 'file_count': len(file_paths)},
                title="Transfert demarre",
                message=f"Envoi de {len(file_paths)} fichier(s) vers {device_name}"
            )
            
            return transfer_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi: {e}")
            self.notifications.transfer_failed(str(e), device_ip)
            return None
    
    def _get_device_name_by_ip(self, ip: str) -> str:
        """Récupère le nom d'un appareil par son IP."""
        for device in self.discovery.get_discovered_devices():
            if device.ip_address == ip:
                return device.hostname
        return ip
    
    def get_available_devices(self) -> List[DeviceInfo]:
        """Récupère la liste des appareils disponibles."""
        return self.discovery.get_discovered_devices()
    
    def get_storage_devices(self) -> List[StorageDevice]:
        """Récupère la liste des périphériques de stockage."""
        return self.storage_explorer.scan_storage_devices()
    
    def browse_directory(self, path: str, show_hidden: bool = None) -> List[FileInfo]:
        """Parcourt un répertoire."""
        if show_hidden is None:
            show_hidden = self.settings.storage_settings.show_hidden_files
        
        return self.storage_explorer.list_directory_contents(path, show_hidden)
    
    def search_files(self, root_path: str, query: str, max_results: int = 100) -> List[FileInfo]:
        """Recherche des fichiers."""
        return self.storage_explorer.search_files(root_path, query, max_results=max_results)
    
    def get_active_transfers(self) -> List[UnifiedTransferJob]:
        """Récupère la liste des transferts actifs (envoi + réception)."""
        return self.transfer_manager.get_active_transfers()
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """Annule un transfert."""
        return self.transfer_manager.cancel_transfer(transfer_id)
    
    def accept_transfer(self, transfer_id: str, destination_folder: str = None) -> bool:
        """Accepte un transfert entrant."""
        if destination_folder is None:
            destination_folder = self.settings.storage_settings.default_download_folder
        
        return self.transfer_manager.accept_transfer(transfer_id, destination_folder)
    
    def reject_transfer(self, transfer_id: str, reason: str = "Refuse") -> bool:
        """Rejette un transfert entrant."""
        return self.transfer_manager.reject_transfer(transfer_id, reason)
    
    def get_network_status(self) -> Dict[str, Any]:
        """Récupère l'état du réseau."""
        hotspot_active, hotspot_status = self.hotspot.get_hotspot_status()
        devices_count = len(self.get_available_devices())
        
        return {
            'hotspot_active': hotspot_active,
            'hotspot_status': hotspot_status,
            'hotspot_ssid': self.hotspot.ssid if hotspot_active else None,
            'devices_discovered': devices_count,
            'discovery_running': self.discovery.is_running,
            'transfer_server_running': self.transfer_manager.is_running
        }
    
    def get_transfer_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Récupère les statistiques de transferts."""
        return self.statistics.get_transfer_statistics(days)
    
    def get_application_info(self) -> Dict[str, Any]:
        """Récupère les informations sur l'application."""
        return {
            'version': '2.0',
            'user_profile': self.settings.user_profile.__dict__,
            'services_running': self.is_running,
            'config_directory': str(self.settings.config_dir),
            'network_status': self.get_network_status(),
            'statistics': self.get_transfer_statistics(7)
        }
    
    def update_user_profile(self, username: str = None, avatar_path: str = None):
        """Met à jour le profil utilisateur."""
        if username:
            self.settings.user_profile.username = username
        if avatar_path:
            self.settings.user_profile.avatar_path = avatar_path
        
        self.settings.save_settings()
        logger.info("Profil utilisateur mis a jour")
    
    def add_trusted_device(self, device_ip: str, trust_level: str = "trusted", 
                          auto_accept: bool = False) -> bool:
        """Ajoute un appareil à la liste de confiance."""
        device_name = self._get_device_name_by_ip(device_ip)
        device_id = self._generate_device_id(device_ip, device_name)
        
        success = self.settings.add_trusted_device(
            device_id, device_name, device_ip, trust_level, auto_accept
        )
        
        if success:
            logger.info(f"Appareil ajoute a la liste de confiance: {device_name}")
        
        return success
    
    def export_all_data(self, export_directory: str) -> Dict[str, bool]:
        """Exporte toutes les données de l'application."""
        export_directory = Path(export_directory)
        export_directory.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        settings_file = export_directory / "datashare_settings.json"
        results['settings'] = self.settings.export_settings(str(settings_file))
        
        stats_file = export_directory / "datashare_statistics.json"
        results['statistics'] = self.statistics.export_statistics(str(stats_file), days=365)
        
        info_file = export_directory / "export_info.json"
        try:
            import json
            export_info = {
                'export_date': datetime.now().isoformat(),
                'datashare_version': '2.0',
                'user_id': self.settings.user_profile.user_id,
                'username': self.settings.user_profile.username,
                'files_included': list(results.keys())
            }
            
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(export_info, f, indent=2, ensure_ascii=False)
            
            results['info'] = True
        except Exception as e:
            logger.error(f"Erreur lors de la creation du fichier d'info: {e}")
            results['info'] = False
        
        logger.info(f"Export termine dans {export_directory}")
        return results
    
    def cleanup_old_data(self, days_to_keep: int = 365):
        """Nettoie les anciennes données."""
        logger.info(f"Nettoyage des donnees de plus de {days_to_keep} jours")
        self.statistics.cleanup_old_data(days_to_keep)
        logger.info("Nettoyage termine")
    
    def restart_network(self) -> bool:
        """Redémarre les services réseau."""
        logger.info("Redemarrage des services reseau...")
        
        if self.hotspot.is_active:
            self.hotspot.stop_hotspot()
        
        self.discovery.stop_discovery()
        time.sleep(2)
        self.discovery.start_discovery()
        
        if self.settings.network_settings.auto_create_hotspot:
            success, message = self.hotspot.create_hotspot()
            if success:
                self.notifications.network_created(self.hotspot.ssid, self.hotspot.password)
                logger.info("Services reseau redemarres avec succes")
                return True
            else:
                self.notifications.network_error(message)
                logger.error(f"Erreur lors du redemarrage: {message}")
                return False
        
        return True
    
    def __enter__(self):
        """Support du context manager."""
        self.start_services()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support du context manager."""
        self.stop_services()


def main():
    """Fonction de démonstration de DataShare Core."""
    print("=" * 80)
    print("DATASHARE CORE v2.0 - DEMONSTRATION COMPLETE")
    print("=" * 80)
    
    try:
        datashare = DataShareCore()
        print("\nDataShare Core initialise")
        
        app_info = datashare.get_application_info()
        print(f"\nINFORMATIONS APPLICATION:")
        print(f"  Version: {app_info['version']}")
        print(f"  Utilisateur: {app_info['user_profile']['username']}")
        print(f"  ID: {app_info['user_profile']['user_id']}")
        print(f"  Configuration: {app_info['config_directory']}")
        
        print(f"\nDEMARRAGE DES SERVICES...")
        if datashare.start_services():
            print("Tous les services sont demarres")
            
            network_status = datashare.get_network_status()
            print(f"\nETAT DU RESEAU:")
            for key, value in network_status.items():
                print(f"  {key}: {value}")
            
            print(f"\nPERIPHERIQUES DE STOCKAGE:")
            storage_devices = datashare.get_storage_devices()
            for device in storage_devices[:3]:
                print(f"  {device.name}: {datashare._format_size(device.free_size)} libre")
            
            print(f"\nSURVEILLANCE DES APPAREILS (30s)...")
            print("Lancez DataShare sur d'autres appareils pour les voir apparaitre")
            
            for i in range(30):
                devices = datashare.get_available_devices()
                transfers = datashare.get_active_transfers()
                
                print(f"\r  Appareils: {len(devices)} | Transferts: {len(transfers)} | {30-i}s restant", 
                      end="", flush=True)
                
                time.sleep(1)
            
            print()
            
            stats = datashare.get_transfer_statistics(30)
            print(f"\nSTATISTIQUES (30 jours):")
            print(f"  Transferts totaux: {stats['total_transfers']}")
            print(f"  Transferts reussis: {stats['successful_transfers']}")
            print(f"  Donnees transferees: {datashare._format_size(stats['total_bytes'])}")
            
        else:
            print("Echec du demarrage des services")
        
    except KeyboardInterrupt:
        print(f"\n\nInterruption detectee")
    
    except Exception as e:
        print(f"\nErreur: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        print(f"\nARRET DE DATASHARE...")
        if 'datashare' in locals():
            datashare.stop_services()
        
        print("DataShare arrete proprement")
        print("Demonstration terminee")


if __name__ == "__main__":
    main()
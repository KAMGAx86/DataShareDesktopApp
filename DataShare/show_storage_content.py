"""
Module d'exploration de périphériques de stockage pour DataShare

Ce module permet de:
- Lister tous les périphériques de stockage (internes, USB, réseau)
- Détecter les partitions et leurs types de système de fichiers
- Explorer le contenu des dossiers de manière hiérarchique
- Filtrer et rechercher des fichiers
- Obtenir des informations détaillées sur l'espace disque
- Gérer les permissions et l'accès aux fichiers
- Support multiplateforme (Windows, Linux, macOS)

Optimisé pour l'intégration avec l'interface Kivy de DataShare.

Auteur: DataShare Team
Version: 3.0
"""

import os
import platform
import subprocess
import psutil
import json
import time
import threading
from typing import List, Dict, Tuple, Optional, Any, Callable
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import shutil
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Types de périphériques de stockage."""
    INTERNAL_HDD = "internal_hdd"        # Disque dur interne
    INTERNAL_SSD = "internal_ssd"        # SSD interne
    USB_DRIVE = "usb_drive"              # Clé USB / Disque USB
    EXTERNAL_HDD = "external_hdd"        # Disque dur externe
    OPTICAL_DRIVE = "optical_drive"      # CD/DVD/Blu-ray
    NETWORK_DRIVE = "network_drive"      # Lecteur réseau
    VIRTUAL_DRIVE = "virtual_drive"      # Lecteur virtuel
    UNKNOWN = "unknown"                  # Type inconnu


class FileType(Enum):
    """Types de fichiers pour le filtrage."""
    DOCUMENT = "document"    # PDF, DOC, TXT, etc.
    IMAGE = "image"         # JPG, PNG, GIF, etc.
    VIDEO = "video"         # MP4, AVI, MKV, etc.
    AUDIO = "audio"         # MP3, WAV, FLAC, etc.
    ARCHIVE = "archive"     # ZIP, RAR, 7Z, etc.
    EXECUTABLE = "executable"  # EXE, APP, etc.
    FOLDER = "folder"       # Dossiers
    OTHER = "other"         # Autres types


@dataclass
class StorageDevice:
    """Informations sur un périphérique de stockage."""
    device_id: str           # Identifiant unique
    name: str               # Nom d'affichage
    mount_point: str        # Point de montage (C:\, /dev/sda1, etc.)
    device_type: DeviceType # Type de périphérique
    file_system: str        # Système de fichiers (NTFS, ext4, etc.)
    total_size: int         # Taille totale en bytes
    used_size: int          # Espace utilisé en bytes
    free_size: int          # Espace libre en bytes
    is_removable: bool      # Périphérique amovible
    is_ready: bool          # Prêt à être utilisé
    vendor: str             # Fabricant (si disponible)
    model: str              # Modèle (si disponible)
    serial_number: str      # Numéro de série (si disponible)


@dataclass
class FileInfo:
    """Informations sur un fichier ou dossier."""
    name: str               # Nom du fichier/dossier
    path: str              # Chemin complet
    size: int              # Taille en bytes (0 pour dossiers)
    modified_time: float   # Date de modification (timestamp)
    created_time: float    # Date de création (timestamp)
    is_directory: bool     # True si c'est un dossier
    is_hidden: bool        # True si le fichier est caché
    file_type: FileType    # Type de fichier
    permissions: str       # Permissions (rwx format ou Windows)
    extension: str         # Extension du fichier
    mime_type: str         # Type MIME (si détectable)


class StorageExplorer:
    """Gestionnaire principal d'exploration de stockage."""
    
    def __init__(self):
        self.os_type = platform.system()  # Windows, Linux, Darwin
        self.devices: Dict[str, StorageDevice] = {}
        self.devices_lock = threading.Lock()
        
        # Extensions de fichiers par type
        self.file_type_extensions = {
            FileType.DOCUMENT: {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'},
            FileType.IMAGE: {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg', '.ico'},
            FileType.VIDEO: {'.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp'},
            FileType.AUDIO: {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus'},
            FileType.ARCHIVE: {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'},
            FileType.EXECUTABLE: {'.exe', '.msi', '.app', '.deb', '.rpm', '.dmg', '.pkg'}
        }
        
        # Callbacks pour l'interface utilisateur
        self.on_device_detected: Optional[Callable] = None
        self.on_device_removed: Optional[Callable] = None
        self.on_scan_progress: Optional[Callable] = None
        
        logger.info(f"StorageExplorer initialisé sur {self.os_type}")
    
    def scan_storage_devices(self) -> List[StorageDevice]:
        """
        Scanne et détecte tous les périphériques de stockage.
        
        Returns:
            List[StorageDevice]: Liste des périphériques détectés
        """
        logger.info("Début du scan des périphériques de stockage...")
        devices = []
        
        try:
            # Obtenir les partitions avec psutil
            partitions = psutil.disk_partitions(all=True)
            
            for partition in partitions:
                try:
                    device = self._analyze_partition(partition)
                    if device:
                        devices.append(device)
                        logger.info(f"Périphérique détecté: {device.name} ({device.mount_point})")
                        
                except Exception as e:
                    logger.debug(f"Erreur lors de l'analyse de {partition.device}: {e}")
            
            # Détection spécialisée selon l'OS
            if self.os_type == "Windows":
                devices.extend(self._scan_windows_devices())
            elif self.os_type == "Linux":
                devices.extend(self._scan_linux_devices())
            elif self.os_type == "Darwin":  # macOS
                devices.extend(self._scan_macos_devices())
            
            # Mettre à jour le cache des périphériques
            with self.devices_lock:
                self.devices.clear()
                for device in devices:
                    self.devices[device.device_id] = device
            
            logger.info(f"Scan terminé: {len(devices)} périphériques détectés")
            return devices
            
        except Exception as e:
            logger.error(f"Erreur lors du scan des périphériques: {e}")
            return []
    
    def _analyze_partition(self, partition) -> Optional[StorageDevice]:
        """Analyse une partition détectée par psutil."""
        try:
            # Obtenir les informations d'utilisation
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total_size = usage.total
                used_size = usage.used
                free_size = usage.free
                is_ready = True
            except (OSError, PermissionError):
                # Partition non accessible (CD vide, etc.)
                total_size = used_size = free_size = 0
                is_ready = False
            
            # Déterminer le type de périphérique
            device_type = self._determine_device_type(partition)
            
            # Informations additionnelles selon l'OS
            vendor, model, serial = self._get_device_hardware_info(partition.device)
            
            # Générer un ID unique
            device_id = self._generate_device_id(partition)
            
            # Nom d'affichage
            display_name = self._generate_display_name(partition, device_type)
            
            device = StorageDevice(
                device_id=device_id,
                name=display_name,
                mount_point=partition.mountpoint,
                device_type=device_type,
                file_system=partition.fstype,
                total_size=total_size,
                used_size=used_size,
                free_size=free_size,
                is_removable=self._is_removable_device(partition),
                is_ready=is_ready,
                vendor=vendor,
                model=model,
                serial_number=serial
            )
            
            return device
            
        except Exception as e:
            logger.debug(f"Erreur lors de l'analyse de la partition {partition.device}: {e}")
            return None
    
    def _determine_device_type(self, partition) -> DeviceType:
        """Détermine le type d'un périphérique."""
        device_path = partition.device.lower()
        fstype = partition.fstype.lower()
        mountpoint = partition.mountpoint.lower()
        
        # Détection par système de fichiers
        if fstype in ['iso9660', 'udf']:
            return DeviceType.OPTICAL_DRIVE
        
        # Détection par point de montage
        if self.os_type == "Windows":
            # Sur Windows, vérifier si c'est un lecteur réseau
            if mountpoint.startswith('\\\\'):
                return DeviceType.NETWORK_DRIVE
            
            # Vérifier si c'est un lecteur amovible
            if self._is_removable_device(partition):
                return DeviceType.USB_DRIVE
                
        elif self.os_type == "Linux":
            # Sur Linux, analyser le chemin du périphérique
            if '/dev/sr' in device_path or '/dev/cdrom' in device_path:
                return DeviceType.OPTICAL_DRIVE
            elif '/media/' in mountpoint or '/mnt/usb' in mountpoint:
                return DeviceType.USB_DRIVE
            elif 'nfs' in fstype or 'cifs' in fstype or 'smb' in fstype:
                return DeviceType.NETWORK_DRIVE
        
        # Détection SSD vs HDD (approximative)
        if self._is_ssd_device(partition):
            return DeviceType.INTERNAL_SSD
        else:
            return DeviceType.INTERNAL_HDD
    
    def _is_removable_device(self, partition) -> bool:
        """Vérifie si un périphérique est amovible."""
        if self.os_type == "Windows":
            try:
                import win32file
                drive_type = win32file.GetDriveType(partition.mountpoint)
                return drive_type == win32file.DRIVE_REMOVABLE
            except ImportError:
                # Fallback sans win32file
                return self._check_removable_fallback(partition)
        
        elif self.os_type == "Linux":
            # Sur Linux, vérifier dans /sys/block
            try:
                device_name = partition.device.split('/')[-1].rstrip('0123456789')
                removable_path = f"/sys/block/{device_name}/removable"
                if os.path.exists(removable_path):
                    with open(removable_path, 'r') as f:
                        return f.read().strip() == '1'
            except Exception:
                pass
        
        return False
    
    def _is_ssd_device(self, partition) -> bool:
        """Détecte approximativement si c'est un SSD."""
        if self.os_type == "Linux":
            try:
                device_name = partition.device.split('/')[-1].rstrip('0123456789')
                rotational_path = f"/sys/block/{device_name}/queue/rotational"
                if os.path.exists(rotational_path):
                    with open(rotational_path, 'r') as f:
                        return f.read().strip() == '0'  # 0 = SSD, 1 = HDD
            except Exception:
                pass
        
        return False  # Par défaut, considérer comme HDD
    
    def _get_device_hardware_info(self, device_path: str) -> Tuple[str, str, str]:
        """Obtient les informations matérielles d'un périphérique."""
        vendor = model = serial = ""
        
        try:
            if self.os_type == "Windows":
                vendor, model, serial = self._get_windows_hardware_info(device_path)
            elif self.os_type == "Linux":
                vendor, model, serial = self._get_linux_hardware_info(device_path)
        except Exception as e:
            logger.debug(f"Impossible d'obtenir les infos matérielles pour {device_path}: {e}")
        
        return vendor, model, serial
    
    def _get_windows_hardware_info(self, device_path: str) -> Tuple[str, str, str]:
        """Obtient les infos matérielles sur Windows."""
        try:
            # Utiliser wmic pour obtenir les informations
            escaped_path = device_path.replace("\\", "\\\\")
            cmd = f'wmic diskdrive where "DeviceID=\'{escaped_path}\'" get ...'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, 
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split(',')
                    if len(parts) >= 4:
                        manufacturer = parts[1].strip()
                        model = parts[2].strip()
                        serial = parts[3].strip()
                        return manufacturer, model, serial
        except Exception:
            pass
        
        return "", "", ""
    
    def _get_linux_hardware_info(self, device_path: str) -> Tuple[str, str, str]:
        """Obtient les infos matérielles sur Linux."""
        try:
            device_name = device_path.split('/')[-1].rstrip('0123456789')
            
            # Lire les informations depuis /sys/block
            sys_path = f"/sys/block/{device_name}"
            
            vendor = ""
            model = ""
            
            # Essayer de lire le modèle
            model_file = f"{sys_path}/device/model"
            if os.path.exists(model_file):
                with open(model_file, 'r') as f:
                    model = f.read().strip()
            
            # Essayer de lire le fabricant
            vendor_file = f"{sys_path}/device/vendor"
            if os.path.exists(vendor_file):
                with open(vendor_file, 'r') as f:
                    vendor = f.read().strip()
            
            return vendor, model, ""
        except Exception:
            pass
        
        return "", "", ""
    
    def _generate_device_id(self, partition) -> str:
        """Génère un identifiant unique pour un périphérique."""
        # Utiliser une combinaison de plusieurs éléments
        elements = [
            partition.device,
            partition.mountpoint,
            partition.fstype,
            str(hash(partition.device + partition.mountpoint))
        ]
        return "_".join(elements).replace("\\", "_").replace("/", "_").replace(":", "_")
    
    def _generate_display_name(self, partition, device_type: DeviceType) -> str:
        """Génère un nom d'affichage pour un périphérique."""
        base_name = ""
        
        if self.os_type == "Windows":
            # Sur Windows, utiliser la lettre de lecteur
            drive_letter = partition.mountpoint.rstrip("\\")
            base_name = f"Lecteur {drive_letter}"
            
            # Essayer d'obtenir le nom de volume
            try:
                import win32api
                volume_name = win32api.GetVolumeInformation(partition.mountpoint)[0]
                if volume_name:
                    base_name = f"{volume_name} ({drive_letter})"
            except ImportError:
                pass
        else:
            # Sur Unix, utiliser le point de montage
            if partition.mountpoint == "/":
                base_name = "Système racine"
            else:
                base_name = os.path.basename(partition.mountpoint) or partition.mountpoint
        
        # Ajouter le type de périphérique
        type_names = {
            DeviceType.INTERNAL_HDD: "Disque dur",
            DeviceType.INTERNAL_SSD: "SSD",
            DeviceType.USB_DRIVE: "Périph. USB",
            DeviceType.EXTERNAL_HDD: "Disque externe",
            DeviceType.OPTICAL_DRIVE: "Lecteur optique",
            DeviceType.NETWORK_DRIVE: "Lecteur réseau",
            DeviceType.VIRTUAL_DRIVE: "Lecteur virtuel"
        }
        
        type_suffix = type_names.get(device_type, "")
        if type_suffix:
            base_name = f"{base_name} [{type_suffix}]"
        
        return base_name
    
    def _scan_windows_devices(self) -> List[StorageDevice]:
        """Scan spécialisé pour Windows."""
        additional_devices = []
        
        try:
            # Utiliser wmic pour détecter les périphériques supplémentaires
            cmd = 'wmic logicaldisk get DeviceID,DriveType,FileSystem,Size,FreeSpace,VolumeName /format:csv'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                # Parser la sortie CSV
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        # TODO: Parser et créer des StorageDevice supplémentaires
                        pass
        except Exception as e:
            logger.debug(f"Erreur scan Windows: {e}")
        
        return additional_devices
    
    def _scan_linux_devices(self) -> List[StorageDevice]:
        """Scan spécialisé pour Linux."""
        additional_devices = []
        
        try:
            # Utiliser lsblk pour des informations détaillées
            result = subprocess.run(['lsblk', '-J'], capture_output=True, text=True)
            if result.returncode == 0:
                # TODO: Parser la sortie JSON de lsblk
                pass
        except Exception as e:
            logger.debug(f"Erreur scan Linux: {e}")
        
        return additional_devices
    
    def _scan_macos_devices(self) -> List[StorageDevice]:
        """Scan spécialisé pour macOS."""
        additional_devices = []
        
        try:
            # Utiliser diskutil pour macOS
            result = subprocess.run(['diskutil', 'list', '-plist'], capture_output=True, text=True)
            if result.returncode == 0:
                # TODO: Parser la sortie plist
                pass
        except Exception as e:
            logger.debug(f"Erreur scan macOS: {e}")
        
        return additional_devices
    
    def _check_removable_fallback(self, partition) -> bool:
        """Vérification fallback pour les périphériques amovibles."""
        # Heuristiques simples
        mount_point = partition.mountpoint.lower()
        device_path = partition.device.lower()
        
        # Mots-clés suggérant un périphérique amovible
        removable_keywords = ['usb', 'removable', 'portable', 'external']
        
        for keyword in removable_keywords:
            if keyword in mount_point or keyword in device_path:
                return True
        
        return False
    
    def list_directory_contents(self, path: str, show_hidden: bool = False) -> List[FileInfo]:
        """
        Liste le contenu d'un répertoire.
        
        Args:
            path (str): Chemin du répertoire à explorer
            show_hidden (bool): Afficher les fichiers cachés
            
        Returns:
            List[FileInfo]: Liste des fichiers et dossiers
        """
        contents = []
        
        try:
            path_obj = Path(path)
            
            if not path_obj.exists():
                logger.warning(f"Chemin inexistant: {path}")
                return []
            
            if not path_obj.is_dir():
                logger.warning(f"Le chemin n'est pas un répertoire: {path}")
                return []
            
            # Lister les éléments
            for item in path_obj.iterdir():
                try:
                    # Ignorer les fichiers cachés si demandé
                    if not show_hidden and self._is_hidden_file(item):
                        continue
                    
                    file_info = self._create_file_info(item)
                    contents.append(file_info)
                    
                except (PermissionError, OSError) as e:
                    logger.debug(f"Accès refusé à {item}: {e}")
                    continue
            
            # Trier: dossiers en premier, puis par nom
            contents.sort(key=lambda x: (not x.is_directory, x.name.lower()))
            
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du répertoire {path}: {e}")
        
        return contents
    
    def _is_hidden_file(self, path: Path) -> bool:
        """Vérifie si un fichier est caché."""
        if self.os_type == "Windows":
            try:
                import stat
                return bool(path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
            except (ImportError, AttributeError, OSError):
                # Fallback: fichier commençant par un point
                return path.name.startswith('.')
        else:
            # Unix: fichier commençant par un point
            return path.name.startswith('.')
    
    def _create_file_info(self, path: Path) -> FileInfo:
        """Crée un objet FileInfo pour un fichier/dossier."""
        try:
            stat = path.stat()
            
            # Informations de base
            name = path.name
            full_path = str(path.absolute())
            size = stat.st_size if path.is_file() else 0
            modified_time = stat.st_mtime
            created_time = getattr(stat, 'st_birthtime', stat.st_ctime)  # macOS a st_birthtime
            is_directory = path.is_dir()
            is_hidden = self._is_hidden_file(path)
            
            # Type de fichier
            if is_directory:
                file_type = FileType.FOLDER
                extension = ""
                mime_type = "inode/directory"
            else:
                extension = path.suffix.lower()
                file_type = self._determine_file_type(extension)
                mime_type = self._get_mime_type(extension)
            
            # Permissions
            permissions = self._get_permissions_string(stat)
            
            return FileInfo(
                name=name,
                path=full_path,
                size=size,
                modified_time=modified_time,
                created_time=created_time,
                is_directory=is_directory,
                is_hidden=is_hidden,
                file_type=file_type,
                permissions=permissions,
                extension=extension,
                mime_type=mime_type
            )
            
        except Exception as e:
            logger.debug(f"Erreur lors de la création de FileInfo pour {path}: {e}")
            
            # Retourner un objet minimal en cas d'erreur
            return FileInfo(
                name=path.name,
                path=str(path),
                size=0,
                modified_time=0,
                created_time=0,
                is_directory=False,
                is_hidden=False,
                file_type=FileType.OTHER,
                permissions="",
                extension="",
                mime_type=""
            )
    
    def _determine_file_type(self, extension: str) -> FileType:
        """Détermine le type d'un fichier par son extension."""
        for file_type, extensions in self.file_type_extensions.items():
            if extension in extensions:
                return file_type
        return FileType.OTHER
    
    def _get_mime_type(self, extension: str) -> str:
        """Obtient le type MIME d'un fichier."""
        mime_types = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.mp4': 'video/mp4',
            '.mp3': 'audio/mpeg',
            '.zip': 'application/zip',
            '.exe': 'application/x-msdownload'
        }
        return mime_types.get(extension, 'application/octet-stream')
    
    def _get_permissions_string(self, stat_result) -> str:
        """Convertit les permissions en chaîne lisible."""
        if self.os_type == "Windows":
            # Sur Windows, les permissions sont plus simples
            mode = stat_result.st_mode
            permissions = ""
            permissions += "r" if os.access(stat_result, os.R_OK) else "-"
            permissions += "w" if os.access(stat_result, os.W_OK) else "-"
            permissions += "x" if os.access(stat_result, os.X_OK) else "-"
            return permissions
        else:
            # Sur Unix, utiliser le format standard
            import stat as stat_module
            mode = stat_result.st_mode
            
            permissions = ""
            # Propriétaire
            permissions += "r" if mode & stat_module.S_IRUSR else "-"
            permissions += "w" if mode & stat_module.S_IWUSR else "-" 
            permissions += "x" if mode & stat_module.S_IXUSR else "-"
            # Groupe
            permissions += "r" if mode & stat_module.S_IRGRP else "-"
            permissions += "w" if mode & stat_module.S_IWGRP else "-"
            permissions += "x" if mode & stat_module.S_IXGRP else "-"
            # Autres
            permissions += "r" if mode & stat_module.S_IROTH else "-"
            permissions += "w" if mode & stat_module.S_IWOTH else "-"
            permissions += "x" if mode & stat_module.S_IXOTH else "-"
            
            return permissions
    
    def search_files(self, root_path: str, query: str, file_types: List[FileType] = None,
                    max_results: int = 100) -> List[FileInfo]:
        """
        Recherche des fichiers dans une arborescence.
        
        Args:
            root_path (str): Répertoire racine de la recherche
            query (str): Terme de recherche (dans le nom de fichier)
            file_types (List[FileType]): Types de fichiers à inclure
            max_results (int): Nombre maximum de résultats
            
        Returns:
            List[FileInfo]: Fichiers correspondants
        """
        results = []
        query_lower = query.lower()
        
        try:
            for root, dirs, files in os.walk(root_path):
                # Vérifier si on a atteint la limite
                if len(results) >= max_results:
                    break
                
                # Chercher dans les dossiers
                for dir_name in dirs[:]:  # Copie pour pouvoir modifier
                    if len(results) >= max_results:
                        break
                    
                    if query_lower in dir_name.lower():
                        try:
                            dir_path = Path(root) / dir_name
                            file_info = self._create_file_info(dir_path)
                            
                            # Filtrer par type si spécifié
                            if file_types is None or file_info.file_type in file_types:
                                results.append(file_info)
                        except Exception as e:
                            logger.debug(f"Erreur lors de l'ajout du dossier {dir_name}: {e}")
                
                # Chercher dans les fichiers
                for file_name in files:
                    if len(results) >= max_results:
                        break
                    
                    if query_lower in file_name.lower():
                        try:
                            file_path = Path(root) / file_name
                            file_info = self._create_file_info(file_path)
                            
                            # Filtrer par type si spécifié
                            if file_types is None or file_info.file_type in file_types:
                                results.append(file_info)
                        except Exception as e:
                            logger.debug(f"Erreur lors de l'ajout du fichier {file_name}: {e}")
        
        except Exception as e:
            logger.error(f"Erreur lors de la recherche dans {root_path}: {e}")
        
        # Trier par pertinence (correspondance exacte en premier)
        results.sort(key=lambda x: (query_lower not in x.name.lower(), x.name.lower()))
        
        return results[:max_results]
    
    def get_device_by_id(self, device_id: str) -> Optional[StorageDevice]:
        """Récupère un périphérique par son ID."""
        with self.devices_lock:
            return self.devices.get(device_id)
    
    def get_all_devices(self) -> List[StorageDevice]:
        """Récupère tous les périphériques détectés."""
        with self.devices_lock:
            return list(self.devices.values())
    
    def refresh_device_info(self, device_id: str) -> Optional[StorageDevice]:
        """Actualise les informations d'un périphérique."""
        with self.devices_lock:
            device = self.devices.get(device_id)
            if not device:
                return None
            
            try:
                # Actualiser l'espace disque
                if device.is_ready and os.path.exists(device.mount_point):
                    usage = psutil.disk_usage(device.mount_point)
                    device.total_size = usage.total
                    device.used_size = usage.used
                    device.free_size = usage.free
                    device.is_ready = True
                else:
                    device.is_ready = False
                
                return device
                
            except Exception as e:
                logger.debug(f"Erreur lors de l'actualisation du périphérique {device_id}: {e}")
                device.is_ready = False
                return device
    
    def get_directory_size(self, path: str) -> int:
        """
        Calcule la taille totale d'un répertoire.
        
        Args:
            path (str): Chemin du répertoire
            
        Returns:
            int: Taille totale en bytes
        """
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(path):
                for file_name in files:
                    try:
                        file_path = os.path.join(root, file_name)
                        total_size += os.path.getsize(file_path)
                    except (OSError, FileNotFoundError):
                        continue
        except Exception as e:
            logger.error(f"Erreur lors du calcul de la taille de {path}: {e}")
        
        return total_size
    
    def format_file_size(self, size_bytes: int) -> str:
        """Formate une taille en bytes de manière lisible."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    def format_timestamp(self, timestamp: float) -> str:
        """Formate un timestamp en date lisible."""
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            return "Date inconnue"
    
    def is_safe_to_access(self, path: str) -> bool:
        """Vérifie si un chemin est sûr à accéder."""
        try:
            path_obj = Path(path).resolve()
            
            # Vérifier que le chemin existe
            if not path_obj.exists():
                return False
            
            # Vérifier les permissions de lecture
            if not os.access(path_obj, os.R_OK):
                return False
            
            # Éviter certains répertoires système sensibles
            sensitive_paths = []
            
            if self.os_type == "Windows":
                sensitive_paths = [
                    "c:\\windows\\system32",
                    "c:\\program files\\common files",
                    "$recycle.bin"
                ]
            elif self.os_type == "Linux":
                sensitive_paths = [
                    "/proc",
                    "/sys", 
                    "/dev",
                    "/root"
                ]
            
            path_str = str(path_obj).lower()
            for sensitive in sensitive_paths:
                if sensitive.lower() in path_str:
                    return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Erreur lors de la vérification de sécurité pour {path}: {e}")
            return False
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques globales de stockage."""
        stats = {
            'total_devices': 0,
            'total_storage': 0,
            'total_used': 0,
            'total_free': 0,
            'devices_by_type': {},
            'removable_devices': 0,
            'ready_devices': 0
        }
        
        with self.devices_lock:
            stats['total_devices'] = len(self.devices)
            
            for device in self.devices.values():
                # Totaux
                stats['total_storage'] += device.total_size
                stats['total_used'] += device.used_size
                stats['total_free'] += device.free_size
                
                # Par type
                device_type = device.device_type.value
                if device_type not in stats['devices_by_type']:
                    stats['devices_by_type'][device_type] = 0
                stats['devices_by_type'][device_type] += 1
                
                # Compteurs
                if device.is_removable:
                    stats['removable_devices'] += 1
                if device.is_ready:
                    stats['ready_devices'] += 1
        
        return stats


class StorageExplorerUI:
    """Interface utilisateur pour l'explorateur de stockage."""
    
    def __init__(self, explorer: StorageExplorer):
        self.explorer = explorer
        self.current_path = ""
        self.navigation_history = []
        self.current_device = None
    
    def display_devices(self):
        """Affiche la liste des périphériques détectés."""
        devices = self.explorer.scan_storage_devices()
        
        print("=" * 80)
        print("💾 PÉRIPHÉRIQUES DE STOCKAGE DÉTECTÉS")
        print("=" * 80)
        
        if not devices:
            print("❌ Aucun périphérique de stockage détecté")
            return
        
        # Grouper par type
        devices_by_type = {}
        for device in devices:
            device_type = device.device_type
            if device_type not in devices_by_type:
                devices_by_type[device_type] = []
            devices_by_type[device_type].append(device)
        
        # Afficher par type
        type_icons = {
            DeviceType.INTERNAL_HDD: "🔵",
            DeviceType.INTERNAL_SSD: "🟣", 
            DeviceType.USB_DRIVE: "🟡",
            DeviceType.EXTERNAL_HDD: "🟠",
            DeviceType.OPTICAL_DRIVE: "🔴",
            DeviceType.NETWORK_DRIVE: "🟢",
            DeviceType.VIRTUAL_DRIVE: "⚪"
        }
        
        device_counter = 1
        self.device_menu = {}  # Pour la sélection
        
        for device_type, device_list in devices_by_type.items():
            icon = type_icons.get(device_type, "⚫")
            print(f"\n{icon} {device_type.value.upper().replace('_', ' ')}")
            print("-" * 50)
            
            for device in device_list:
                status = "🟢 Prêt" if device.is_ready else "🔴 Non disponible"
                removable = "📱 Amovible" if device.is_removable else "💻 Fixe"
                
                print(f"  {device_counter}. {device.name}")
                print(f"     📂 Point de montage: {device.mount_point}")
                print(f"     💾 Espace: {self.explorer.format_file_size(device.used_size)} / "
                      f"{self.explorer.format_file_size(device.total_size)} utilisés")
                
                if device.total_size > 0:
                    usage_percent = (device.used_size / device.total_size) * 100
                    print(f"     📊 Utilisation: {usage_percent:.1f}%")
                
                print(f"     🗂️ Système de fichiers: {device.file_system}")
                print(f"     {status} • {removable}")
                
                if device.vendor or device.model:
                    print(f"     🏷️ Modèle: {device.vendor} {device.model}".strip())
                
                print()
                
                self.device_menu[device_counter] = device
                device_counter += 1
        
        # Statistiques globales
        stats = self.explorer.get_storage_statistics()
        print("📊 STATISTIQUES GLOBALES")
        print("-" * 30)
        print(f"🔢 Nombre de périphériques: {stats['total_devices']}")
        print(f"💾 Stockage total: {self.explorer.format_file_size(stats['total_storage'])}")
        print(f"📈 Espace utilisé: {self.explorer.format_file_size(stats['total_used'])}")
        print(f"📉 Espace libre: {self.explorer.format_file_size(stats['total_free'])}")
        print(f"📱 Périphériques amovibles: {stats['removable_devices']}")
    
    def navigate_to_device(self, device: StorageDevice):
        """Navigue vers un périphérique."""
        if not device.is_ready:
            print(f"❌ Le périphérique {device.name} n'est pas accessible")
            return False
        
        if not self.explorer.is_safe_to_access(device.mount_point):
            print(f"⚠️ Accès refusé au périphérique {device.name}")
            return False
        
        self.current_device = device
        self.current_path = device.mount_point
        self.navigation_history.append(self.current_path)
        
        print(f"📂 Navigation vers: {device.name} ({device.mount_point})")
        self.display_directory_contents()
        return True
    
    def display_directory_contents(self):
        """Affiche le contenu du répertoire actuel."""
        if not self.current_path:
            print("❌ Aucun répertoire sélectionné")
            return
        
        print(f"\n📁 Contenu de: {self.current_path}")
        print("=" * 80)
        
        try:
            contents = self.explorer.list_directory_contents(self.current_path)
            
            if not contents:
                print("📭 Répertoire vide ou inaccessible")
                return
            
            # Séparer dossiers et fichiers
            folders = [item for item in contents if item.is_directory]
            files = [item for item in contents if not item.is_directory]
            
            item_counter = 1
            self.content_menu = {}
            
            # Afficher les dossiers
            if folders:
                print("📁 DOSSIERS:")
                print("-" * 20)
                for folder in folders:
                    hidden_indicator = "🔒" if folder.is_hidden else ""
                    print(f"  {item_counter}. 📁 {folder.name} {hidden_indicator}")
                    print(f"      📅 Modifié: {self.explorer.format_timestamp(folder.modified_time)}")
                    print(f"      🔐 Permissions: {folder.permissions}")
                    print()
                    
                    self.content_menu[item_counter] = folder
                    item_counter += 1
            
            # Afficher les fichiers
            if files:
                print("📄 FICHIERS:")
                print("-" * 20)
                
                # Grouper par type
                files_by_type = {}
                for file_item in files:
                    file_type = file_item.file_type
                    if file_type not in files_by_type:
                        files_by_type[file_type] = []
                    files_by_type[file_type].append(file_item)
                
                # Icônes par type
                type_icons = {
                    FileType.DOCUMENT: "📄",
                    FileType.IMAGE: "🖼️",
                    FileType.VIDEO: "🎥",
                    FileType.AUDIO: "🎵",
                    FileType.ARCHIVE: "📦",
                    FileType.EXECUTABLE: "⚙️",
                    FileType.OTHER: "📋"
                }
                
                for file_type, file_list in files_by_type.items():
                    if file_list:
                        print(f"\n{type_icons.get(file_type, '📋')} {file_type.value.upper()}:")
                        
                        for file_item in file_list:
                            hidden_indicator = "🔒" if file_item.is_hidden else ""
                            print(f"  {item_counter}. {file_item.name} {hidden_indicator}")
                            print(f"      📏 Taille: {self.explorer.format_file_size(file_item.size)}")
                            print(f"      📅 Modifié: {self.explorer.format_timestamp(file_item.modified_time)}")
                            print(f"      🔐 Permissions: {file_item.permissions}")
                            if file_item.extension:
                                print(f"      🏷️ Type: {file_item.extension.upper()} ({file_item.mime_type})")
                            print()
                            
                            self.content_menu[item_counter] = file_item
                            item_counter += 1
            
            # Résumé
            total_items = len(contents)
            total_size = sum(item.size for item in files)
            print(f"📊 RÉSUMÉ: {len(folders)} dossier(s), {len(files)} fichier(s)")
            print(f"💾 Taille totale des fichiers: {self.explorer.format_file_size(total_size)}")
            
        except Exception as e:
            print(f"❌ Erreur lors de l'affichage du contenu: {e}")
    
    def navigate_to_item(self, item: FileInfo):
        """Navigue vers un élément (dossier uniquement)."""
        if not item.is_directory:
            print(f"📄 {item.name} est un fichier, pas un dossier")
            return False
        
        if not self.explorer.is_safe_to_access(item.path):
            print(f"⚠️ Accès refusé au dossier {item.name}")
            return False
        
        self.current_path = item.path
        self.navigation_history.append(self.current_path)
        
        print(f"📂 Navigation vers: {item.name}")
        self.display_directory_contents()
        return True
    
    def go_back(self):
        """Remonte d'un niveau dans la navigation."""
        if len(self.navigation_history) <= 1:
            print("📍 Déjà au niveau racine")
            return False
        
        # Enlever le répertoire actuel
        self.navigation_history.pop()
        
        # Retourner au précédent
        if self.navigation_history:
            self.current_path = self.navigation_history[-1]
        else:
            self.current_path = ""
        
        if self.current_path:
            print(f"⬅️ Retour vers: {self.current_path}")
            self.display_directory_contents()
        else:
            print("📋 Retour à la liste des périphériques")
            self.display_devices()
        
        return True
    
    def search_files_interactive(self):
        """Interface interactive de recherche."""
        if not self.current_path:
            print("❌ Sélectionnez d'abord un périphérique")
            return
        
        print("\n🔍 RECHERCHE DE FICHIERS")
        print("=" * 40)
        
        # Demander les critères de recherche
        query = input("🔤 Terme de recherche: ").strip()
        if not query:
            print("❌ Terme de recherche requis")
            return
        
        print("\n📂 Types de fichiers à inclure:")
        print("1. Tous les types")
        print("2. Documents uniquement")
        print("3. Images uniquement") 
        print("4. Vidéos uniquement")
        print("5. Audio uniquement")
        print("6. Dossiers uniquement")
        
        try:
            choice = input("\nVotre choix (1-6): ").strip()
            
            file_types_filter = None
            if choice == "2":
                file_types_filter = [FileType.DOCUMENT]
            elif choice == "3":
                file_types_filter = [FileType.IMAGE]
            elif choice == "4":
                file_types_filter = [FileType.VIDEO]
            elif choice == "5":
                file_types_filter = [FileType.AUDIO]
            elif choice == "6":
                file_types_filter = [FileType.FOLDER]
            
            print(f"\n🔍 Recherche de '{query}' dans {self.current_path}...")
            print("⏳ Recherche en cours...")
            
            # Effectuer la recherche
            results = self.explorer.search_files(
                self.current_path, 
                query, 
                file_types_filter, 
                max_results=50
            )
            
            print(f"\n📋 RÉSULTATS DE RECHERCHE ({len(results)} trouvé(s))")
            print("=" * 60)
            
            if not results:
                print("📭 Aucun résultat trouvé")
                return
            
            # Afficher les résultats
            for i, result in enumerate(results, 1):
                icon = "📁" if result.is_directory else "📄"
                print(f"{i:2d}. {icon} {result.name}")
                print(f"     📂 Dans: {os.path.dirname(result.path)}")
                if not result.is_directory:
                    print(f"     📏 Taille: {self.explorer.format_file_size(result.size)}")
                print(f"     📅 Modifié: {self.explorer.format_timestamp(result.modified_time)}")
                print()
                
        except (KeyboardInterrupt, EOFError):
            print("\n❌ Recherche annulée")
        except Exception as e:
            print(f"❌ Erreur lors de la recherche: {e}")


def main():
    """
    Fonction principale de démonstration du module d'exploration de stockage.
    """
    print("=" * 80)
    print("💾 DATASHARE - EXPLORATEUR DE STOCKAGE")
    print("=" * 80)
    
    # Initialisation
    explorer = StorageExplorer()
    ui = StorageExplorerUI(explorer)
    
    print("✅ Explorateur de stockage initialisé")
    print(f"🖥️ Système détecté: {explorer.os_type}")
    
    print("\n🔍 Scan des périphériques de stockage en cours...")
    
    # Interface interactive
    try:
        while True:
            print("\n" + "=" * 50)
            print("📋 MENU PRINCIPAL")
            print("=" * 50)
            print("1. 💾 Afficher les périphériques de stockage")
            print("2. 📁 Explorer un périphérique")
            print("3. 🔍 Rechercher des fichiers")
            print("4. ⬅️ Retour / Navigation")
            print("5. 📊 Statistiques de stockage")
            print("6. 🔄 Actualiser la liste des périphériques")
            print("7. ❌ Quitter")
            
            try:
                choice = input("\n📝 Votre choix (1-7): ").strip()
                
                if choice == "1":
                    # Afficher les périphériques
                    ui.display_devices()
                
                elif choice == "2":
                    # Explorer un périphérique
                    if hasattr(ui, 'device_menu') and ui.device_menu:
                        print("\n📱 Sélectionnez un périphérique à explorer:")
                        device_choice = input("Numéro du périphérique: ").strip()
                        
                        try:
                            device_num = int(device_choice)
                            if device_num in ui.device_menu:
                                device = ui.device_menu[device_num]
                                ui.navigate_to_device(device)
                            else:
                                print("❌ Numéro de périphérique invalide")
                        except ValueError:
                            print("❌ Veuillez entrer un numéro valide")
                    else:
                        print("❌ Affichez d'abord la liste des périphériques (option 1)")
                
                elif choice == "3":
                    # Rechercher des fichiers
                    ui.search_files_interactive()
                
                elif choice == "4":
                    # Navigation
                    if ui.current_path:
                        print("\n🧭 NAVIGATION")
                        print("1. ⬅️ Remonter d'un niveau")
                        print("2. 📂 Naviguer vers un dossier")
                        print("3. 🏠 Retour aux périphériques")
                        
                        nav_choice = input("Choix: ").strip()
                        
                        if nav_choice == "1":
                            ui.go_back()
                        elif nav_choice == "2":
                            if hasattr(ui, 'content_menu') and ui.content_menu:
                                print("Sélectionnez un dossier:")
                                folder_choice = input("Numéro: ").strip()
                                try:
                                    folder_num = int(folder_choice)
                                    if folder_num in ui.content_menu:
                                        item = ui.content_menu[folder_num]
                                        if item.is_directory:
                                            ui.navigate_to_item(item)
                                        else:
                                            print("❌ Cet élément n'est pas un dossier")
                                    else:
                                        print("❌ Numéro invalide")
                                except ValueError:
                                    print("❌ Veuillez entrer un numéro valide")
                            else:
                                print("❌ Aucun contenu affiché")
                        elif nav_choice == "3":
                            ui.current_path = ""
                            ui.navigation_history = []
                            ui.current_device = None
                            print("🏠 Retour à la liste des périphériques")
                    else:
                        print("❌ Vous êtes déjà au niveau racine")
                
                elif choice == "5":
                    # Statistiques
                    stats = explorer.get_storage_statistics()
                    print("\n📊 STATISTIQUES DE STOCKAGE")
                    print("=" * 40)
                    print(f"🔢 Périphériques détectés: {stats['total_devices']}")
                    print(f"💾 Capacité totale: {explorer.format_file_size(stats['total_storage'])}")
                    print(f"📈 Espace utilisé: {explorer.format_file_size(stats['total_used'])}")
                    print(f"📉 Espace libre: {explorer.format_file_size(stats['total_free'])}")
                    print(f"📱 Périphériques amovibles: {stats['removable_devices']}")
                    print(f"🟢 Périphériques prêts: {stats['ready_devices']}")
                    
                    print("\n📋 Répartition par type:")
                    for device_type, count in stats['devices_by_type'].items():
                        print(f"  • {device_type.replace('_', ' ').title()}: {count}")
                
                elif choice == "6":
                    # Actualiser
                    print("🔄 Actualisation des périphériques...")
                    explorer.scan_storage_devices()
                    print("✅ Liste actualisée")
                
                elif choice == "7":
                    # Quitter
                    break
                
                else:
                    print("❌ Choix invalide, veuillez réessayer")
                    
            except KeyboardInterrupt:
                print("\n⏸️ Interruption détectée")
                break
            except Exception as e:
                print(f"❌ Erreur: {e}")
    
    except KeyboardInterrupt:
        print("\n🛑 Arrêt demandé")
    
    finally:
        print("\n📊 RÉSUMÉ DE LA SESSION")
        print("=" * 30)
        stats = explorer.get_storage_statistics()
        print(f"💾 Périphériques explorés: {stats['total_devices']}")
        print(f"📁 Répertoire final: {ui.current_path or 'Racine'}")
        
        print("\n✅ Explorateur de stockage fermé")
        print("🎉 Merci d'avoir utilisé DataShare!")


if __name__ == "__main__":
    main()
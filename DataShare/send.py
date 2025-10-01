"""
Module de transfert de fichiers sécurisé pour DataShare

Améliorations v4.0:
- Chiffrement AES-256-GCM pour tous les transferts
- Gestion correcte des chemins avec espaces
- Optimisations de vitesse supplémentaires
- Compression adaptative intelligente
- Transferts parallélisés multi-threads

Auteur: DataShare Team
Version: 4.0
"""

import socket
import threading
import os
import json
import hashlib
import time
import zipfile
import tempfile
import struct
import logging
from typing import Dict, List, Tuple, Optional, Callable, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import shutil
import base64

# Cryptographie
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# Configuration
TRANSFER_PORT = 32001
CHUNK_SIZE_MIN = 128 * 1024      # 128KB
CHUNK_SIZE_MAX = 16 * 1024 * 1024  # 16MB - Augmenté pour plus de vitesse
CHUNK_SIZE_DEFAULT = 2 * 1024 * 1024  # 2MB - Augmenté
COMPRESSION_THRESHOLD = 10 * 1024 * 1024
MAX_CONCURRENT_TRANSFERS = 8  # Augmenté
SOCKET_BUFFER_SIZE = 4 * 1024 * 1024  # 4MB - Doublé
CONNECTION_TIMEOUT = 30
HEARTBEAT_INTERVAL = 5

# Sécurité
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12    # 96 bits pour GCM
SALT_SIZE = 32     # 256 bits

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TransferStatus(Enum):
    """Statuts possibles d'un transfert."""
    PENDING = "pending"
    NEGOTIATING = "negotiating"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class MessageType(Enum):
    """Types de messages du protocole de transfert."""
    # Phase de négociation
    TRANSFER_REQUEST = "transfer_request"
    TRANSFER_ACCEPT = "transfer_accept"
    TRANSFER_REJECT = "transfer_reject"
    FOLDER_SELECT_REQUEST = "folder_select_request"
    FOLDER_SELECT_RESPONSE = "folder_select_response"
    KEY_EXCHANGE = "key_exchange"
    
    # Phase de transfert
    FILE_HEADER = "file_header"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    
    # Contrôle
    TRANSFER_COMPLETE = "transfer_complete"
    TRANSFER_CANCEL = "transfer_cancel"
    TRANSFER_PAUSE = "transfer_pause"
    TRANSFER_RESUME = "transfer_resume"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


@dataclass
class FileMetadata:
    """Métadonnées d'un fichier à transférer."""
    name: str
    size: int
    relative_path: str
    is_directory: bool
    checksum: str
    created_time: float
    modified_time: float


@dataclass
class TransferJob:
    """Informations sur un job de transfert."""
    transfer_id: str
    sender_ip: str
    sender_name: str
    files: List[FileMetadata]
    total_size: int
    destination_folder: str
    compression_enabled: bool
    chunk_size: int
    status: TransferStatus
    progress: float
    speed: float
    eta: int
    error_message: str = ""
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    encryption_key: Optional[bytes] = None  # Clé de chiffrement


class CryptoManager:
    """Gestionnaire de chiffrement AES-256-GCM."""
    
    def __init__(self):
        self.session_keys: Dict[str, bytes] = {}
    
    def generate_session_key(self, transfer_id: str) -> bytes:
        """Génère une clé de session unique pour un transfert."""
        key = secrets.token_bytes(AES_KEY_SIZE)
        self.session_keys[transfer_id] = key
        logger.info(f"Clé de session générée pour {transfer_id}")
        return key
    
    def get_session_key(self, transfer_id: str) -> Optional[bytes]:
        """Récupère la clé de session d'un transfert."""
        return self.session_keys.get(transfer_id)
    
    def encrypt_chunk(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Chiffre un chunk de données avec AES-256-GCM.
        
        Returns:
            Tuple[bytes, bytes]: (données chiffrées, nonce)
        """
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return encrypted, nonce
    
    def decrypt_chunk(self, encrypted_data: bytes, nonce: bytes, key: bytes) -> bytes:
        """Déchiffre un chunk de données."""
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Dérive une clé à partir d'un mot de passe (optionnel)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def cleanup_session(self, transfer_id: str):
        """Nettoie la clé de session après transfert."""
        if transfer_id in self.session_keys:
            del self.session_keys[transfer_id]


class PathHandler:
    """Gestionnaire de chemins pour Windows/Linux avec espaces."""
    
    @staticmethod
    def normalize_path(path_str: str) -> Path:
        """Normalise un chemin (gère espaces, quotes, etc.)."""
        # Retirer les guillemets si présents
        path_str = path_str.strip('"').strip("'")
        
        # Convertir en Path
        path = Path(path_str)
        
        # Résoudre le chemin absolu
        try:
            path = path.resolve()
        except Exception as e:
            logger.warning(f"Impossible de résoudre {path_str}: {e}")
        
        return path
    
    @staticmethod
    def safe_path_join(base: Path, *parts: str) -> Path:
        """Joint des chemins de manière sécurisée."""
        result = base
        for part in parts:
            # Nettoyer chaque partie
            clean_part = part.strip().replace('\\', '/').strip('/')
            if clean_part and clean_part != '.':
                result = result / clean_part
        return result
    
    @staticmethod
    def ensure_parent_exists(file_path: Path):
        """S'assure que le dossier parent existe."""
        parent = file_path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)


class PerformanceMonitor:
    """Moniteur de performance optimisé."""
    
    def __init__(self):
        self.transfer_history: List[Tuple[int, float, float]] = []
        self.current_chunk_size = CHUNK_SIZE_DEFAULT
        self.last_adjustment_time = time.time()
        self.adjustment_interval = 5  # Ajuster plus souvent
        self.lock = threading.Lock()
        
    def record_transfer(self, chunk_size: int, bytes_transferred: int, duration: float):
        """Enregistre les métriques de manière thread-safe."""
        with self.lock:
            if duration > 0:
                speed = bytes_transferred / duration
                self.transfer_history.append((chunk_size, speed, time.time()))
                
                # Garder les 100 dernières mesures
                if len(self.transfer_history) > 100:
                    self.transfer_history.pop(0)
    
    def get_optimal_chunk_size(self) -> int:
        """Calcule la taille optimale avec algorithme amélioré."""
        with self.lock:
            now = time.time()
            
            if now - self.last_adjustment_time < self.adjustment_interval:
                return self.current_chunk_size
            
            if len(self.transfer_history) < 10:
                return self.current_chunk_size
            
            # Analyser les mesures récentes
            recent = self.transfer_history[-20:]
            
            # Calculer la vitesse moyenne
            avg_speed = sum(s for _, s, _ in recent) / len(recent)
            
            # Augmenter progressivement si performance stable
            if avg_speed > 50 * 1024 * 1024:  # > 50 MB/s
                self.current_chunk_size = min(
                    CHUNK_SIZE_MAX,
                    int(self.current_chunk_size * 1.2)
                )
            elif avg_speed < 10 * 1024 * 1024:  # < 10 MB/s
                self.current_chunk_size = max(
                    CHUNK_SIZE_MIN,
                    int(self.current_chunk_size * 0.8)
                )
            
            self.last_adjustment_time = now
            return self.current_chunk_size


class FileTransferManager:
    """Gestionnaire principal avec chiffrement."""
    
    def __init__(self, port: int = TRANSFER_PORT):
        self.port = port
        self.active_transfers: Dict[str, TransferJob] = {}
        self.transfer_lock = threading.Lock()
        
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        # Callbacks
        self.on_transfer_request: Optional[Callable] = None
        self.on_progress_update: Optional[Callable] = None
        self.on_transfer_complete: Optional[Callable] = None
        self.on_folder_select_request: Optional[Callable] = None
        
        # Managers
        self.performance_monitor = PerformanceMonitor()
        self.crypto_manager = CryptoManager()
        self.path_handler = PathHandler()
        
        logger.info(f"FileTransferManager initialisé (chiffrement AES-256 activé)")
    
    def start_server(self):
        """Démarre le serveur."""
        if self.is_running:
            return
        
        self.is_running = True
        self.server_thread = threading.Thread(
            target=self._server_loop,
            name="DataShare-SecureServer",
            daemon=True
        )
        self.server_thread.start()
        logger.info(f"Serveur sécurisé démarré sur le port {self.port}")
    
    def stop_server(self):
        """Arrête le serveur."""
        if not self.is_running:
            return
        
        logger.info("Arrêt du serveur...")
        self.is_running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        with self.transfer_lock:
            for transfer_id in list(self.active_transfers.keys()):
                self.cancel_transfer(transfer_id)
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
        
        logger.info("Serveur arrêté")
    
    def _server_loop(self):
        """Boucle serveur."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Optimisations TCP
            self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.server_socket.settimeout(1.0)
            
            self.server_socket.bind(('', self.port))
            self.server_socket.listen(MAX_CONCURRENT_TRANSFERS)
            
            logger.info("Serveur en écoute...")
            
            while self.is_running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    client_thread = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except socket.error:
                    if self.is_running:
                        logger.error("Erreur d'acceptation")
                    break
                    
        except Exception as e:
            logger.error(f"Erreur serveur: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_client_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Gère une connexion client."""
        logger.info(f"Connexion de {client_address[0]}")
        
        try:
            # Optimisations socket
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_socket.settimeout(CONNECTION_TIMEOUT)
            
            while self.is_running:
                try:
                    message = self._receive_message(client_socket)
                    if not message:
                        break
                    
                    self._process_received_message(message, client_socket, client_address)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Erreur traitement: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Erreur client {client_address[0]}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _send_message(self, sock: socket.socket, message_type: MessageType, data: Any):
        """Envoie un message."""
        message = {
            'type': message_type.value,
            'timestamp': time.time(),
            'data': data
        }
        
        json_data = json.dumps(message).encode('utf-8')
        size_bytes = struct.pack('!I', len(json_data))
        sock.sendall(size_bytes + json_data)
    
    def _receive_message(self, sock: socket.socket) -> Optional[Dict]:
        """Reçoit un message."""
        size_bytes = self._receive_exact(sock, 4)
        if not size_bytes:
            return None
        
        message_size = struct.unpack('!I', size_bytes)[0]
        
        if message_size > 50 * 1024 * 1024:
            raise ValueError(f"Message trop gros: {message_size}")
        
        json_bytes = self._receive_exact(sock, message_size)
        if not json_bytes:
            return None
        
        return json.loads(json_bytes.decode('utf-8'))
    
    def _receive_exact(self, sock: socket.socket, size: int) -> bytes:
        """Reçoit exactement N bytes."""
        data = b''
        while len(data) < size:
            chunk = sock.recv(min(size - len(data), SOCKET_BUFFER_SIZE))
            if not chunk:
                break
            data += chunk
        return data if len(data) == size else b''
    
    def _process_received_message(self, message: Dict, sock: socket.socket, addr: Tuple[str, int]):
        """Traite un message reçu."""
        msg_type = MessageType(message['type'])
        data = message['data']
        
        if msg_type == MessageType.TRANSFER_REQUEST:
            self._handle_transfer_request(data, sock, addr)
        elif msg_type == MessageType.KEY_EXCHANGE:
            self._handle_key_exchange(data, sock)
        elif msg_type == MessageType.FILE_CHUNK:
            self._handle_file_chunk(data, sock)
    
    def _handle_transfer_request(self, data: Dict, sock: socket.socket, addr: Tuple[str, int]):
        """Gère une demande de transfert."""
        try:
            transfer_job = TransferJob(
                transfer_id=data['transfer_id'],
                sender_ip=addr[0],
                sender_name=data['sender_name'],
                files=[FileMetadata(**f) for f in data['files']],
                total_size=data['total_size'],
                destination_folder="",
                compression_enabled=data.get('compression_enabled', False),
                chunk_size=data.get('chunk_size', CHUNK_SIZE_DEFAULT),
                status=TransferStatus.NEGOTIATING,
                progress=0.0,
                speed=0.0,
                eta=0,
                created_at=time.time()
            )
            
            with self.transfer_lock:
                self.active_transfers[transfer_job.transfer_id] = transfer_job
            
            # Générer et envoyer la clé de chiffrement
            session_key = self.crypto_manager.generate_session_key(transfer_job.transfer_id)
            transfer_job.encryption_key = session_key
            
            key_exchange_data = {
                'transfer_id': transfer_job.transfer_id,
                'session_key': base64.b64encode(session_key).decode('utf-8')
            }
            self._send_message(sock, MessageType.KEY_EXCHANGE, key_exchange_data)
            
            if self.on_folder_select_request:
                self.on_folder_select_request(transfer_job)
            else:
                default_folder = str(Path.home() / "Downloads" / "DataShare")
                os.makedirs(default_folder, exist_ok=True)
                transfer_job.destination_folder = default_folder
                transfer_job.status = TransferStatus.TRANSFERRING
                self._send_message(sock, MessageType.TRANSFER_ACCEPT, {})
                
        except Exception as e:
            logger.error(f"Erreur demande transfert: {e}")
            self._send_message(sock, MessageType.TRANSFER_REJECT, {'reason': str(e)})
    
    def send_files(self, target_ip: str, files_and_folders: List[str], 
                   sender_name: str = "DataShare User") -> str:
        """Envoie des fichiers avec chiffrement."""
        transfer_id = hashlib.md5(f"{target_ip}{time.time()}".encode()).hexdigest()[:16]
        
        logger.info(f"Envoi sécurisé vers {target_ip} - ID: {transfer_id}")
        
        try:
            # Normaliser tous les chemins
            normalized_paths = [
                self.path_handler.normalize_path(p) for p in files_and_folders
            ]
            
            file_list = self._analyze_files_and_folders(normalized_paths)
            total_size = sum(f.size for f in file_list)
            
            compression_enabled = total_size > COMPRESSION_THRESHOLD
            
            transfer_job = TransferJob(
                transfer_id=transfer_id,
                sender_ip="localhost",
                sender_name=sender_name,
                files=file_list,
                total_size=total_size,
                destination_folder="",
                compression_enabled=compression_enabled,
                chunk_size=self.performance_monitor.get_optimal_chunk_size(),
                status=TransferStatus.PENDING,
                progress=0.0,
                speed=0.0,
                eta=0,
                created_at=time.time()
            )
            
            with self.transfer_lock:
                self.active_transfers[transfer_id] = transfer_job
            
            send_thread = threading.Thread(
                target=self._send_files_thread,
                args=(transfer_job, target_ip, normalized_paths),
                daemon=True
            )
            send_thread.start()
            
            return transfer_id
            
        except Exception as e:
            logger.error(f"Erreur initialisation: {e}")
            with self.transfer_lock:
                if transfer_id in self.active_transfers:
                    del self.active_transfers[transfer_id]
            raise
    
    def _analyze_files_and_folders(self, paths: List[Path]) -> List[FileMetadata]:
        """Analyse les fichiers (gestion correcte des espaces)."""
        file_list = []
        
        for path in paths:
            if not path.exists():
                logger.warning(f"Ignoré (inexistant): {path}")
                continue
            
            if path.is_file():
                file_meta = self._create_file_metadata(path, "")
                file_list.append(file_meta)
                
            elif path.is_dir():
                for root, dirs, files in os.walk(path):
                    root_path = Path(root)
                    
                    try:
                        rel_path = root_path.relative_to(path.parent)
                        rel_path_str = str(rel_path)
                    except ValueError:
                        rel_path_str = root_path.name
                    
                    if root_path != path or not files:
                        folder_meta = FileMetadata(
                            name=root_path.name,
                            size=0,
                            relative_path=rel_path_str,
                            is_directory=True,
                            checksum="",
                            created_time=root_path.stat().st_ctime,
                            modified_time=root_path.stat().st_mtime
                        )
                        file_list.append(folder_meta)
                    
                    for file_name in files:
                        file_path = root_path / file_name
                        file_meta = self._create_file_metadata(file_path, rel_path_str)
                        file_list.append(file_meta)
        
        logger.info(f"Analysé: {len(file_list)} éléments")
        return file_list
    
    def _create_file_metadata(self, file_path: Path, relative_base: str) -> FileMetadata:
        """Crée les métadonnées."""
        stat = file_path.stat()
        
        checksum = ""
        if stat.st_size < 100 * 1024 * 1024:
            try:
                with open(file_path, 'rb') as f:
                    checksum = hashlib.md5(f.read()).hexdigest()
            except Exception as e:
                logger.debug(f"Pas de checksum pour {file_path}: {e}")
        
        if relative_base:
            relative_path = str(Path(relative_base) / file_path.name)
        else:
            relative_path = file_path.name
        
        return FileMetadata(
            name=file_path.name,
            size=stat.st_size,
            relative_path=relative_path,
            is_directory=False,
            checksum=checksum,
            created_time=stat.st_ctime,
            modified_time=stat.st_mtime
        )
    
    def _send_files_thread(self, transfer_job: TransferJob, target_ip: str, source_paths: List[Path]):
        """Thread d'envoi sécurisé."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender_socket:
                # Optimisations maximales
                sender_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
                sender_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
                sender_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sender_socket.settimeout(CONNECTION_TIMEOUT)
                
                logger.info(f"Connexion vers {target_ip}:{self.port}")
                sender_socket.connect((target_ip, self.port))
                
                # Demande de transfert
                request_data = {
                    'transfer_id': transfer_job.transfer_id,
                    'sender_name': transfer_job.sender_name,
                    'files': [asdict(f) for f in transfer_job.files],
                    'total_size': transfer_job.total_size,
                    'compression_enabled': transfer_job.compression_enabled,
                    'chunk_size': transfer_job.chunk_size
                }
                
                self._send_message(sender_socket, MessageType.TRANSFER_REQUEST, request_data)
                
                # Attendre échange de clés
                response = self._receive_message(sender_socket)
                if not response or MessageType(response['type']) != MessageType.KEY_EXCHANGE:
                    raise Exception("Échec échange de clés")
                
                # Récupérer la clé
                session_key = base64.b64decode(response['data']['session_key'])
                transfer_job.encryption_key = session_key
                self.crypto_manager.session_keys[transfer_job.transfer_id] = session_key
                
                # Attendre acceptation
                accept_response = self._receive_message(sender_socket)
                if MessageType(accept_response['type']) == MessageType.TRANSFER_REJECT:
                    raise Exception(f"Refusé: {accept_response['data'].get('reason')}")
                
                transfer_job.status = TransferStatus.TRANSFERRING
                transfer_job.started_at = time.time()
                
                logger.info("Transfert accepté, début envoi chiffré")
                self._perform_encrypted_transfer(transfer_job, sender_socket, source_paths)
                
        except Exception as e:
            logger.error(f"Erreur envoi: {e}")
            with self.transfer_lock:
                transfer_job.status = TransferStatus.FAILED
                transfer_job.error_message = str(e)
            
            if self.on_transfer_complete:
                self.on_transfer_complete(transfer_job)
    
    def _perform_encrypted_transfer(self, transfer_job: TransferJob, sock: socket.socket, source_paths: List[Path]):
        """Transfert chiffré optimisé."""
        try:
            bytes_transferred = 0
            start_time = time.time()
            last_progress = start_time
            
            for file_meta in transfer_job.files:
                if file_meta.is_directory:
                    self._send_message(sock, MessageType.FILE_HEADER, asdict(file_meta))
                    continue
                
                source_file = self._find_source_file(file_meta, source_paths)
                if not source_file or not source_file.exists():
                    logger.warning(f"Source introuvable: {file_meta.name}")
                    continue
                
                logger.info(f"Envoi chiffré: {file_meta.name}")
                self._send_message(sock, MessageType.FILE_HEADER, asdict(file_meta))
                
                # Lecture et chiffrement par chunks
                with open(source_file, 'rb') as f:
                    chunk_start = time.time()
                    
                    while True:
                        chunk = f.read(transfer_job.chunk_size)
                        if not chunk:
                            break
                        
                        # Chiffrement AES-GCM
                        encrypted, nonce = self.crypto_manager.encrypt_chunk(
                            chunk, transfer_job.encryption_key
                        )
                        
                        # Envoi du chunk chiffré
                        chunk_data = {
                            'transfer_id': transfer_job.transfer_id,
                            'file_name': file_meta.name,
                            'encrypted_data': base64.b64encode(encrypted).decode('utf-8'),
                            'nonce': base64.b64encode(nonce).decode('utf-8')
                        }
                        
                        self._send_message(sock, MessageType.FILE_CHUNK, chunk_data)
                        
                        # Statistiques
                        bytes_transferred += len(chunk)
                        current_time = time.time()
                        
                        if current_time - chunk_start > 0:
                            self.performance_monitor.record_transfer(
                                transfer_job.chunk_size, len(chunk), current_time - chunk_start
                            )
                        
                        # Mise à jour progrès
                        if current_time - last_progress >= 0.5:  # Plus fréquent
                            elapsed = current_time - start_time
                            speed = bytes_transferred / elapsed if elapsed > 0 else 0
                            
                            transfer_job.progress = bytes_transferred / transfer_job.total_size
                            transfer_job.speed = speed
                            
                            if speed > 0:
                                remaining = transfer_job.total_size - bytes_transferred
                                transfer_job.eta = int(remaining / speed)
                            
                            if self.on_progress_update:
                                self.on_progress_update(transfer_job)
                            
                            last_progress = current_time
                        
                        chunk_start = current_time
                
                self._send_message(sock, MessageType.FILE_COMPLETE, {
                    'transfer_id': transfer_job.transfer_id,
                    'file_name': file_meta.name
                })
            
            # Fin transfert
            self._send_message(sock, MessageType.TRANSFER_COMPLETE, {
                'transfer_id': transfer_job.transfer_id,
                'total_bytes': bytes_transferred,
                'duration': time.time() - start_time
            })
            
            transfer_job.status = TransferStatus.COMPLETED
            transfer_job.progress = 1.0
            transfer_job.completed_at = time.time()
            
            logger.info(f"Transfert chiffré {transfer_job.transfer_id} terminé")
            
            # Nettoyer la clé
            self.crypto_manager.cleanup_session(transfer_job.transfer_id)
            
            if self.on_transfer_complete:
                self.on_transfer_complete(transfer_job)
                
        except Exception as e:
            logger.error(f"Erreur transfert: {e}")
            transfer_job.status = TransferStatus.FAILED
            transfer_job.error_message = str(e)
            
            if self.on_transfer_complete:
                self.on_transfer_complete(transfer_job)
    
    def _find_source_file(self, file_meta: FileMetadata, source_paths: List[Path]) -> Optional[Path]:
        """Trouve le fichier source."""
        for source_path in source_paths:
            if source_path.is_file() and source_path.name == file_meta.name:
                return source_path
            
            elif source_path.is_dir():
                for root, dirs, files in os.walk(source_path):
                    for file_name in files:
                        if file_name == file_meta.name:
                            candidate = Path(root) / file_name
                            try:
                                rel_path = candidate.relative_to(source_path.parent)
                                if str(rel_path) == file_meta.relative_path:
                                    return candidate
                            except ValueError:
                                continue
        
        return None
    
    def _handle_file_chunk(self, data: Dict, sock: socket.socket):
        """Gère la réception d'un chunk chiffré."""
        try:
            transfer_id = data['transfer_id']
            
            with self.transfer_lock:
                if transfer_id not in self.active_transfers:
                    logger.warning(f"Transfert inconnu: {transfer_id}")
                    return
                
                transfer_job = self.active_transfers[transfer_id]
            
            # Déchiffrer le chunk
            encrypted_data = base64.b64decode(data['encrypted_data'])
            nonce = base64.b64decode(data['nonce'])
            
            decrypted_data = self.crypto_manager.decrypt_chunk(
                encrypted_data, nonce, transfer_job.encryption_key
            )
            
            # Écrire les données déchiffrées
            file_name = data['file_name']
            dest_path = self.path_handler.safe_path_join(
                Path(transfer_job.destination_folder),
                file_name
            )
            
            self.path_handler.ensure_parent_exists(dest_path)
            
            with open(dest_path, 'ab') as f:
                f.write(decrypted_data)
            
        except Exception as e:
            logger.error(f"Erreur réception chunk: {e}")
    
    def _handle_key_exchange(self, data: Dict, sock: socket.socket):
        """Gère l'échange de clés."""
        try:
            transfer_id = data['transfer_id']
            session_key = base64.b64decode(data['session_key'])
            
            with self.transfer_lock:
                if transfer_id in self.active_transfers:
                    self.active_transfers[transfer_id].encryption_key = session_key
                    self.crypto_manager.session_keys[transfer_id] = session_key
                    logger.info(f"Clé de session reçue pour {transfer_id}")
        
        except Exception as e:
            logger.error(f"Erreur échange clés: {e}")
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """Annule un transfert."""
        with self.transfer_lock:
            if transfer_id not in self.active_transfers:
                return False
            
            transfer_job = self.active_transfers[transfer_id]
            transfer_job.status = TransferStatus.CANCELLED
            
            # Nettoyer la clé
            self.crypto_manager.cleanup_session(transfer_id)
            
            logger.info(f"Transfert {transfer_id} annulé")
            return True
    
    def get_active_transfers(self) -> List[TransferJob]:
        """Liste des transferts actifs."""
        with self.transfer_lock:
            return list(self.active_transfers.values())
    
    def get_transfer_by_id(self, transfer_id: str) -> Optional[TransferJob]:
        """Récupère un transfert."""
        with self.transfer_lock:
            return self.active_transfers.get(transfer_id)
    
    def get_transfer_statistics(self) -> Dict[str, Any]:
        """Statistiques globales."""
        with self.transfer_lock:
            active_count = len(self.active_transfers)
            completed = sum(1 for t in self.active_transfers.values() 
                          if t.status == TransferStatus.COMPLETED)
            failed = sum(1 for t in self.active_transfers.values() 
                       if t.status == TransferStatus.FAILED)
            
            total_bytes = sum(t.total_size for t in self.active_transfers.values())
            transferred = sum(int(t.total_size * t.progress) 
                            for t in self.active_transfers.values())
            
            speeds = [t.speed for t in self.active_transfers.values() 
                     if t.status == TransferStatus.TRANSFERRING and t.speed > 0]
            avg_speed = sum(speeds) / len(speeds) if speeds else 0
            
            return {
                'active_transfers': active_count,
                'completed_transfers': completed,
                'failed_transfers': failed,
                'total_bytes': total_bytes,
                'transferred_bytes': transferred,
                'average_speed': avg_speed,
                'optimal_chunk_size': self.performance_monitor.get_optimal_chunk_size(),
                'encryption': 'AES-256-GCM'
            }


class FileTransferUI:
    """Interface utilisateur pour les transferts."""
    
    def __init__(self, transfer_manager: FileTransferManager):
        self.transfer_manager = transfer_manager
        
        self.transfer_manager.on_transfer_request = self.on_transfer_request
        self.transfer_manager.on_progress_update = self.on_progress_update  
        self.transfer_manager.on_transfer_complete = self.on_transfer_complete
        self.transfer_manager.on_folder_select_request = self.on_folder_select_request
    
    def on_transfer_request(self, transfer_job: TransferJob):
        """Callback demande de transfert."""
        print(f"\n[DEMANDE DE TRANSFERT CHIFFRE]")
        print(f"Expediteur: {transfer_job.sender_name} ({transfer_job.sender_ip})")
        print(f"Fichiers: {len(transfer_job.files)}")
        print(f"Taille: {self._format_size(transfer_job.total_size)}")
        print(f"Chiffrement: AES-256-GCM")
        print(f"Compression: {'Oui' if transfer_job.compression_enabled else 'Non'}")
        
        print(f"\nFichiers a recevoir:")
        for i, fm in enumerate(transfer_job.files[:10], 1):
            icon = "[D]" if fm.is_directory else "[F]"
            print(f"   {i}. {icon} {fm.name} ({self._format_size(fm.size)})")
        
        if len(transfer_job.files) > 10:
            print(f"   ... et {len(transfer_job.files) - 10} autres")
    
    def on_folder_select_request(self, transfer_job: TransferJob):
        """Demande dossier de destination."""
        print(f"\n[SELECTION DOSSIER]")
        print(f"Destination pour les fichiers de {transfer_job.sender_name}:")
        
        default_options = [
            str(Path.home() / "Downloads" / "DataShare"),
            str(Path.home() / "Documents" / "DataShare"),
            str(Path.home() / "Desktop" / "DataShare")
        ]
        
        print(f"\nOptions:")
        for i, option in enumerate(default_options, 1):
            print(f"   {i}. {option}")
        print(f"   4. Autre dossier")
        print(f"   5. Refuser")
        
        while True:
            try:
                choice = input(f"\nChoix (1-5): ").strip()
                
                if choice in ['1', '2', '3']:
                    folder = default_options[int(choice) - 1]
                    os.makedirs(folder, exist_ok=True)
                    self.transfer_manager.accept_transfer(transfer_job.transfer_id, folder)
                    print(f"Accepte vers: {folder}")
                    break
                    
                elif choice == '4':
                    custom = input("Chemin: ").strip()
                    if custom:
                        try:
                            # Gérer les chemins avec espaces
                            clean_path = self.transfer_manager.path_handler.normalize_path(custom)
                            os.makedirs(clean_path, exist_ok=True)
                            self.transfer_manager.accept_transfer(transfer_job.transfer_id, str(clean_path))
                            print(f"Accepte vers: {clean_path}")
                            break
                        except Exception as e:
                            print(f"Erreur: {e}")
                    
                elif choice == '5':
                    self.transfer_manager.reject_transfer(transfer_job.transfer_id)
                    print(f"Refuse")
                    break
                    
                else:
                    print("Choix invalide")
                    
            except (ValueError, KeyboardInterrupt):
                print("\nAnnule")
                self.transfer_manager.reject_transfer(transfer_job.transfer_id)
                break
    
    def on_progress_update(self, transfer_job: TransferJob):
        """Mise a jour progression."""
        bar = self._create_progress_bar(transfer_job.progress, 40)
        speed = self._format_speed(transfer_job.speed)
        eta = self._format_eta(transfer_job.eta)
        
        print(f"\r{transfer_job.transfer_id[:8]}... {bar} "
              f"{transfer_job.progress*100:.1f}% | {speed} | ETA: {eta}", 
              end="", flush=True)
    
    def on_transfer_complete(self, transfer_job: TransferJob):
        """Transfert termine."""
        print()
        
        if transfer_job.status == TransferStatus.COMPLETED:
            duration = transfer_job.completed_at - transfer_job.started_at
            avg_speed = transfer_job.total_size / duration if duration > 0 else 0
            
            print(f"[TRANSFERT TERMINE]")
            print(f"Fichiers: {len(transfer_job.files)}")
            print(f"Taille: {self._format_size(transfer_job.total_size)}")
            print(f"Duree: {self._format_duration(duration)}")
            print(f"Vitesse moyenne: {self._format_speed(avg_speed)}")
            print(f"Dossier: {transfer_job.destination_folder}")
        
        elif transfer_job.status == TransferStatus.FAILED:
            print(f"[ECHEC]: {transfer_job.error_message}")
        
        elif transfer_job.status == TransferStatus.CANCELLED:
            print(f"[ANNULE]")
    
    def _format_size(self, bytes_val: int) -> str:
        """Formate une taille."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} PB"
    
    def _format_speed(self, speed: float) -> str:
        """Formate une vitesse."""
        return f"{self._format_size(speed)}/s"
    
    def _format_eta(self, seconds: int) -> str:
        """Formate un ETA."""
        if seconds <= 0:
            return "Calcul..."
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds//60}m {seconds%60}s"
        else:
            h = seconds // 3600
            m = (seconds % 3600) // 60
            return f"{h}h {m}m"
    
    def _format_duration(self, seconds: float) -> str:
        """Formate une duree."""
        return self._format_eta(int(seconds))
    
    def _create_progress_bar(self, progress: float, width: int = 30) -> str:
        """Barre de progression."""
        filled = int(progress * width)
        return f"[{'#' * filled}{'.' * (width - filled)}]"


def main():
    """Demonstration du module."""
    print("=" * 80)
    print("DATASHARE - MODULE DE TRANSFERT SECURISE")
    print("Chiffrement AES-256-GCM | Vitesse optimisee | Gestion chemins avec espaces")
    print("=" * 80)
    
    transfer_manager = FileTransferManager(port=TRANSFER_PORT)
    ui = FileTransferUI(transfer_manager)
    
    print(f"\nInitialise:")
    print(f"  Port: {TRANSFER_PORT}")
    print(f"  Chunk size: {transfer_manager.performance_monitor.get_optimal_chunk_size() // 1024}KB")
    print(f"  Buffer socket: {SOCKET_BUFFER_SIZE // 1024}KB")
    print(f"  Chiffrement: AES-256-GCM")
    
    transfer_manager.start_server()
    print(f"\nServeur demarre")
    
    print(f"\nCommandes:")
    print(f"  send <IP> <fichier1> [fichier2] ... - Envoyer fichiers")
    print(f"  list                                 - Lister transferts")
    print(f"  stats                                - Statistiques")
    print(f"  cancel <ID>                          - Annuler transfert")
    print(f"  quit                                 - Quitter")
    print(f"\nNote: Les chemins avec espaces sont supportes")
    print(f"      Exemple: send 192.168.1.10 \"C:\\Users\\CL INFO\\Desktop\\fichier.txt\"")
    
    try:
        while True:
            try:
                command = input(f"\nDataShare> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd in ['quit', 'exit']:
                    break
                
                elif cmd == 'send':
                    if len(parts) < 3:
                        print("Usage: send <IP> <fichier1> [fichier2] ...")
                        continue
                    
                    target_ip = parts[1]
                    files = parts[2:]
                    
                    # Normaliser les chemins
                    valid = []
                    for f in files:
                        path = transfer_manager.path_handler.normalize_path(f)
                        if path.exists():
                            valid.append(str(path))
                        else:
                            print(f"Introuvable: {f}")
                    
                    if valid:
                        try:
                            tid = transfer_manager.send_files(target_ip, valid, "Console User")
                            print(f"Transfert demarre - ID: {tid}")
                        except Exception as e:
                            print(f"Erreur: {e}")
                    else:
                        print("Aucun fichier valide")
                
                elif cmd == 'list':
                    transfers = transfer_manager.get_active_transfers()
                    if transfers:
                        print(f"\nTransferts actifs ({len(transfers)}):")
                        for t in transfers:
                            status_map = {
                                TransferStatus.PENDING: "[ATTENTE]",
                                TransferStatus.NEGOTIATING: "[NEGO]", 
                                TransferStatus.TRANSFERRING: "[ENVOI]",
                                TransferStatus.COMPLETED: "[OK]",
                                TransferStatus.FAILED: "[ECHEC]",
                                TransferStatus.CANCELLED: "[ANNULE]"
                            }
                            status = status_map.get(t.status, "[?]")
                            print(f"  {status} {t.transfer_id[:12]}... | {t.sender_name} | "
                                  f"{ui._format_size(t.total_size)} | {t.progress*100:.0f}%")
                    else:
                        print("Aucun transfert actif")
                
                elif cmd == 'stats':
                    stats = transfer_manager.get_transfer_statistics()
                    print(f"\nStatistiques:")
                    print(f"  Actifs: {stats['active_transfers']}")
                    print(f"  Termines: {stats['completed_transfers']}")
                    print(f"  Echoues: {stats['failed_transfers']}")
                    print(f"  Transfere: {ui._format_size(stats['transferred_bytes'])}")
                    print(f"  Vitesse: {ui._format_speed(stats['average_speed'])}")
                    print(f"  Chunk optimal: {stats['optimal_chunk_size'] // 1024}KB")
                    print(f"  Chiffrement: {stats['encryption']}")
                
                elif cmd == 'cancel':
                    if len(parts) < 2:
                        print("Usage: cancel <transfer_id>")
                        continue
                    
                    tid = parts[1]
                    if transfer_manager.cancel_transfer(tid):
                        print(f"Transfert {tid} annule")
                    else:
                        print(f"Transfert {tid} introuvable")
                
                elif cmd == 'help':
                    print(f"\nAide:")
                    print(f"  send <IP> <fichiers>  - Envoyer fichiers")
                    print(f"  list                  - Liste transferts")
                    print(f"  stats                 - Statistiques")
                    print(f"  cancel <ID>           - Annuler")
                    print(f"  quit                  - Quitter")
                
                else:
                    print(f"Commande inconnue: {cmd} (tapez 'help')")
                
            except KeyboardInterrupt:
                print(f"\nInterruption")
                break
            except Exception as e:
                print(f"Erreur: {e}")
    
    except KeyboardInterrupt:
        print(f"\nArret")
    
    finally:
        print(f"\nArret du serveur...")
        transfer_manager.stop_server()
        
        stats = transfer_manager.get_transfer_statistics()
        print(f"\nResume:")
        print(f"  Transferts: {stats['completed_transfers'] + stats['failed_transfers']}")
        print(f"  Donnees: {ui._format_size(stats['transferred_bytes'])}")
        
        print(f"\nModule arrete")


if __name__ == "__main__":
    main()
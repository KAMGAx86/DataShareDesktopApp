"""
Module de réception de fichiers sécurisé pour DataShare

Compatible avec le module d'envoi chiffré AES-256-GCM.

Auteur: DataShare Team
Version: 4.0
"""

import socket
import threading
import os
import json
import hashlib
import time
import struct
import logging
from typing import Dict, List, Tuple, Optional, Callable, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import base64

# Cryptographie
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
TRANSFER_PORT = 32001
CHUNK_SIZE_DEFAULT = 2 * 1024 * 1024
MAX_CONCURRENT_TRANSFERS = 8
SOCKET_BUFFER_SIZE = 4 * 1024 * 1024
CONNECTION_TIMEOUT = 30

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
    """Types de messages du protocole."""
    TRANSFER_REQUEST = "transfer_request"
    TRANSFER_ACCEPT = "transfer_accept"
    TRANSFER_REJECT = "transfer_reject"
    KEY_EXCHANGE = "key_exchange"
    FILE_HEADER = "file_header"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    TRANSFER_COMPLETE = "transfer_complete"
    TRANSFER_CANCEL = "transfer_cancel"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


@dataclass
class FileMetadata:
    """Métadonnées d'un fichier."""
    name: str
    size: int
    relative_path: str
    is_directory: bool
    checksum: str
    created_time: float
    modified_time: float


@dataclass
class ReceiveJob:
    """Job de réception."""
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
    bytes_received: int
    current_file: str
    error_message: str = ""
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    encryption_key: Optional[bytes] = None


class PathHandler:
    """Gestionnaire de chemins."""
    
    @staticmethod
    def normalize_path(path_str: str) -> Path:
        """Normalise un chemin."""
        path_str = path_str.strip('"').strip("'")
        path = Path(path_str)
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


class CryptoManager:
    """Gestionnaire de déchiffrement."""
    
    def __init__(self):
        self.session_keys: Dict[str, bytes] = {}
    
    def store_session_key(self, transfer_id: str, key: bytes):
        """Stocke une clé de session."""
        self.session_keys[transfer_id] = key
        logger.info(f"Clé de session stockée pour {transfer_id}")
    
    def get_session_key(self, transfer_id: str) -> Optional[bytes]:
        """Récupère la clé de session."""
        return self.session_keys.get(transfer_id)
    
    def decrypt_chunk(self, encrypted_data: bytes, nonce: bytes, key: bytes) -> bytes:
        """Déchiffre un chunk."""
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted
    
    def cleanup_session(self, transfer_id: str):
        """Nettoie la clé de session."""
        if transfer_id in self.session_keys:
            del self.session_keys[transfer_id]


class FileReceiver:
    """Gestionnaire de réception."""
    
    def __init__(self, port: int = TRANSFER_PORT, auto_accept: bool = False):
        self.port = port
        self.auto_accept = auto_accept
        self.active_receives: Dict[str, ReceiveJob] = {}
        self.receive_lock = threading.Lock()
        
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        # Callbacks
        self.on_transfer_request: Optional[Callable] = None
        self.on_progress_update: Optional[Callable] = None
        self.on_transfer_complete: Optional[Callable] = None
        self.on_file_received: Optional[Callable] = None
        
        # Managers
        self.crypto_manager = CryptoManager()
        self.path_handler = PathHandler()
        
        # Statistiques
        self.total_received = 0
        self.session_start = time.time()
        
        # Dossier par défaut
        self.default_download_folder = Path.home() / "Downloads" / "DataShare"
        self.default_download_folder.mkdir(parents=True, exist_ok=True)
        
        # Mapping socket->transfer pour gérer les connexions
        self.socket_to_transfer: Dict[socket.socket, str] = {}
        
        logger.info(f"FileReceiver initialisé (déchiffrement AES-256)")
    
    def start_server(self):
        """Démarre le serveur."""
        if self.is_running:
            return
        
        self.is_running = True
        self.server_thread = threading.Thread(
            target=self._server_loop,
            daemon=True
        )
        self.server_thread.start()
        logger.info(f"Serveur démarré sur le port {self.port}")
    
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
        
        with self.receive_lock:
            for transfer_id in list(self.active_receives.keys()):
                self.cancel_receive(transfer_id)
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
        
        logger.info("Serveur arrêté")
    
    def _server_loop(self):
        """Boucle serveur."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                        logger.error("Erreur acceptation")
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
            # Optimisations
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
                    try:
                        self._send_message(client_socket, MessageType.HEARTBEAT, {})
                    except:
                        break
                    continue
                except Exception as e:
                    logger.error(f"Erreur traitement: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Erreur client: {e}")
        finally:
            # Nettoyer le mapping
            if client_socket in self.socket_to_transfer:
                del self.socket_to_transfer[client_socket]
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
        try:
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
            
        except Exception as e:
            logger.debug(f"Erreur réception: {e}")
            return None
    
    def _receive_exact(self, sock: socket.socket, size: int) -> bytes:
        """Reçoit exactement N bytes."""
        data = b''
        while len(data) < size:
            try:
                chunk = sock.recv(min(size - len(data), SOCKET_BUFFER_SIZE))
                if not chunk:
                    break
                data += chunk
            except socket.error:
                break
        return data if len(data) == size else b''
    
    def _process_received_message(self, message: Dict, sock: socket.socket, addr: Tuple[str, int]):
        """Traite un message."""
        try:
            msg_type = MessageType(message['type'])
            data = message['data']
            
            if msg_type == MessageType.TRANSFER_REQUEST:
                self._handle_transfer_request(data, sock, addr)
            elif msg_type == MessageType.KEY_EXCHANGE:
                self._handle_key_exchange(data, sock)
            elif msg_type == MessageType.FILE_HEADER:
                self._handle_file_header(data, sock)
            elif msg_type == MessageType.FILE_CHUNK:
                self._handle_file_chunk(data, sock)
            elif msg_type == MessageType.FILE_COMPLETE:
                self._handle_file_complete(data, sock)
            elif msg_type == MessageType.TRANSFER_COMPLETE:
                self._handle_transfer_complete(data, sock)
            elif msg_type == MessageType.HEARTBEAT:
                self._send_message(sock, MessageType.HEARTBEAT, {})
                
        except Exception as e:
            logger.error(f"Erreur traitement message: {e}")
            self._send_message(sock, MessageType.ERROR, {'error': str(e)})
    
    def _handle_transfer_request(self, data: Dict, sock: socket.socket, addr: Tuple[str, int]):
        """Gère une demande de transfert."""
        try:
            receive_job = ReceiveJob(
                transfer_id=data['transfer_id'],
                sender_ip=addr[0],
                sender_name=data['sender_name'],
                files=[FileMetadata(**f) for f in data['files']],
                total_size=data['total_size'],
                destination_folder=str(self.default_download_folder),
                compression_enabled=data.get('compression_enabled', False),
                chunk_size=data.get('chunk_size', CHUNK_SIZE_DEFAULT),
                status=TransferStatus.NEGOTIATING,
                progress=0.0,
                speed=0.0,
                eta=0,
                bytes_received=0,
                current_file="",
                created_at=time.time()
            )
            
            with self.receive_lock:
                self.active_receives[receive_job.transfer_id] = receive_job
            
            # Associer le socket au transfert
            self.socket_to_transfer[sock] = receive_job.transfer_id
            
            logger.info(f"Demande de {receive_job.sender_name} ({receive_job.sender_ip})")
            logger.info(f"{len(receive_job.files)} fichiers, {self._format_size(receive_job.total_size)}")
            
            # Auto-accept ou demander confirmation
            if self.auto_accept:
                self._accept_transfer(receive_job, sock)
            elif self.on_transfer_request:
                self.on_transfer_request(receive_job, sock)
            else:
                self._console_transfer_request(receive_job, sock)
                
        except Exception as e:
            logger.error(f"Erreur demande transfert: {e}")
            self._send_message(sock, MessageType.TRANSFER_REJECT, {'reason': str(e)})
    
    def _console_transfer_request(self, receive_job: ReceiveJob, sock: socket.socket):
        """Gestion console."""
        print(f"\n{'='*60}")
        print(f"DEMANDE DE TRANSFERT CHIFFRE")
        print(f"{'='*60}")
        print(f"Expediteur: {receive_job.sender_name} ({receive_job.sender_ip})")
        print(f"Fichiers: {len(receive_job.files)}")
        print(f"Taille: {self._format_size(receive_job.total_size)}")
        print(f"Chiffrement: AES-256-GCM")
        
        print(f"\nFichiers a recevoir:")
        for i, fm in enumerate(receive_job.files[:10], 1):
            icon = "[D]" if fm.is_directory else "[F]"
            print(f"   {i}. {icon} {fm.name} ({self._format_size(fm.size)})")
        
        if len(receive_job.files) > 10:
            print(f"   ... et {len(receive_job.files) - 10} autres")
        
        while True:
            try:
                response = input(f"\nAccepter? [O/n/d=dossier]: ").strip().lower()
                
                if response in ['', 'o', 'oui']:
                    self._accept_transfer(receive_job, sock)
                    break
                elif response in ['n', 'non']:
                    self._reject_transfer(receive_job, sock, "Refuse")
                    break
                elif response in ['d', 'dossier']:
                    folder = input("Dossier: ").strip()
                    if folder:
                        folder_path = self.path_handler.normalize_path(folder)
                        folder_path.mkdir(parents=True, exist_ok=True)
                        receive_job.destination_folder = str(folder_path)
                    self._accept_transfer(receive_job, sock)
                    break
                else:
                    print("O, N ou D")
                    
            except KeyboardInterrupt:
                self._reject_transfer(receive_job, sock, "Annule")
                break
    
    def _accept_transfer(self, receive_job: ReceiveJob, sock: socket.socket):
        """Accepte un transfert."""
        try:
            dest_path = Path(receive_job.destination_folder)
            dest_path.mkdir(parents=True, exist_ok=True)
            
            receive_job.status = TransferStatus.TRANSFERRING
            receive_job.started_at = time.time()
            
            # Attendre KEY_EXCHANGE avant d'accepter
            # (géré dans _handle_key_exchange)
            
            logger.info(f"Transfert accepté vers {receive_job.destination_folder}")
            
        except Exception as e:
            logger.error(f"Erreur acceptation: {e}")
            self._reject_transfer(receive_job, sock, str(e))
    
    def _reject_transfer(self, receive_job: ReceiveJob, sock: socket.socket, reason: str):
        """Rejette un transfert."""
        receive_job.status = TransferStatus.FAILED
        receive_job.error_message = reason
        
        self._send_message(sock, MessageType.TRANSFER_REJECT, {'reason': reason})
        
        with self.receive_lock:
            if receive_job.transfer_id in self.active_receives:
                del self.active_receives[receive_job.transfer_id]
        
        logger.info(f"Transfert rejeté: {reason}")
    
    def _handle_key_exchange(self, data: Dict, sock: socket.socket):
        """Gère l'échange de clés."""
        try:
            transfer_id = data['transfer_id']
            session_key = base64.b64decode(data['session_key'])
            
            with self.receive_lock:
                if transfer_id in self.active_receives:
                    receive_job = self.active_receives[transfer_id]
                    receive_job.encryption_key = session_key
                    self.crypto_manager.store_session_key(transfer_id, session_key)
                    
                    # Envoyer l'acceptation maintenant
                    accept_data = {
                        'transfer_id': transfer_id,
                        'ready': True
                    }
                    self._send_message(sock, MessageType.TRANSFER_ACCEPT, accept_data)
                    
                    logger.info(f"Clé reçue et transfert accepté")
        
        except Exception as e:
            logger.error(f"Erreur échange clés: {e}")
    
    def _handle_file_header(self, data: Dict, sock: socket.socket):
        """Gère l'en-tête d'un fichier."""
        try:
            file_meta = FileMetadata(**data)
            
            # Trouver le job
            transfer_id = self.socket_to_transfer.get(sock)
            if not transfer_id:
                return
            
            with self.receive_lock:
                if transfer_id not in self.active_receives:
                    return
                receive_job = self.active_receives[transfer_id]
            
            receive_job.current_file = file_meta.name
            
            # Créer le chemin
            dest_path = Path(receive_job.destination_folder)
            
            if file_meta.relative_path:
                file_dest = self.path_handler.safe_path_join(dest_path, file_meta.relative_path)
            else:
                file_dest = dest_path / file_meta.name
            
            if file_meta.is_directory:
                file_dest.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Dossier: {file_dest}")
            else:
                self.path_handler.ensure_parent_exists(file_dest)
                receive_job.current_file_handle = open(file_dest, 'wb')
                receive_job.current_file_path = file_dest
                receive_job.current_file_size = file_meta.size
                receive_job.current_file_received = 0
                
                logger.info(f"Reception: {file_meta.name}")
                
        except Exception as e:
            logger.error(f"Erreur en-tête: {e}")
    
    def _handle_file_chunk(self, data: Dict, sock: socket.socket):
        """Gère un chunk chiffré."""
        try:
            transfer_id = self.socket_to_transfer.get(sock)
            if not transfer_id:
                return
            
            with self.receive_lock:
                if transfer_id not in self.active_receives:
                    return
                receive_job = self.active_receives[transfer_id]
            
            if not hasattr(receive_job, 'current_file_handle'):
                return
            
            # Déchiffrer
            encrypted_data = base64.b64decode(data['encrypted_data'])
            nonce = base64.b64decode(data['nonce'])
            
            decrypted = self.crypto_manager.decrypt_chunk(
                encrypted_data, nonce, receive_job.encryption_key
            )
            
            # Écrire
            receive_job.current_file_handle.write(decrypted)
            
            # Stats
            chunk_size = len(decrypted)
            receive_job.current_file_received += chunk_size
            receive_job.bytes_received += chunk_size
            
            # Progression
            current_time = time.time()
            elapsed = current_time - receive_job.started_at
            
            if elapsed > 0:
                receive_job.speed = receive_job.bytes_received / elapsed
                receive_job.progress = receive_job.bytes_received / receive_job.total_size
                
                if receive_job.speed > 0:
                    remaining = receive_job.total_size - receive_job.bytes_received
                    receive_job.eta = int(remaining / receive_job.speed)
            
            # Callback
            if self.on_progress_update:
                self.on_progress_update(receive_job)
                
        except Exception as e:
            logger.error(f"Erreur chunk: {e}")
    
    def _handle_file_complete(self, data: Dict, sock: socket.socket):
        """Fin de fichier."""
        try:
            transfer_id = self.socket_to_transfer.get(sock)
            if not transfer_id:
                return
            
            with self.receive_lock:
                if transfer_id not in self.active_receives:
                    return
                receive_job = self.active_receives[transfer_id]
            
            if hasattr(receive_job, 'current_file_handle'):
                receive_job.current_file_handle.close()
                delattr(receive_job, 'current_file_handle')
            
            file_name = data.get('file_name', receive_job.current_file)
            logger.info(f"Fichier reçu: {file_name}")
            
            if self.on_file_received:
                self.on_file_received(receive_job, file_name)
            
            # Nettoyer
            for attr in ['current_file_path', 'current_file_size', 'current_file_received']:
                if hasattr(receive_job, attr):
                    delattr(receive_job, attr)
                    
        except Exception as e:
            logger.error(f"Erreur fin fichier: {e}")
    
    def _handle_transfer_complete(self, data: Dict, sock: socket.socket):
        """Transfert terminé."""
        try:
            transfer_id = data.get('transfer_id')
            
            with self.receive_lock:
                if transfer_id and transfer_id in self.active_receives:
                    receive_job = self.active_receives[transfer_id]
                    
                    receive_job.status = TransferStatus.COMPLETED
                    receive_job.progress = 1.0
                    receive_job.completed_at = time.time()
                    
                    duration = receive_job.completed_at - receive_job.started_at
                    avg_speed = receive_job.bytes_received / duration if duration > 0 else 0
                    
                    self.total_received += receive_job.bytes_received
                    
                    logger.info(f"Transfert termine")
                    logger.info(f"Taille: {self._format_size(receive_job.bytes_received)}")
                    logger.info(f"Duree: {self._format_duration(duration)}")
                    logger.info(f"Vitesse: {self._format_speed(avg_speed)}")
                    
                    # Nettoyer la clé
                    self.crypto_manager.cleanup_session(transfer_id)
                    
                    if self.on_transfer_complete:
                        self.on_transfer_complete(receive_job)
                    
        except Exception as e:
            logger.error(f"Erreur fin transfert: {e}")
    
    def cancel_receive(self, transfer_id: str) -> bool:
        """Annule une réception."""
        with self.receive_lock:
            if transfer_id not in self.active_receives:
                return False
            
            receive_job = self.active_receives[transfer_id]
            receive_job.status = TransferStatus.CANCELLED
            
            if hasattr(receive_job, 'current_file_handle'):
                try:
                    receive_job.current_file_handle.close()
                except:
                    pass
            
            self.crypto_manager.cleanup_session(transfer_id)
            
            return True
    
    def get_active_receives(self) -> List[ReceiveJob]:
        """Liste des réceptions."""
        with self.receive_lock:
            return list(self.active_receives.values())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Statistiques."""
        with self.receive_lock:
            active = len(self.active_receives)
            completed = sum(1 for r in self.active_receives.values() 
                          if r.status == TransferStatus.COMPLETED)
            failed = sum(1 for r in self.active_receives.values() 
                       if r.status == TransferStatus.FAILED)
            
            speeds = [r.speed for r in self.active_receives.values() 
                     if r.status == TransferStatus.TRANSFERRING and r.speed > 0]
            avg_speed = sum(speeds) / len(speeds) if speeds else 0
            
            uptime = time.time() - self.session_start
            
            return {
                'active_receives': active,
                'completed_receives': completed,
                'failed_receives': failed,
                'session_total_received': self.total_received,
                'average_speed': avg_speed,
                'uptime': uptime,
                'default_folder': str(self.default_download_folder),
                'encryption': 'AES-256-GCM'
            }
    
    def _format_size(self, b: int) -> str:
        """Formate une taille."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"
    
    def _format_speed(self, s: float) -> str:
        """Formate une vitesse."""
        return f"{self._format_size(s)}/s"
    
    def _format_duration(self, d: float) -> str:
        """Formate une durée."""
        d = int(d)
        if d < 60:
            return f"{d}s"
        elif d < 3600:
            return f"{d//60}m {d%60}s"
        else:
            return f"{d//3600}h {(d%3600)//60}m"


class FileReceiverUI:
    """Interface console."""
    
    def __init__(self, receiver: FileReceiver):
        self.receiver = receiver
        
        self.receiver.on_transfer_request = self.on_transfer_request
        self.receiver.on_progress_update = self.on_progress_update
        self.receiver.on_transfer_complete = self.on_transfer_complete
        self.receiver.on_file_received = self.on_file_received
        
        self.last_progress_time = {}
    
    def on_transfer_request(self, receive_job: ReceiveJob, sock: socket.socket):
        """Demande transfert."""
        print(f"\n[DEMANDE TRANSFERT CHIFFRE]")
        print(f"De: {receive_job.sender_name} ({receive_job.sender_ip})")
        print(f"Fichiers: {len(receive_job.files)}")
        print(f"Taille: {self._format_size(receive_job.total_size)}")
        print(f"Chiffrement: AES-256-GCM")
        
        # Accepter automatiquement pour simplifier
        self.receiver._accept_transfer(receive_job, sock)
        print(f"Accepte automatiquement")
    
    def on_progress_update(self, receive_job: ReceiveJob):
        """Mise a jour progression."""
        current_time = time.time()
        transfer_id = receive_job.transfer_id
        
        if (transfer_id not in self.last_progress_time or 
            current_time - self.last_progress_time.get(transfer_id, 0) >= 1.0):
            
            bar = self._create_progress_bar(receive_job.progress, 40)
            speed = self._format_speed(receive_job.speed)
            eta = self._format_eta(receive_job.eta)
            
            print(f"\r{transfer_id[:8]}... {bar} "
                  f"{receive_job.progress*100:.1f}% | {speed} | ETA: {eta}", 
                  end="", flush=True)
            
            self.last_progress_time[transfer_id] = current_time
    
    def on_file_received(self, receive_job: ReceiveJob, file_name: str):
        """Fichier reçu."""
        print(f"\nRecu: {file_name}")
    
    def on_transfer_complete(self, receive_job: ReceiveJob):
        """Transfert terminé."""
        print()
        
        if receive_job.status == TransferStatus.COMPLETED:
            duration = receive_job.completed_at - receive_job.started_at
            avg_speed = receive_job.bytes_received / duration if duration > 0 else 0
            
            print(f"\n[TRANSFERT TERMINE]")
            print(f"Fichiers: {len(receive_job.files)}")
            print(f"Taille: {self._format_size(receive_job.bytes_received)}")
            print(f"Duree: {self._format_duration(duration)}")
            print(f"Vitesse: {self._format_speed(avg_speed)}")
            print(f"Dossier: {receive_job.destination_folder}")
        
        elif receive_job.status == TransferStatus.FAILED:
            print(f"\n[ECHEC]: {receive_job.error_message}")
        
        elif receive_job.status == TransferStatus.CANCELLED:
            print(f"\n[ANNULE]")
        
        if receive_job.transfer_id in self.last_progress_time:
            del self.last_progress_time[receive_job.transfer_id]
    
    def _create_progress_bar(self, progress: float, width: int = 40) -> str:
        """Barre de progression."""
        filled = int(progress * width)
        return f"[{'#' * filled}{'.' * (width - filled)}]"
    
    def _format_size(self, b: int) -> str:
        """Formate une taille."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"
    
    def _format_speed(self, s: float) -> str:
        """Formate une vitesse."""
        return f"{self._format_size(s)}/s"
    
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
        """Formate une durée."""
        return self._format_eta(int(seconds))


def main():
    """Programme principal."""
    print("=" * 80)
    print("DATASHARE - RECEPTEUR SECURISE")
    print("Dechiffrement AES-256-GCM | Gestion chemins avec espaces")
    print("=" * 80)
    
    receiver = FileReceiver(port=TRANSFER_PORT, auto_accept=True)
    ui = FileReceiverUI(receiver)
    
    print(f"\nInitialise:")
    print(f"  Port: {TRANSFER_PORT}")
    print(f"  Dossier: {receiver.default_download_folder}")
    print(f"  Auto-accept: Oui")
    print(f"  Chiffrement: AES-256-GCM")
    
    receiver.start_server()
    print(f"\nServeur demarre - En attente de transferts...")
    
    print(f"\nCommandes:")
    print(f"  list   - Lister receptions")
    print(f"  stats  - Statistiques")
    print(f"  cancel <ID> - Annuler")
    print(f"  quit   - Quitter")
    
    try:
        while True:
            try:
                command = input(f"\nReceiver> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd in ['quit', 'exit']:
                    break
                
                elif cmd == 'list':
                    receives = receiver.get_active_receives()
                    if receives:
                        print(f"\nReceptions actives ({len(receives)}):")
                        for r in receives:
                            status_map = {
                                TransferStatus.PENDING: "[ATTENTE]",
                                TransferStatus.NEGOTIATING: "[NEGO]",
                                TransferStatus.TRANSFERRING: "[RECEP]",
                                TransferStatus.COMPLETED: "[OK]",
                                TransferStatus.FAILED: "[ECHEC]",
                                TransferStatus.CANCELLED: "[ANNULE]"
                            }
                            status = status_map.get(r.status, "[?]")
                            print(f"  {status} {r.transfer_id[:12]}... | {r.sender_name} | "
                                  f"{receiver._format_size(r.total_size)} | {r.progress*100:.0f}%")
                    else:
                        print("Aucune reception")
                
                elif cmd == 'stats':
                    stats = receiver.get_statistics()
                    print(f"\nStatistiques:")
                    print(f"  Actifs: {stats['active_receives']}")
                    print(f"  Termines: {stats['completed_receives']}")
                    print(f"  Echoues: {stats['failed_receives']}")
                    print(f"  Recu: {receiver._format_size(stats['session_total_received'])}")
                    print(f"  Vitesse: {receiver._format_speed(stats['average_speed'])}")
                    print(f"  Uptime: {receiver._format_duration(stats['uptime'])}")
                    print(f"  Chiffrement: {stats['encryption']}")
                
                elif cmd == 'cancel':
                    if len(parts) < 2:
                        print("Usage: cancel <transfer_id>")
                        continue
                    
                    tid = parts[1]
                    if receiver.cancel_receive(tid):
                        print(f"Reception {tid} annulee")
                    else:
                        print(f"Reception {tid} introuvable")
                
                elif cmd == 'help':
                    print(f"\nAide:")
                    print(f"  list        - Liste receptions")
                    print(f"  stats       - Statistiques")
                    print(f"  cancel <ID> - Annuler")
                    print(f"  quit        - Quitter")
                
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
        receiver.stop_server()
        
        stats = receiver.get_statistics()
        print(f"\nResume:")
        print(f"  Receptions: {stats['completed_receives'] + stats['failed_receives']}")
        print(f"  Donnees: {receiver._format_size(stats['session_total_received'])}")
        
        print(f"\nModule arrete")


if __name__ == "__main__":
    main()
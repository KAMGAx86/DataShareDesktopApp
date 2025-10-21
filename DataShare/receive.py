"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  MODULE DE RÉCEPTION AMÉLIORÉ v6.0                           ║
║                     DataShare - Édition Optimisée                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

AMÉLIORATIONS APPORTÉES:
━━━━━━━━━━━━━━━━━━━━━━━━
✅ Protocole binaire synchronisé avec send.py
✅ Buffers TCP 64MB (identique émetteur)
✅ ChaCha20-Poly1305 déchiffrement
✅ Barre de progression temps réel côté réception
✅ Pipeline de déchiffrement parallèle (8 workers)
✅ Timeouts adaptés (300s)
✅ Gestion robuste des erreurs réseau
✅ Écriture optimisée avec mmap pour gros fichiers
✅ Compatible avec tous les modes (turbo/chiffré/compressé)

SYNCHRONISATION PARFAITE AVEC SEND.PY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Même protocole binaire
- Même format de chunks
- Même handshake
- Même gestion des modes

Auteur: DataShare Team
Version: 6.0
"""

import socket
import threading
import os
import time
import struct
import logging
import mmap
from typing import Dict, List, Tuple, Optional, Callable, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import IntEnum
from queue import Queue, Empty
import sys
from collections import deque

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS CONDITIONNELS
# ══════════════════════════════════════════════════════════════════════════════

try:
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False
    logging.warning("lz4 non disponible, décompression désactivée")

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logging.warning("cryptography non disponible, déchiffrement désactivé")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION (IDENTIQUE À SEND.PY)
# ══════════════════════════════════════════════════════════════════════════════

TRANSFER_PORT = 32001

# Chunks (identiques send.py)
CHUNK_SIZE_TURBO = 32 * 1024 * 1024
CHUNK_SIZE_DEFAULT = 16 * 1024 * 1024
CHUNK_SIZE_COMPRESSED = 8 * 1024 * 1024

# Buffers TCP massifs
SOCKET_BUFFER_SIZE = 64 * 1024 * 1024

# Timeouts
CONNECTION_TIMEOUT = 300
HEARTBEAT_INTERVAL = 30

# Crypto
CHACHA20_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12

# Pipeline
MAX_CRYPTO_WORKERS = min(8, (os.cpu_count() or 4))
PIPELINE_DEPTH = 16

# Write buffer
WRITE_BUFFER_SIZE = 64 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# ÉNUMÉRATIONS (IDENTIQUES À SEND.PY)
# ══════════════════════════════════════════════════════════════════════════════

class MessageType(IntEnum):
    """Types de messages"""
    FILE_HEADER = 0x05
    FILE_CHUNK = 0x06
    FILE_COMPLETE = 0x07
    TRANSFER_COMPLETE = 0x08
    HEARTBEAT = 0x09
    ERROR = 0x0A


class TransferMode(IntEnum):
    """Modes de transfert"""
    TURBO = 0x01
    ENCRYPTED = 0x02
    COMPRESSED = 0x03


class TransferStatus(IntEnum):
    """États"""
    PENDING = 0
    NEGOTIATING = 1
    TRANSFERRING = 2
    COMPLETED = 3
    FAILED = 4
    CANCELLED = 5


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURES DE DONNÉES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FileMetadata:
    """Métadonnées fichier"""
    name: str
    size: int
    relative_path: str
    modified_time: float


@dataclass
class ReceiveJob:
    """Job de réception"""
    transfer_id: str
    sender_ip: str
    sender_name: str
    files: List[FileMetadata]
    total_size: int
    destination_folder: str
    mode: TransferMode
    status: TransferStatus
    
    # Progression
    progress: float = 0.0
    speed: float = 0.0
    eta: int = 0
    bytes_received: int = 0
    current_file: str = ""
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    
    # Crypto
    session_key: Optional[bytes] = None


@dataclass
class ReceiveStats:
    """Statistiques internes"""
    bytes_received: int = 0
    chunks_received: int = 0
    start_time: float = 0
    speed_samples: deque = field(default_factory=lambda: deque(maxlen=20))


# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOLE BINAIRE (IDENTIQUE À SEND.PY)
# ══════════════════════════════════════════════════════════════════════════════

class BinaryProtocol:
    """Protocole binaire"""
    
    @staticmethod
    def unpack_header(data: bytes) -> Tuple[MessageType, int]:
        """Décode header"""
        msg_type, size = struct.unpack('!BI', data[:5])
        return MessageType(msg_type), size
    
    @staticmethod
    def pack_header(msg_type: MessageType, payload_size: int) -> bytes:
        """Encode header"""
        return struct.pack('!BI', msg_type, payload_size)
    
    @staticmethod
    def unpack_file_header(data: bytes) -> FileMetadata:
        """Décode métadonnées fichier"""
        offset = 0
        
        # Nom
        name_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        name = data[offset:offset+name_len].decode('utf-8')
        offset += name_len
        
        # Chemin
        path_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        rel_path = data[offset:offset+path_len].decode('utf-8')
        offset += path_len
        
        # Taille et date
        size, mtime = struct.unpack('!Qd', data[offset:offset+16])
        
        return FileMetadata(
            name=name,
            size=size,
            relative_path=rel_path,
            modified_time=mtime
        )
    
    @staticmethod
    def unpack_chunk(data: bytes) -> Tuple[int, int, bytes, bool]:
        """Décode chunk"""
        file_id, offset, flags, data_len = struct.unpack('!QQBI', data[:21])
        chunk_data = data[21:21+data_len]
        compressed = bool(flags & 0x02)
        return file_id, offset, chunk_data, compressed


# ══════════════════════════════════════════════════════════════════════════════
# OPTIMISEUR TCP (IDENTIQUE À SEND.PY)
# ══════════════════════════════════════════════════════════════════════════════

class TCPOptimizer:
    """Optimisations TCP"""
    
    @staticmethod
    def optimize_socket(sock: socket.socket, is_server: bool = False):
        """Applique optimisations TCP"""
        try:
            # Buffers 64MB
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        except OSError as e:
            logger.warning(f"Buffers 64MB impossibles: {e}")
        
        # TCP_NODELAY
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        if is_server:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Optimisations Linux
        if sys.platform.startswith('linux'):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, 12, 1)  # TCP_QUICKACK
                sock.setsockopt(socket.IPPROTO_TCP, 3, 0)   # TCP_CORK off
                logger.debug("✓ Optimisations Linux activées")
            except:
                pass
        
        # Optimisations Windows
        elif sys.platform == 'win32':
            try:
                SIO_LOOPBACK_FAST_PATH = 0x98000010
                sock.ioctl(SIO_LOOPBACK_FAST_PATH, True)
                logger.debug("✓ Optimisations Windows activées")
            except:
                pass
        
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.settimeout(CONNECTION_TIMEOUT)


# ══════════════════════════════════════════════════════════════════════════════
# CHIFFREMENT
# ══════════════════════════════════════════════════════════════════════════════

class StreamCipher:
    """ChaCha20-Poly1305"""
    
    def __init__(self, key: bytes):
        if not HAS_CRYPTO:
            raise ImportError("cryptography manquant")
        self.cipher = ChaCha20Poly1305(key)
    
    def decrypt_chunk(self, data: bytes, nonce: bytes) -> bytes:
        """Déchiffre chunk"""
        return self.cipher.decrypt(nonce, data, None)


# ══════════════════════════════════════════════════════════════════════════════
# COMPRESSION
# ══════════════════════════════════════════════════════════════════════════════

class CompressionEngine:
    """Décompression LZ4"""
    
    @staticmethod
    def decompress(data: bytes) -> bytes:
        """Décompresse LZ4"""
        if not HAS_LZ4:
            return data
        return lz4.frame.decompress(data)


# ══════════════════════════════════════════════════════════════════════════════
# BUFFER D'ÉCRITURE OPTIMISÉ
# ══════════════════════════════════════════════════════════════════════════════

class WriteBuffer:
    """Buffer d'écriture avec mmap pour gros fichiers"""
    
    def __init__(self, file_path: Path, file_size: int):
        self.file_path = file_path
        self.file_size = file_size
        self.file_handle = None
        self.mmap_handle = None
        self.use_mmap = file_size > 100 * 1024 * 1024  # >100MB
        
        # Créer fichier
        self.file_handle = open(file_path, 'wb')
        
        if self.use_mmap and file_size > 0:
            try:
                # Pré-allouer
                self.file_handle.seek(file_size - 1)
                self.file_handle.write(b'\x00')
                self.file_handle.flush()
                
                # Créer mmap
                self.mmap_handle = mmap.mmap(
                    self.file_handle.fileno(),
                    file_size,
                    access=mmap.ACCESS_WRITE
                )
                logger.debug(f"✓ mmap activé pour {file_path.name}")
            except Exception as e:
                logger.warning(f"mmap échoué: {e}, mode standard")
                self.use_mmap = False
                self.file_handle.seek(0)
                self.file_handle.truncate()
    
    def write_at(self, offset: int, data: bytes):
        """Écrit à un offset"""
        if self.mmap_handle:
            self.mmap_handle[offset:offset+len(data)] = data
        else:
            self.file_handle.seek(offset)
            self.file_handle.write(data)
    
    def flush(self):
        """Flush"""
        if self.mmap_handle:
            self.mmap_handle.flush()
        if self.file_handle:
            self.file_handle.flush()
            try:
                os.fsync(self.file_handle.fileno())
            except:
                pass
    
    def close(self):
        """Ferme"""
        self.flush()
        if self.mmap_handle:
            self.mmap_handle.close()
        if self.file_handle:
            self.file_handle.close()


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE DE DÉCHIFFREMENT
# ══════════════════════════════════════════════════════════════════════════════

class DecryptionPipeline:
    """Pipeline de déchiffrement parallèle"""
    
    def __init__(self, cipher: Optional[StreamCipher], num_workers: int = MAX_CRYPTO_WORKERS):
        self.cipher = cipher
        self.num_workers = num_workers if cipher else 1
        self.input_queue = Queue(maxsize=PIPELINE_DEPTH)
        self.output_queue = Queue(maxsize=PIPELINE_DEPTH * 2)
        self.workers = []
        self.running = False
        self.error_event = threading.Event()
    
    def start(self):
        """Démarre workers"""
        self.running = True
        self.error_event.clear()
        
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name=f"Decrypt-{i}"
            )
            worker.start()
            self.workers.append(worker)
        
        logger.debug(f"✓ Pipeline déchiffrement: {self.num_workers} workers")
    
    def stop(self):
        """Arrête workers"""
        self.running = False
        
        for _ in range(self.num_workers):
            try:
                self.input_queue.put(None, timeout=0.1)
            except:
                pass
        
        for worker in self.workers:
            worker.join(timeout=2)
    
    def _worker_loop(self):
        """Boucle worker"""
        while self.running and not self.error_event.is_set():
            try:
                item = self.input_queue.get(timeout=1.0)
                
                if item is None:
                    break
                
                offset, encrypted_data, compressed = item
                
                # Déchiffrement
                if self.cipher:
                    nonce = encrypted_data[:CHACHA20_NONCE_SIZE]
                    ciphertext = encrypted_data[CHACHA20_NONCE_SIZE:]
                    
                    try:
                        decrypted = self.cipher.decrypt_chunk(ciphertext, nonce)
                    except Exception as e:
                        logger.error(f"Erreur déchiffrement: {e}")
                        self.error_event.set()
                        break
                else:
                    decrypted = encrypted_data
                
                # Décompression
                if compressed and HAS_LZ4:
                    try:
                        decrypted = CompressionEngine.decompress(decrypted)
                    except Exception as e:
                        logger.error(f"Erreur décompression: {e}")
                        self.error_event.set()
                        break
                
                self.output_queue.put((offset, decrypted))
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Pipeline error: {e}")
                self.error_event.set()
                break
    
    def process(self, offset: int, data: bytes, compressed: bool):
        """Ajoute chunk à traiter"""
        if not self.error_event.is_set():
            try:
                self.input_queue.put((offset, data, compressed), timeout=5.0)
            except Exception as e:
                logger.error(f"Erreur ajout chunk: {e}")
    
    def get_result(self, timeout: float = 5.0) -> Optional[Tuple[int, bytes]]:
        """Récupère résultat"""
        try:
            return self.output_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def has_error(self) -> bool:
        """Vérifie erreur"""
        return self.error_event.is_set()


# ══════════════════════════════════════════════════════════════════════════════
# GESTIONNAIRE DE RÉCEPTION
# ══════════════════════════════════════════════════════════════════════════════

class FileReceiver:
    """
    Gestionnaire de réception ULTRA-OPTIMISÉ.
    Synchronisé parfaitement avec FileTransferManager (send.py).
    """
    
    def __init__(self, port: int = TRANSFER_PORT, auto_accept: bool = True):
        self.port = port
        self.auto_accept = auto_accept
        
        self.server_socket: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        self.active_receives: Dict[str, ReceiveJob] = {}
        self.receive_lock = threading.Lock()
        
        self.total_received = 0
        self.session_start = time.time()
        
        self.default_download_folder = Path.home() / "Downloads" / "DataShare"
        self.default_download_folder.mkdir(parents=True, exist_ok=True)
        
        # Callbacks
        self.on_transfer_request: Optional[Callable] = None
        self.on_progress_update: Optional[Callable] = None
        self.on_transfer_complete: Optional[Callable] = None
        self.on_file_received: Optional[Callable] = None
        
        logger.info(f"FileReceiver initialisé (port {port})")
        logger.info(f"  Buffers TCP: {SOCKET_BUFFER_SIZE // 1024 // 1024}MB")
        logger.info(f"  Workers déchiffrement: {MAX_CRYPTO_WORKERS}")
        logger.info(f"  Dossier: {self.default_download_folder}")
    
    def start_server(self):
        """Démarre serveur"""
        if self.is_running:
            return
        
        self.is_running = True
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        logger.info(f"✅ Serveur démarré sur 0.0.0.0:{self.port}")
    
    def stop_server(self):
        """Arrête serveur"""
        if not self.is_running:
            return
        
        logger.info("Arrêt du serveur...")
        self.is_running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.server_thread:
            self.server_thread.join(timeout=5)
        
        logger.info("✓ Serveur arrêté")
    
    def _server_loop(self):
        """Boucle serveur"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            TCPOptimizer.optimize_socket(self.server_socket, is_server=True)
            
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            logger.info(f"👂 En écoute...")
            
            while self.is_running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()
                    
                    logger.info(f"✓ Connexion de {client_address[0]}")
                    
                    # Optimiser socket client
                    TCPOptimizer.optimize_socket(client_socket, is_server=False)
                    
                    # Thread de réception
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_running:
                        logger.error(f"Erreur accept: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Erreur serveur: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_client(self, sock: socket.socket, addr: Tuple[str, int]):
        """Gère connexion client"""
        transfer_id = None
        
        try:
            # Recevoir handshake
            transfer_id, mode, session_key = self._receive_handshake(sock)
            
            mode_str = {
                TransferMode.TURBO: "TURBO",
                TransferMode.ENCRYPTED: "CHIFFRÉ",
                TransferMode.COMPRESSED: "COMPRESSÉ"
            }.get(mode, "INCONNU")
            
            logger.info(f"═══════════════════════════════════════════════════")
            logger.info(f"NOUVEAU TRANSFERT")
            logger.info(f"═══════════════════════════════════════════════════")
            logger.info(f"  ID: {transfer_id}")
            logger.info(f"  Mode: {mode_str}")
            logger.info(f"  De: {addr[0]}")
            logger.info(f"═══════════════════════════════════════════════════\n")
            
            # Créer job
            receive_job = ReceiveJob(
                transfer_id=transfer_id,
                sender_ip=addr[0],
                sender_name="Remote",
                files=[],
                total_size=0,
                destination_folder=str(self.default_download_folder),
                mode=mode,
                status=TransferStatus.TRANSFERRING,
                session_key=session_key,
                started_at=time.time()
            )
            
            with self.receive_lock:
                self.active_receives[transfer_id] = receive_job
            
            # Créer cipher si besoin
            cipher = None
            if mode != TransferMode.TURBO and session_key:
                cipher = StreamCipher(session_key)
            
            # Recevoir fichiers
            stats = ReceiveStats(start_time=time.time())
            self._receive_transfer(sock, receive_job, cipher, stats)
            
            # Fin
            receive_job.status = TransferStatus.COMPLETED
            receive_job.completed_at = time.time()
            
            duration = receive_job.completed_at - receive_job.started_at
            avg_speed = stats.bytes_received / duration if duration > 0 else 0
            
            self.total_received += stats.bytes_received
            
            logger.info(f"\n═══════════════════════════════════════════════════")
            logger.info(f"✅ TRANSFERT TERMINÉ")
            logger.info(f"═══════════════════════════════════════════════════")
            logger.info(f"  Taille: {self._format_size(stats.bytes_received)}")
            logger.info(f"  Durée: {self._format_duration(duration)}")
            logger.info(f"  Vitesse: {self._format_speed(avg_speed)}")
            logger.info(f"  Chunks: {stats.chunks_received}")
            
            if mode == TransferMode.TURBO:
                efficiency = (avg_speed / (125 * 1024 * 1024)) * 100
                logger.info(f"  Efficacité Gigabit: {efficiency:.1f}%")
            
            logger.info(f"═══════════════════════════════════════════════════\n")
            
            if self.on_transfer_complete:
                self.on_transfer_complete(receive_job)
        
        except Exception as e:
            logger.error(f"❌ ERREUR: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            try:
                sock.close()
            except:
                pass
            
            if transfer_id:
                with self.receive_lock:
                    if transfer_id in self.active_receives:
                        del self.active_receives[transfer_id]
    
    def _receive_handshake(self, sock: socket.socket) -> Tuple[str, TransferMode, Optional[bytes]]:
        """Reçoit handshake binaire"""
        
        # Format: [magic:4][version:1][mode:1][key_len:1][key][id:16]
        handshake_data = self._recv_exact(sock, 7)
        
        magic, version, mode, key_len = struct.unpack('!4sBBB', handshake_data)
        
        if magic != b'DSHR':
            raise ValueError(f"Magic number invalide: {magic}")
        
        # Clé si présente
        session_key = None
        if key_len > 0:
            session_key = self._recv_exact(sock, key_len)
        
        # Transfer ID
        transfer_id_bytes = self._recv_exact(sock, 16)
        transfer_id = transfer_id_bytes.rstrip(b'\x00').decode('utf-8')
        
        return transfer_id, TransferMode(mode), session_key
    
    def _receive_transfer(self, sock: socket.socket, receive_job: ReceiveJob,
                          cipher: Optional[StreamCipher], stats: ReceiveStats):
        """Reçoit transfert complet"""
        
        logger.info(f"⚡ RÉCEPTION EN COURS...\n")
        
        # Pipeline
        pipeline = DecryptionPipeline(cipher)
        pipeline.start()
        
        current_file: Optional[WriteBuffer] = None
        current_file_meta: Optional[FileMetadata] = None
        last_update = time.time()
        expected_offset = 0
        chunks_in_pipeline = 0
        
        try:
            while True:
                # Recevoir message
                msg_type, payload = self._receive_binary_message(sock)
                
                if msg_type == MessageType.FILE_HEADER:
                    # Attendre fin pipeline
                    while chunks_in_pipeline > 0:
                        result = pipeline.get_result(timeout=5.0)
                        if result:
                            dec_offset, dec_data = result
                            if current_file:
                                current_file.write_at(dec_offset, dec_data)
                            chunks_in_pipeline -= 1
                    
                    # Fermer fichier précédent
                    if current_file:
                        current_file.flush()
                        current_file.close()
                        
                        if self.on_file_received and current_file_meta:
                            self.on_file_received(receive_job, current_file_meta.name)
                        
                        logger.info(f"     ✓ Fichier terminé")
                    
                    # Nouveau fichier
                    current_file_meta = BinaryProtocol.unpack_file_header(payload)
                    receive_job.current_file = current_file_meta.name
                    receive_job.files.append(current_file_meta)
                    receive_job.total_size += current_file_meta.size
                    
                    # Créer chemin
                    if current_file_meta.relative_path:
                        dest_path = self.default_download_folder / current_file_meta.relative_path
                    else:
                        dest_path = self.default_download_folder / current_file_meta.name
                    
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Buffer d'écriture
                    current_file = WriteBuffer(dest_path, current_file_meta.size)
                    expected_offset = 0
                    
                    logger.info(f"  📥 {current_file_meta.name} ({self._format_size(current_file_meta.size)})")
                
                elif msg_type == MessageType.FILE_CHUNK:
                    if not current_file:
                        continue
                    
                    # Décoder chunk
                    file_id, offset, chunk_data, compressed = BinaryProtocol.unpack_chunk(payload)
                    
                    # Envoyer au pipeline
                    pipeline.process(offset, chunk_data, compressed)
                    chunks_in_pipeline += 1
                    
                    # Récupérer résultats
                    while True:
                        result = pipeline.get_result(timeout=0.001)
                        if result is None:
                            break
                        
                        dec_offset, dec_data = result
                        chunks_in_pipeline -= 1
                        
                        # Écrire
                        current_file.write_at(dec_offset, dec_data)
                        expected_offset = dec_offset + len(dec_data)
                        
                        # Stats
                        stats.bytes_received += len(dec_data)
                        stats.chunks_received += 1
                        receive_job.bytes_received = stats.bytes_received
                        
                        # Progression
                        if receive_job.total_size > 0:
                            receive_job.progress = (stats.bytes_received / receive_job.total_size) * 100
                        
                        current_time = time.time()
                        elapsed = current_time - stats.start_time
                        if elapsed > 0:
                            receive_job.speed = stats.bytes_received / elapsed
                            remaining = receive_job.total_size - stats.bytes_received
                            receive_job.eta = int(remaining / receive_job.speed) if receive_job.speed > 0 else 0
                        
                        # Afficher progression
                        if current_time - last_update >= 0.5:
                            self._print_progress(receive_job, current_file_meta)
                            last_update = current_time
                            
                            if self.on_progress_update:
                                self.on_progress_update(receive_job)
                
                elif msg_type == MessageType.FILE_COMPLETE:
                    print()  # Nouvelle ligne après barre
                    # Attendre fin chunks
                    while chunks_in_pipeline > 0:
                        result = pipeline.get_result(timeout=5.0)
                        if result:
                            dec_offset, dec_data = result
                            if current_file:
                                current_file.write_at(dec_offset, dec_data)
                                stats.bytes_received += len(dec_data)
                                stats.chunks_received += 1
                            chunks_in_pipeline -= 1
                
                elif msg_type == MessageType.TRANSFER_COMPLETE:
                    # Attendre fin pipeline
                    while chunks_in_pipeline > 0:
                        result = pipeline.get_result(timeout=5.0)
                        if result:
                            dec_offset, dec_data = result
                            if current_file:
                                current_file.write_at(dec_offset, dec_data)
                                stats.bytes_received += len(dec_data)
                                stats.chunks_received += 1
                            chunks_in_pipeline -= 1
                    
                    # Fermer dernier fichier
                    if current_file:
                        current_file.flush()
                        current_file.close()
                        
                        if self.on_file_received and current_file_meta:
                            self.on_file_received(receive_job, current_file_meta.name)
                    
                    break
                
                elif msg_type == MessageType.HEARTBEAT:
                    # Répondre
                    self._send_binary_message(sock, MessageType.HEARTBEAT, b'')
                
                elif msg_type == MessageType.ERROR:
                    error_msg = payload.decode('utf-8', errors='ignore')
                    logger.error(f"Erreur émetteur: {error_msg}")
                    break
                
                # Vérifier erreurs pipeline
                if pipeline.has_error():
                    raise Exception("Erreur pipeline déchiffrement")
        
        finally:
            pipeline.stop()
            if current_file:
                try:
                    current_file.close()
                except:
                    pass
    
    def _print_progress(self, receive_job: ReceiveJob, current_file: FileMetadata):
        """Affiche barre de progression"""
        bar_width = 40
        filled = int(bar_width * receive_job.progress / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        print(f"\r     │{bar}│ {receive_job.progress:5.1f}% │ "
              f"{self._format_speed(receive_job.speed)} │ "
              f"ETA: {self._format_duration(receive_job.eta)}", 
              end='', flush=True)
    
    def _receive_binary_message(self, sock: socket.socket) -> Tuple[MessageType, bytes]:
        """Reçoit message binaire"""
        header = self._recv_exact(sock, 5)
        if not header:
            raise ConnectionError("Connexion fermée")
        
        msg_type, payload_size = BinaryProtocol.unpack_header(header)
        
        if payload_size > 0:
            payload = self._recv_exact(sock, payload_size)
            if not payload:
                raise ConnectionError("Payload incomplet")
        else:
            payload = b''
        
        return msg_type, payload
    
    def _send_binary_message(self, sock: socket.socket, msg_type: MessageType, payload: bytes):
        """Envoie message binaire"""
        header = BinaryProtocol.pack_header(msg_type, len(payload))
        sock.sendall(header + payload)
    
    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        """Reçoit exactement N bytes"""
        data = b''
        while len(data) < size:
            try:
                chunk = sock.recv(min(size - len(data), SOCKET_BUFFER_SIZE))
                if not chunk:
                    raise ConnectionError("Connexion fermée pendant réception")
                data += chunk
            except socket.timeout:
                raise TimeoutError(f"Timeout après {CONNECTION_TIMEOUT}s")
            except socket.error as e:
                raise ConnectionError(f"Erreur réseau: {e}")
        
        return data
    
    def get_active_receives(self) -> List[ReceiveJob]:
        """Récupère liste des réceptions actives"""
        with self.receive_lock:
            return list(self.active_receives.values())
    
    def get_receive_by_id(self, transfer_id: str) -> Optional[ReceiveJob]:
        """Récupère réception par ID"""
        with self.receive_lock:
            return self.active_receives.get(transfer_id)
    
    def cancel_receive(self, transfer_id: str) -> bool:
        """Annule réception"""
        with self.receive_lock:
            if transfer_id in self.active_receives:
                receive_job = self.active_receives[transfer_id]
                receive_job.status = TransferStatus.CANCELLED
                logger.info(f"Réception {transfer_id[:8]} annulée")
                return True
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Récupère statistiques globales"""
        with self.receive_lock:
            active = len([r for r in self.active_receives.values() 
                         if r.status == TransferStatus.TRANSFERRING])
            completed = len([r for r in self.active_receives.values() 
                           if r.status == TransferStatus.COMPLETED])
            failed = len([r for r in self.active_receives.values() 
                         if r.status == TransferStatus.FAILED])
            
            speeds = []
            for r in self.active_receives.values():
                if r.status == TransferStatus.TRANSFERRING and r.speed > 0:
                    speeds.append(r.speed)
            
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
                'encryption': 'ChaCha20-Poly1305' if HAS_CRYPTO else 'None'
            }
    
    def _format_size(self, b: int) -> str:
        """Formate taille"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"
    
    def _format_speed(self, s: float) -> str:
        """Formate vitesse"""
        return f"{self._format_size(s)}/s"
    
    def _format_duration(self, d: float) -> str:
        """Formate durée"""
        d = int(d)
        if d < 0:
            return "N/A"
        if d < 60:
            return f"{d}s"
        elif d < 3600:
            return f"{d//60}m {d%60}s"
        else:
            return f"{d//3600}h {(d%3600)//60}m"


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE POUR COMPATIBILITÉ (garde le même nom que ton fichier original)
# ══════════════════════════════════════════════════════════════════════════════

# Alias pour compatibilité
class DataShareReceiver(FileReceiver):
    """Alias pour compatibilité"""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# FONCTION MAIN POUR TESTS
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """Fonction de test du module de réception"""
    print("=" * 80)
    print("MODULE DE RÉCEPTION DATASHARE v6.0 - TEST".center(80))
    print("=" * 80)
    
    receiver = FileReceiver(port=TRANSFER_PORT, auto_accept=True)
    
    print(f"\n✓ Receiver initialisé")
    print(f"  Port: {TRANSFER_PORT}")
    print(f"  Dossier: {receiver.default_download_folder}")
    print(f"  Buffers TCP: {SOCKET_BUFFER_SIZE // 1024 // 1024}MB")
    print(f"  Workers: {MAX_CRYPTO_WORKERS}")
    print(f"  Timeout: {CONNECTION_TIMEOUT}s")
    print(f"  Protocole: Binaire synchronisé avec send.py")
    print(f"  Déchiffrement: {'ChaCha20' if HAS_CRYPTO else 'NON'}")
    print(f"  Décompression: {'LZ4' if HAS_LZ4 else 'NON'}")
    
    receiver.start_server()
    
    print(f"\n✅ Serveur prêt - En attente de transferts...")
    print(f"\n💡 Commandes:")
    print(f"  stats  - Voir statistiques")
    print(f"  quit   - Quitter")
    
    try:
        while True:
            try:
                command = input(f"\nReceiver> ").strip().lower()
                
                if command in ['quit', 'exit', 'q']:
                    break
                
                elif command == 'stats':
                    stats = receiver.get_statistics()
                    print(f"\n📊 Statistiques:")
                    print(f"  Transferts actifs: {stats['active_receives']}")
                    print(f"  Terminés: {stats['completed_receives']}")
                    print(f"  Total reçu: {receiver._format_size(stats['session_total_received'])}")
                    print(f"  Vitesse moyenne: {receiver._format_speed(stats['average_speed'])}")
                    print(f"  Uptime: {receiver._format_duration(stats['uptime'])}")
                    print(f"  Dossier: {stats['default_folder']}")
                
                elif command == 'help':
                    print(f"\n💡 Commandes:")
                    print(f"  stats  - Voir statistiques")
                    print(f"  quit   - Quitter")
                
                else:
                    print(f"❌ Commande inconnue (tapez 'help')")
            
            except KeyboardInterrupt:
                print(f"\n⚠️  Interruption")
                break
            
            except EOFError:
                break
    
    finally:
        print(f"\n🛑 Arrêt du récepteur...")
        receiver.stop_server()
        print(f"✓ Terminé")


if __name__ == "__main__":
    main()
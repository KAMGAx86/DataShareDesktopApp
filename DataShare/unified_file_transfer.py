"""
Module de transfert bidirectionnel unifié pour DataShare

Ce module combine les capacités d'envoi et de réception en une seule interface.
Il orchestre les deux modules séparés (sender et receiver) pour fournir
une API simple et cohérente.

Auteur: DataShare Team
Version: 4.0
"""

import logging
import threading
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

# Import des modules de transfert avec les noms réels
from send import (
    FileTransferManager as SenderManager,
    TransferJob as SendJob,
    TransferStatus,
    MessageType,
    CryptoManager,
    PathHandler,
    PerformanceMonitor
)

from receive import (
    FileReceiver,
    ReceiveJob,
    TransferStatus as RecvStatus
)

logger = logging.getLogger(__name__)


class UnifiedTransferJob:
    """
    Job de transfert unifié qui peut être soit un envoi soit une réception.
    Simplifie l'interface pour l'utilisateur.
    """
    
    def __init__(self, job_data, direction: str):
        """
        Args:
            job_data: SendJob ou ReceiveJob
            direction: 'sent' ou 'received'
        """
        self.original_job = job_data
        self.direction = direction
        
        # Propriétés communes
        self.transfer_id = job_data.transfer_id
        self.status = job_data.status
        self.progress = job_data.progress
        self.speed = job_data.speed
        self.eta = job_data.eta
        self.total_size = job_data.total_size
        self.files = job_data.files
        
        # Propriétés spécifiques à la direction
        if direction == 'sent':
            self.remote_ip = getattr(job_data, 'sender_ip', 'unknown')
            self.remote_name = getattr(job_data, 'sender_name', 'unknown')
            self.bytes_transferred = int(job_data.total_size * job_data.progress)
        else:  # received
            self.remote_ip = job_data.sender_ip
            self.remote_name = job_data.sender_name
            self.bytes_transferred = job_data.bytes_received
            self.destination_folder = job_data.destination_folder
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire."""
        return {
            'transfer_id': self.transfer_id,
            'direction': self.direction,
            'status': self.status.value if hasattr(self.status, 'value') else str(self.status),
            'progress': self.progress,
            'speed': self.speed,
            'eta': self.eta,
            'total_size': self.total_size,
            'bytes_transferred': self.bytes_transferred,
            'remote_ip': self.remote_ip,
            'remote_name': self.remote_name,
            'file_count': len(self.files)
        }


class DataShareFileTransfer:
    """
    Gestionnaire de transfert bidirectionnel unifié.
    
    Cette classe orchestre à la fois l'envoi et la réception de fichiers
    en fournissant une interface unique et cohérente.
    """
    
    def __init__(self, port: int = 32001):
        """
        Initialise le gestionnaire bidirectionnel.
        
        Args:
            port: Port TCP pour les transferts
        """
        self.port = port
        
        # Modules sous-jacents
        self.sender = SenderManager(port)
        self.receiver = FileReceiver(port, auto_accept=False)
        
        # État global
        self.is_running = False
        self._lock = threading.Lock()
        
        # Callbacks unifiés
        self._unified_callbacks = {
            'on_transfer_request': None,
            'on_progress_update': None,
            'on_transfer_complete': None,
            'on_file_received': None
        }
        
        # Configurer les callbacks internes
        self._setup_callbacks()
        
        logger.info(f"DataShareFileTransfer initialisé sur le port {port}")
    
    def _setup_callbacks(self):
        """Configure les callbacks pour rediriger vers les callbacks unifiés."""
        
        # Callbacks du récepteur
        self.receiver.on_transfer_request = self._handle_receive_request
        self.receiver.on_progress_update = self._handle_receive_progress
        self.receiver.on_transfer_complete = self._handle_receive_complete
        self.receiver.on_file_received = self._handle_file_received
        
        # Callbacks de l'envoyeur
        self.sender.on_progress_update = self._handle_send_progress
        self.sender.on_transfer_complete = self._handle_send_complete
    
    def _handle_receive_request(self, receive_job: ReceiveJob, socket):
        """Gère une demande de réception."""
        if self._unified_callbacks['on_transfer_request']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_transfer_request'](unified_job, socket)
    
    def _handle_receive_progress(self, receive_job: ReceiveJob):
        """Gère la progression d'une réception."""
        if self._unified_callbacks['on_progress_update']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_progress_update'](unified_job)
    
    def _handle_receive_complete(self, receive_job: ReceiveJob):
        """Gère la fin d'une réception."""
        if self._unified_callbacks['on_transfer_complete']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_transfer_complete'](unified_job)
    
    def _handle_file_received(self, receive_job: ReceiveJob, file_name: str):
        """Gère la réception d'un fichier."""
        if self._unified_callbacks['on_file_received']:
            self._unified_callbacks['on_file_received'](receive_job, file_name)
    
    def _handle_send_progress(self, send_job: SendJob):
        """Gère la progression d'un envoi."""
        if self._unified_callbacks['on_progress_update']:
            unified_job = UnifiedTransferJob(send_job, 'sent')
            self._unified_callbacks['on_progress_update'](unified_job)
    
    def _handle_send_complete(self, send_job: SendJob):
        """Gère la fin d'un envoi."""
        if self._unified_callbacks['on_transfer_complete']:
            unified_job = UnifiedTransferJob(send_job, 'sent')
            self._unified_callbacks['on_transfer_complete'](unified_job)
    
    # Propriétés pour les callbacks
    @property
    def on_transfer_request(self):
        return self._unified_callbacks['on_transfer_request']
    
    @on_transfer_request.setter
    def on_transfer_request(self, callback: Callable):
        self._unified_callbacks['on_transfer_request'] = callback
    
    @property
    def on_progress_update(self):
        return self._unified_callbacks['on_progress_update']
    
    @on_progress_update.setter
    def on_progress_update(self, callback: Callable):
        self._unified_callbacks['on_progress_update'] = callback
    
    @property
    def on_transfer_complete(self):
        return self._unified_callbacks['on_transfer_complete']
    
    @on_transfer_complete.setter
    def on_transfer_complete(self, callback: Callable):
        self._unified_callbacks['on_transfer_complete'] = callback
    
    @property
    def on_file_received(self):
        return self._unified_callbacks['on_file_received']
    
    @on_file_received.setter
    def on_file_received(self, callback: Callable):
        self._unified_callbacks['on_file_received'] = callback
    
    def start_server(self):
        """Démarre les serveurs d'envoi et de réception."""
        if self.is_running:
            logger.warning("Les serveurs sont déjà en cours d'exécution")
            return
        
        with self._lock:
            logger.info("Démarrage des serveurs de transfert...")
            
            # Démarrer l'envoyeur
            self.sender.start_server()
            
            # Démarrer le récepteur
            self.receiver.start_server()
            
            self.is_running = True
            logger.info("Serveurs de transfert démarrés (envoi + réception)")
    
    def stop_server(self):
        """Arrête les serveurs d'envoi et de réception."""
        if not self.is_running:
            return
        
        with self._lock:
            logger.info("Arrêt des serveurs de transfert...")
            
            # Arrêter l'envoyeur
            self.sender.stop_server()
            
            # Arrêter le récepteur
            self.receiver.stop_server()
            
            self.is_running = False
            logger.info("Serveurs de transfert arrêtés")
    
    def send_files(self, target_ip: str, files_and_folders: List[str], 
                   sender_name: str = "DataShare User") -> str:
        """
        Envoie des fichiers vers un destinataire.
        
        Args:
            target_ip: IP du destinataire
            files_and_folders: Liste des chemins à envoyer
            sender_name: Nom de l'expéditeur
            
        Returns:
            str: ID du transfert
        """
        return self.sender.send_files(target_ip, files_and_folders, sender_name)
    
    def accept_transfer(self, transfer_id: str, destination_folder: str) -> bool:
        """
        Accepte un transfert entrant.
        
        Args:
            transfer_id: ID du transfert
            destination_folder: Dossier de destination
            
        Returns:
            bool: Succès
        """
        return self.receiver.accept_transfer(transfer_id, destination_folder)
    
    def reject_transfer(self, transfer_id: str, reason: str = "Refusé") -> bool:
        """
        Rejette un transfert entrant.
        
        Args:
            transfer_id: ID du transfert
            reason: Raison du rejet
            
        Returns:
            bool: Succès
        """
        return self.receiver.reject_transfer(transfer_id, reason)
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """
        Annule un transfert en cours (envoi ou réception).
        
        Args:
            transfer_id: ID du transfert
            
        Returns:
            bool: Succès
        """
        # Essayer d'annuler côté envoi
        if self.sender.cancel_transfer(transfer_id):
            return True
        
        # Essayer d'annuler côté réception
        if self.receiver.cancel_receive(transfer_id):
            return True
        
        return False
    
    def get_active_transfers(self) -> List[UnifiedTransferJob]:
        """
        Récupère tous les transferts actifs (envois + réceptions).
        
        Returns:
            List[UnifiedTransferJob]: Liste unifiée des transferts
        """
        transfers = []
        
        # Récupérer les envois
        for send_job in self.sender.get_active_transfers():
            unified = UnifiedTransferJob(send_job, 'sent')
            transfers.append(unified)
        
        # Récupérer les réceptions
        for receive_job in self.receiver.get_active_receives():
            unified = UnifiedTransferJob(receive_job, 'received')
            transfers.append(unified)
        
        return transfers
    
    def get_transfer_by_id(self, transfer_id: str) -> Optional[UnifiedTransferJob]:
        """
        Récupère un transfert par son ID.
        
        Args:
            transfer_id: ID du transfert
            
        Returns:
            Optional[UnifiedTransferJob]: Transfert trouvé ou None
        """
        # Chercher dans les envois
        send_job = self.sender.get_transfer_by_id(transfer_id)
        if send_job:
            return UnifiedTransferJob(send_job, 'sent')
        
        # Chercher dans les réceptions
        receive_job = self.receiver.get_receive_by_id(transfer_id)
        if receive_job:
            return UnifiedTransferJob(receive_job, 'received')
        
        return None
    
    def get_transfer_statistics(self) -> Dict[str, Any]:
        """
        Récupère les statistiques globales des transferts.
        
        Returns:
            Dict: Statistiques combinées envoi + réception
        """
        send_stats = self.sender.get_transfer_statistics()
        receive_stats = self.receiver.get_statistics()
        
        return {
            'total_active_transfers': send_stats['active_transfers'] + receive_stats['active_receives'],
            'active_sends': send_stats['active_transfers'],
            'active_receives': receive_stats['active_receives'],
            'completed_sends': send_stats['completed_transfers'],
            'completed_receives': receive_stats['completed_receives'],
            'failed_sends': send_stats['failed_transfers'],
            'failed_receives': receive_stats['failed_receives'],
            'total_bytes_sent': send_stats['total_bytes'],
            'total_bytes_received': receive_stats['session_total_received'],
            'average_send_speed': send_stats['average_speed'],
            'average_receive_speed': receive_stats['average_speed'],
            'optimal_chunk_size': send_stats['optimal_chunk_size'],
            'encryption': send_stats.get('encryption', 'AES-256-GCM')
        }
    
    def set_auto_accept(self, enabled: bool, destination_folder: str = None):
        """
        Configure l'acceptation automatique des transferts entrants.
        
        Args:
            enabled: Activer/désactiver
            destination_folder: Dossier par défaut (optionnel)
        """
        self.receiver.auto_accept = enabled
        if destination_folder:
            self.receiver.default_download_folder = Path(destination_folder)
        
        logger.info(f"Auto-accept {'activé' if enabled else 'désactivé'}")


def main():
    """Fonction de démonstration."""
    print("=" * 80)
    print("MODULE DE TRANSFERT BIDIRECTIONNEL UNIFIE")
    print("=" * 80)
    
    # Initialiser
    transfer = DataShareFileTransfer(port=32001)
    
    print(f"\nInitialise:")
    print(f"  Port: {transfer.port}")
    print(f"  Chiffrement: AES-256-GCM")
    print(f"  Mode: Bidirectionnel (envoi + reception)")
    
    # Démarrer les serveurs
    transfer.start_server()
    print(f"\nServeurs demarres")
    
    # Statistiques
    stats = transfer.get_transfer_statistics()
    print(f"\nStatistiques:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\nCommandes disponibles:")
    print(f"  - send_files(ip, files, name)")
    print(f"  - accept_transfer(id, folder)")
    print(f"  - cancel_transfer(id)")
    print(f"  - get_active_transfers()")
    
    # Arrêter
    transfer.stop_server()
    print(f"\nServeurs arretes")


if __name__ == "__main__":
    main()
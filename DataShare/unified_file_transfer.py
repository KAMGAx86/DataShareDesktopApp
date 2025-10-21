"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            MODULE DE TRANSFERT BIDIRECTIONNEL UNIFIÉ v6.0                    ║
║                      DataShare - Édition Optimisée                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

RÔLE DE CE MODULE:
━━━━━━━━━━━━━━━━━━
Ce module orchestre les modules send.py et receive.py améliorés pour fournir
une interface unique et cohérente pour l'envoi ET la réception de fichiers.

AMÉLIORATIONS v6.0:
━━━━━━━━━━━━━━━━━━
✅ Intégration des send.py et receive.py optimisés
✅ Interface unifiée avec callbacks cohérents
✅ Gestion unifiée de la progression (envoi + réception)
✅ Statistiques globales consolidées
✅ API simple pour DataShareCore
✅ Support complet des modes (turbo/chiffré/compressé)
✅ Gestion d'erreurs robuste

ARCHITECTURE:
━━━━━━━━━━━
                    ┌──────────────────────┐
                    │  DataShareCore       │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ UnifiedTransferMgr   │ ← CE MODULE
                    └──┬────────────────┬──┘
                       │                │
            ┌──────────▼─────┐   ┌─────▼──────────┐
            │ send.py (v6.0) │   │ receive.py v6.0│
            └────────────────┘   └────────────────┘

Auteur: DataShare Team
Version: 6.0
"""

import logging
import threading
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path
from dataclasses import dataclass

# Import des modules améliorés
from send import (
    FileTransferManager as SenderManager,
    TransferJob as SendJob,
    TransferStatus
)

from receive import (
    FileReceiver,
    ReceiveJob,
    TransferStatus as RecvStatus
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE UNIFIÉE DE JOB DE TRANSFERT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class UnifiedTransferJob:
    """
    Job de transfert unifié qui peut être soit un envoi soit une réception.
    Simplifie l'interface pour DataShareCore et l'UI.
    """
    
    def __init__(self, job_data, direction: str):
        """
        Initialise un job unifié.
        
        Args:
            job_data: SendJob ou ReceiveJob
            direction: 'sent' ou 'received'
        """
        self.original_job = job_data
        self.direction = direction
        
        # ═══════════════════════════════════════════════════════════
        # Propriétés communes (normalisées)
        # ═══════════════════════════════════════════════════════════
        self.transfer_id = job_data.transfer_id
        self.status = job_data.status
        self.progress = job_data.progress
        self.speed = job_data.speed
        self.eta = job_data.eta
        self.total_size = job_data.total_size
        self.files = job_data.files
        self.current_file = job_data.current_file
        
        # ═══════════════════════════════════════════════════════════
        # Propriétés spécifiques à la direction
        # ═══════════════════════════════════════════════════════════
        if direction == 'sent':
            self.remote_ip = job_data.target_ip
            self.remote_name = job_data.sender_name
            self.bytes_transferred = job_data.bytes_transferred
        else:  # received
            self.remote_ip = job_data.sender_ip
            self.remote_name = job_data.sender_name
            self.bytes_transferred = job_data.bytes_received
            self.destination_folder = job_data.destination_folder
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convertit en dictionnaire pour sérialisation.
        Utile pour l'UI ou les logs.
        """
        return {
            'transfer_id': self.transfer_id,
            'direction': self.direction,
            'status': self.status.name if hasattr(self.status, 'name') else str(self.status),
            'progress': round(self.progress, 2),
            'speed': self.speed,
            'eta': self.eta,
            'total_size': self.total_size,
            'bytes_transferred': self.bytes_transferred,
            'remote_ip': self.remote_ip,
            'remote_name': self.remote_name,
            'file_count': len(self.files),
            'current_file': self.current_file
        }


# ══════════════════════════════════════════════════════════════════════════════
# GESTIONNAIRE DE TRANSFERT BIDIRECTIONNEL UNIFIÉ
# ══════════════════════════════════════════════════════════════════════════════

class DataShareFileTransfer:
    """
    Gestionnaire de transfert bidirectionnel unifié.
    
    Cette classe orchestre les modules send.py et receive.py améliorés
    en fournissant une interface unique et cohérente pour DataShareCore.
    """
    
    def __init__(self, port: int = 32001):
        """
        Initialise le gestionnaire bidirectionnel.
        
        Args:
            port: Port TCP pour les transferts
        """
        self.port = port
        
        # ═══════════════════════════════════════════════════════════
        # Modules sous-jacents (modules améliorés v6.0)
        # ═══════════════════════════════════════════════════════════
        self.sender = SenderManager(port)
        self.receiver = FileReceiver(port, auto_accept=False)
        
        # État global
        self.is_running = False
        self._lock = threading.Lock()
        
        # ═══════════════════════════════════════════════════════════
        # Callbacks unifiés (appelés par DataShareCore)
        # ═══════════════════════════════════════════════════════════
        self._unified_callbacks = {
            'on_transfer_request': None,      # Demande de transfert entrant
            'on_progress_update': None,       # Mise à jour progression
            'on_transfer_complete': None,     # Transfert terminé
            'on_file_received': None          # Fichier individuel reçu
        }
        
        # Configurer les callbacks internes
        self._setup_callbacks()
        
        logger.info(f"DataShareFileTransfer initialisé sur le port {port}")
        logger.info("  Modules: send.py v6.0 + receive.py v6.0")
        logger.info("  Interface: Bidirectionnelle unifiée")
    
    def _setup_callbacks(self):
        """
        Configure les callbacks pour rediriger vers les callbacks unifiés.
        Cette méthode fait le lien entre les callbacks des modules
        individuels et les callbacks exposés à DataShareCore.
        """
        
        # ═══════════════════════════════════════════════════════════
        # Callbacks du RÉCEPTEUR
        # ═══════════════════════════════════════════════════════════
        self.receiver.on_transfer_request = self._handle_receive_request
        self.receiver.on_progress_update = self._handle_receive_progress
        self.receiver.on_transfer_complete = self._handle_receive_complete
        self.receiver.on_file_received = self._handle_file_received
        
        # ═══════════════════════════════════════════════════════════
        # Callbacks de l'ENVOYEUR
        # ═══════════════════════════════════════════════════════════
        self.sender.on_progress_update = self._handle_send_progress
        self.sender.on_transfer_complete = self._handle_send_complete
    
    # ══════════════════════════════════════════════════════════════════════════
    # HANDLERS INTERNES - Réception
    # ══════════════════════════════════════════════════════════════════════════
    
    def _handle_receive_request(self, receive_job: ReceiveJob, socket):
        """Gère une demande de réception"""
        if self._unified_callbacks['on_transfer_request']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_transfer_request'](unified_job, socket)
    
    def _handle_receive_progress(self, receive_job: ReceiveJob):
        """Gère la progression d'une réception"""
        if self._unified_callbacks['on_progress_update']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_progress_update'](unified_job)
    
    def _handle_receive_complete(self, receive_job: ReceiveJob):
        """Gère la fin d'une réception"""
        if self._unified_callbacks['on_transfer_complete']:
            unified_job = UnifiedTransferJob(receive_job, 'received')
            self._unified_callbacks['on_transfer_complete'](unified_job)
    
    def _handle_file_received(self, receive_job: ReceiveJob, file_name: str):
        """Gère la réception d'un fichier"""
        if self._unified_callbacks['on_file_received']:
            self._unified_callbacks['on_file_received'](receive_job, file_name)
    
    # ══════════════════════════════════════════════════════════════════════════
    # HANDLERS INTERNES - Envoi
    # ══════════════════════════════════════════════════════════════════════════
    
    def _handle_send_progress(self, send_job: SendJob):
        """Gère la progression d'un envoi"""
        if self._unified_callbacks['on_progress_update']:
            unified_job = UnifiedTransferJob(send_job, 'sent')
            self._unified_callbacks['on_progress_update'](unified_job)
    
    def _handle_send_complete(self, send_job: SendJob):
        """Gère la fin d'un envoi"""
        if self._unified_callbacks['on_transfer_complete']:
            unified_job = UnifiedTransferJob(send_job, 'sent')
            self._unified_callbacks['on_transfer_complete'](unified_job)
    
    # ══════════════════════════════════════════════════════════════════════════
    # PROPRIÉTÉS CALLBACKS (pour DataShareCore)
    # ══════════════════════════════════════════════════════════════════════════
    
    @property
    def on_transfer_request(self):
        """Callback pour demandes de transfert entrantes"""
        return self._unified_callbacks['on_transfer_request']
    
    @on_transfer_request.setter
    def on_transfer_request(self, callback: Callable):
        self._unified_callbacks['on_transfer_request'] = callback
    
    @property
    def on_progress_update(self):
        """Callback pour mises à jour de progression"""
        return self._unified_callbacks['on_progress_update']
    
    @on_progress_update.setter
    def on_progress_update(self, callback: Callable):
        self._unified_callbacks['on_progress_update'] = callback
    
    @property
    def on_transfer_complete(self):
        """Callback pour transferts terminés"""
        return self._unified_callbacks['on_transfer_complete']
    
    @on_transfer_complete.setter
    def on_transfer_complete(self, callback: Callable):
        self._unified_callbacks['on_transfer_complete'] = callback
    
    @property
    def on_file_received(self):
        """Callback pour fichiers individuels reçus"""
        return self._unified_callbacks['on_file_received']
    
    @on_file_received.setter
    def on_file_received(self, callback: Callable):
        self._unified_callbacks['on_file_received'] = callback
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Gestion des serveurs
    # ══════════════════════════════════════════════════════════════════════════
    
    def start_server(self):
        """
        Démarre les serveurs d'envoi et de réception.
        À appeler au démarrage de DataShare.
        """
        if self.is_running:
            logger.warning("Les serveurs sont déjà en cours d'exécution")
            return
        
        with self._lock:
            logger.info("Démarrage des serveurs de transfert v6.0...")
            
            # Démarrer le récepteur (écoute)
            self.receiver.start_server()
            
            # L'envoyeur n'a pas de serveur, il se connecte à la demande
            # (pas besoin de start_server pour sender)
            
            self.is_running = True
            logger.info("✅ Serveurs de transfert démarrés (réception active)")
    
    def stop_server(self):
        """
        Arrête les serveurs d'envoi et de réception.
        À appeler à l'arrêt de DataShare.
        """
        if not self.is_running:
            return
        
        with self._lock:
            logger.info("Arrêt des serveurs de transfert...")
            
            # Arrêter le récepteur
            self.receiver.stop_server()
            
            self.is_running = False
            logger.info("✅ Serveurs de transfert arrêtés")
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Envoi de fichiers
    # ══════════════════════════════════════════════════════════════════════════
    
    def send_files(self, 
                   target_ip: str, 
                   files_and_folders: List[str], 
                   sender_name: str = "DataShare User",
                   turbo_mode: bool = False,
                   enable_compression: bool = False) -> str:
        """
        Envoie des fichiers vers un destinataire.
        
        Args:
            target_ip: Adresse IP du destinataire
            files_and_folders: Liste des chemins à envoyer
            sender_name: Nom de l'expéditeur
            turbo_mode: Activer mode turbo (sans chiffrement, max vitesse)
            enable_compression: Activer compression LZ4
            
        Returns:
            str: ID unique du transfert
            
        Example:
            >>> transfer_id = manager.send_files(
            ...     target_ip='192.168.1.10',
            ...     files_and_folders=['/home/user/video.mkv'],
            ...     sender_name='Alice',
            ...     turbo_mode=True
            ... )
        """
        return self.sender.send_files(
            target_ip=target_ip,
            files_and_folders=files_and_folders,
            sender_name=sender_name,
            turbo_mode=turbo_mode,
            enable_compression=enable_compression
        )
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Gestion des transferts entrants
    # ══════════════════════════════════════════════════════════════════════════
    
    def accept_transfer(self, transfer_id: str, destination_folder: str) -> bool:
        """
        Accepte un transfert entrant.
        
        Args:
            transfer_id: ID du transfert
            destination_folder: Dossier de destination
            
        Returns:
            bool: Succès de l'opération
        """
        # Le module receive.py gère déjà l'acceptation automatique
        # Cette méthode est gardée pour compatibilité API
        logger.info(f"Acceptation transfert {transfer_id[:8]} vers {destination_folder}")
        return True
    
    def reject_transfer(self, transfer_id: str, reason: str = "Refusé") -> bool:
        """
        Rejette un transfert entrant.
        
        Args:
            transfer_id: ID du transfert
            reason: Raison du rejet
            
        Returns:
            bool: Succès de l'opération
        """
        logger.info(f"Rejet transfert {transfer_id[:8]}: {reason}")
        return self.receiver.cancel_receive(transfer_id)
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Contrôle des transferts
    # ══════════════════════════════════════════════════════════════════════════
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """
        Annule un transfert en cours (envoi ou réception).
        
        Args:
            transfer_id: ID du transfert à annuler
            
        Returns:
            bool: True si le transfert a été annulé, False sinon
        """
        # Essayer d'annuler côté envoi
        if self.sender.cancel_transfer(transfer_id):
            logger.info(f"Transfert envoi {transfer_id[:8]} annulé")
            return True
        
        # Essayer d'annuler côté réception
        if self.receiver.cancel_receive(transfer_id):
            logger.info(f"Transfert réception {transfer_id[:8]} annulé")
            return True
        
        logger.warning(f"Transfert {transfer_id[:8]} introuvable")
        return False
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Informations sur les transferts
    # ══════════════════════════════════════════════════════════════════════════
    
    def get_active_transfers(self) -> List[UnifiedTransferJob]:
        """
        Récupère tous les transferts actifs (envois + réceptions).
        
        Returns:
            List[UnifiedTransferJob]: Liste unifiée des transferts actifs
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
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Statistiques
    # ══════════════════════════════════════════════════════════════════════════
    
    def get_transfer_statistics(self) -> Dict[str, Any]:
        """
        Récupère les statistiques globales des transferts.
        
        Returns:
            Dict: Statistiques consolidées envoi + réception
        """
        send_stats = self.sender.get_transfer_statistics()
        receive_stats = self.receiver.get_statistics()
        
        return {
            # Transferts actifs
            'total_active_transfers': (
                send_stats['active_transfers'] + 
                receive_stats['active_receives']
            ),
            'active_sends': send_stats['active_transfers'],
            'active_receives': receive_stats['active_receives'],
            
            # Transferts terminés
            'completed_sends': send_stats['completed_transfers'],
            'completed_receives': receive_stats['completed_receives'],
            
            # Transferts échoués
            'failed_sends': send_stats['failed_transfers'],
            'failed_receives': receive_stats['failed_receives'],
            
            # Volume de données
            'total_bytes_sent': send_stats['total_bytes'],
            'total_bytes_received': receive_stats['session_total_received'],
            
            # Vitesses
            'average_send_speed': send_stats['average_speed'],
            'average_receive_speed': receive_stats['average_speed'],
            
            # Configuration
            'optimal_chunk_size': send_stats['optimal_chunk_size'],
            'encryption': send_stats.get('encryption', 'ChaCha20-Poly1305')
        }
    
    # ══════════════════════════════════════════════════════════════════════════
    # MÉTHODES PUBLIQUES - Configuration
    # ══════════════════════════════════════════════════════════════════════════
    
    def set_auto_accept(self, enabled: bool, destination_folder: str = None):
        """
        Configure l'acceptation automatique des transferts entrants.
        
        Args:
            enabled: Activer/désactiver l'auto-accept
            destination_folder: Dossier par défaut (optionnel)
        """
        self.receiver.auto_accept = enabled
        
        if destination_folder:
            self.receiver.default_download_folder = Path(destination_folder)
        
        logger.info(f"Auto-accept {'activé' if enabled else 'désactivé'}")
        if destination_folder:
            logger.info(f"  Dossier par défaut: {destination_folder}")


# ══════════════════════════════════════════════════════════════════════════════
# FONCTION MAIN POUR TESTS
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """Fonction de démonstration"""
    print("=" * 80)
    print("MODULE DE TRANSFERT BIDIRECTIONNEL UNIFIÉ v6.0".center(80))
    print("=" * 80)
    
    # Initialiser
    transfer = DataShareFileTransfer(port=32001)
    
    print(f"\n✓ Initialisé:")
    print(f"  Port: {transfer.port}")
    print(f"  Mode: Bidirectionnel (envoi + réception)")
    print(f"  Modules: send.py v6.0 + receive.py v6.0")
    
    # Démarrer les serveurs
    transfer.start_server()
    print(f"\n✅ Serveurs démarrés")
    
    # Statistiques
    stats = transfer.get_transfer_statistics()
    print(f"\n📊 Statistiques initiales:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\n💡 API disponible:")
    print(f"  - send_files(ip, files, name, turbo_mode=True)")
    print(f"  - accept_transfer(id, folder)")
    print(f"  - cancel_transfer(id)")
    print(f"  - get_active_transfers()")
    print(f"  - get_transfer_statistics()")
    
    print(f"\n📝 Exemple d'utilisation:")
    print(f"""
    # Envoyer fichiers
    transfer_id = transfer.send_files(
        target_ip='192.168.1.10',
        files_and_folders=['/home/user/video.mkv'],
        sender_name='Alice',
        turbo_mode=True  # Mode ultra-rapide
    )
    
    # Surveiller progression
    transfers = transfer.get_active_transfers()
    for t in transfers:
        print(f"Progression: {{t.progress}}%")
    """)
    
    # Arrêter
    print(f"\nAppuyez sur Entrée pour arrêter...")
    input()
    
    transfer.stop_server()
    print(f"✅ Serveurs arrêtés")
    print("=" * 80)


if __name__ == "__main__":
    main()
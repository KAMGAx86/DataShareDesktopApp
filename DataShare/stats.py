"""
Gestionnaire de statistiques et d'historique pour DataShare

Ce module gère :
- Historique détaillé des transferts
- Statistiques de performance réseau
- Analyse des appareils connectés
- Graphiques de données d'utilisation
- Export des rapports
- Nettoyage automatique des anciennes données

Auteur: DataShare Team
Version: 1.0
"""

import json
import sqlite3
import threading
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import statistics

logger = logging.getLogger(__name__)

class TransferDirection(Enum):
    """Direction du transfert."""
    SENT = "sent"
    RECEIVED = "received"

class TransferStatus(Enum):
    """Statut du transfert."""
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class TransferRecord:
    """Enregistrement d'un transfert."""
    id: str
    timestamp: float
    direction: TransferDirection
    status: TransferStatus
    device_id: str
    device_name: str
    device_ip: str
    file_count: int
    total_bytes: int
    duration: float
    average_speed: float
    error_message: str = ""
    file_types: List[str] = None
    
    def __post_init__(self):
        if self.file_types is None:
            self.file_types = []

@dataclass
class DeviceStats:
    """Statistiques d'un appareil."""
    device_id: str
    device_name: str
    last_ip: str
    first_seen: float
    last_seen: float
    total_connections: int
    successful_transfers: int
    failed_transfers: int
    total_bytes_sent: int
    total_bytes_received: int
    average_speed: float
    trust_level: str = "unknown"

@dataclass
class NetworkSession:
    """Session réseau."""
    session_id: str
    start_time: float
    end_time: float
    network_type: str  # hotspot_created, hotspot_joined, existing_network
    network_name: str
    devices_connected: List[str]
    transfers_count: int
    total_bytes: int

class StatisticsManager:
    """Gestionnaire principal des statistiques."""
    
    def __init__(self, db_path: Optional[str] = None):
        # Déterminer le chemin de la base de données
        if db_path:
            self.db_path = Path(db_path)
        else:
            from user_config import get_settings
            settings = get_settings()
            self.db_path = Path(settings.config_dir) / "statistics.db"
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_lock = threading.Lock()
        
        # Statistiques en mémoire pour accès rapide
        self.current_session: Optional[NetworkSession] = None
        self.transfer_records: List[TransferRecord] = []
        self.device_stats: Dict[str, DeviceStats] = {}
        
        # Configuration
        self.max_records_memory = 1000  # Nombre max d'enregistrements en mémoire
        self.cleanup_days = 365  # Garder les données pendant 1 an
        
        # Initialiser la base de données
        self._init_database()
        
        # Charger les données récentes
        self._load_recent_data()
        
        logger.info(f"StatisticsManager initialisé - DB: {self.db_path}")
    
    def _init_database(self):
        """Initialise la base de données SQLite."""
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                # Table des transferts
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS transfers (
                        id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        direction TEXT NOT NULL,
                        status TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        device_name TEXT NOT NULL,
                        device_ip TEXT NOT NULL,
                        file_count INTEGER NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        duration REAL NOT NULL,
                        average_speed REAL NOT NULL,
                        error_message TEXT,
                        file_types TEXT
                    )
                """)
                
                # Table des statistiques d'appareils
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_stats (
                        device_id TEXT PRIMARY KEY,
                        device_name TEXT NOT NULL,
                        last_ip TEXT NOT NULL,
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        total_connections INTEGER DEFAULT 0,
                        successful_transfers INTEGER DEFAULT 0,
                        failed_transfers INTEGER DEFAULT 0,
                        total_bytes_sent INTEGER DEFAULT 0,
                        total_bytes_received INTEGER DEFAULT 0,
                        average_speed REAL DEFAULT 0,
                        trust_level TEXT DEFAULT 'unknown'
                    )
                """)
                
                # Table des sessions réseau
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS network_sessions (
                        session_id TEXT PRIMARY KEY,
                        start_time REAL NOT NULL,
                        end_time REAL,
                        network_type TEXT NOT NULL,
                        network_name TEXT NOT NULL,
                        devices_connected TEXT,
                        transfers_count INTEGER DEFAULT 0,
                        total_bytes INTEGER DEFAULT 0
                    )
                """)
                
                # Index pour les performances
                conn.execute("CREATE INDEX IF NOT EXISTS idx_transfers_timestamp ON transfers(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_transfers_device ON transfers(device_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_device_stats_last_seen ON device_stats(last_seen)")
                
                conn.commit()
                logger.info("Base de données initialisée")
                
            finally:
                conn.close()
    
    def _load_recent_data(self):
        """Charge les données récentes en mémoire."""
        # Charger les transferts récents (30 derniers jours)
        cutoff_time = time.time() - (30 * 24 * 3600)
        
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                # Transferts récents
                cursor = conn.execute("""
                    SELECT * FROM transfers 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (cutoff_time, self.max_records_memory))
                
                self.transfer_records = []
                for row in cursor.fetchall():
                    file_types = json.loads(row[12]) if row[12] else []
                    record = TransferRecord(
                        id=row[0],
                        timestamp=row[1],
                        direction=TransferDirection(row[2]),
                        status=TransferStatus(row[3]),
                        device_id=row[4],
                        device_name=row[5],
                        device_ip=row[6],
                        file_count=row[7],
                        total_bytes=row[8],
                        duration=row[9],
                        average_speed=row[10],
                        error_message=row[11] or "",
                        file_types=file_types
                    )
                    self.transfer_records.append(record)
                
                # Statistiques d'appareils
                cursor = conn.execute("SELECT * FROM device_stats")
                self.device_stats = {}
                for row in cursor.fetchall():
                    stats = DeviceStats(
                        device_id=row[0],
                        device_name=row[1],
                        last_ip=row[2],
                        first_seen=row[3],
                        last_seen=row[4],
                        total_connections=row[5],
                        successful_transfers=row[6],
                        failed_transfers=row[7],
                        total_bytes_sent=row[8],
                        total_bytes_received=row[9],
                        average_speed=row[10],
                        trust_level=row[11]
                    )
                    self.device_stats[stats.device_id] = stats
                
                logger.info(f"Données chargées: {len(self.transfer_records)} transferts, "
                          f"{len(self.device_stats)} appareils")
                
            finally:
                conn.close()
    
    def record_transfer(self, transfer_record: TransferRecord):
        """Enregistre un nouveau transfert."""
        # Ajouter en mémoire
        self.transfer_records.append(transfer_record)
        
        # Limiter la mémoire
        if len(self.transfer_records) > self.max_records_memory:
            self.transfer_records.pop(0)
        
        # Sauvegarder en base
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO transfers 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    transfer_record.id,
                    transfer_record.timestamp,
                    transfer_record.direction.value,
                    transfer_record.status.value,
                    transfer_record.device_id,
                    transfer_record.device_name,
                    transfer_record.device_ip,
                    transfer_record.file_count,
                    transfer_record.total_bytes,
                    transfer_record.duration,
                    transfer_record.average_speed,
                    transfer_record.error_message,
                    json.dumps(transfer_record.file_types)
                ))
                conn.commit()
            finally:
                conn.close()
        
        # Mettre à jour les statistiques d'appareil
        self._update_device_stats(transfer_record)
        
        logger.info(f"Transfert enregistré: {transfer_record.id}")
    
    def _update_device_stats(self, transfer_record: TransferRecord):
        """Met à jour les statistiques d'un appareil."""
        device_id = transfer_record.device_id
        
        # Récupérer ou créer les stats
        if device_id in self.device_stats:
            stats = self.device_stats[device_id]
        else:
            stats = DeviceStats(
                device_id=device_id,
                device_name=transfer_record.device_name,
                last_ip=transfer_record.device_ip,
                first_seen=transfer_record.timestamp,
                last_seen=transfer_record.timestamp,
                total_connections=0,
                successful_transfers=0,
                failed_transfers=0,
                total_bytes_sent=0,
                total_bytes_received=0,
                average_speed=0
            )
            self.device_stats[device_id] = stats
        
        # Mettre à jour les stats
        stats.device_name = transfer_record.device_name  # Nom peut changer
        stats.last_ip = transfer_record.device_ip
        stats.last_seen = transfer_record.timestamp
        
        if transfer_record.status == TransferStatus.COMPLETED:
            stats.successful_transfers += 1
            if transfer_record.direction == TransferDirection.SENT:
                stats.total_bytes_sent += transfer_record.total_bytes
            else:
                stats.total_bytes_received += transfer_record.total_bytes
            
            # Recalculer la vitesse moyenne
            all_speeds = []
            for record in self.transfer_records:
                if (record.device_id == device_id and 
                    record.status == TransferStatus.COMPLETED and 
                    record.average_speed > 0):
                    all_speeds.append(record.average_speed)
            
            if all_speeds:
                stats.average_speed = statistics.mean(all_speeds)
        else:
            stats.failed_transfers += 1
        
        # Sauvegarder en base
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO device_stats 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    stats.device_id,
                    stats.device_name,
                    stats.last_ip,
                    stats.first_seen,
                    stats.last_seen,
                    stats.total_connections,
                    stats.successful_transfers,
                    stats.failed_transfers,
                    stats.total_bytes_sent,
                    stats.total_bytes_received,
                    stats.average_speed,
                    stats.trust_level
                ))
                conn.commit()
            finally:
                conn.close()
    
    def record_device_connection(self, device_id: str, device_name: str, device_ip: str):
        """Enregistre une connexion d'appareil."""
        if device_id in self.device_stats:
            stats = self.device_stats[device_id]
            stats.total_connections += 1
            stats.last_seen = time.time()
            stats.last_ip = device_ip
            stats.device_name = device_name
        else:
            # Nouvel appareil
            stats = DeviceStats(
                device_id=device_id,
                device_name=device_name,
                last_ip=device_ip,
                first_seen=time.time(),
                last_seen=time.time(),
                total_connections=1,
                successful_transfers=0,
                failed_transfers=0,
                total_bytes_sent=0,
                total_bytes_received=0,
                average_speed=0
            )
            self.device_stats[device_id] = stats
        
        # Sauvegarder
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO device_stats 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    stats.device_id,
                    stats.device_name,
                    stats.last_ip,
                    stats.first_seen,
                    stats.last_seen,
                    stats.total_connections,
                    stats.successful_transfers,
                    stats.failed_transfers,
                    stats.total_bytes_sent,
                    stats.total_bytes_received,
                    stats.average_speed,
                    stats.trust_level
                ))
                conn.commit()
            finally:
                conn.close()
        
        logger.debug(f"Connexion enregistrée pour {device_name}")
    
    def start_network_session(self, network_type: str, network_name: str) -> str:
        """Démarre une nouvelle session réseau."""
        session_id = f"session_{int(time.time() * 1000)}"
        
        self.current_session = NetworkSession(
            session_id=session_id,
            start_time=time.time(),
            end_time=0,
            network_type=network_type,
            network_name=network_name,
            devices_connected=[],
            transfers_count=0,
            total_bytes=0
        )
        
        logger.info(f"Session réseau démarrée: {session_id} ({network_type})")
        return session_id
    
    def end_network_session(self):
        """Termine la session réseau actuelle."""
        if not self.current_session:
            return
        
        self.current_session.end_time = time.time()
        
        # Sauvegarder en base
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO network_sessions 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.current_session.session_id,
                    self.current_session.start_time,
                    self.current_session.end_time,
                    self.current_session.network_type,
                    self.current_session.network_name,
                    json.dumps(self.current_session.devices_connected),
                    self.current_session.transfers_count,
                    self.current_session.total_bytes
                ))
                conn.commit()
            finally:
                conn.close()
        
        logger.info(f"Session réseau terminée: {self.current_session.session_id}")
        self.current_session = None
    
    def add_device_to_session(self, device_id: str):
        """Ajoute un appareil à la session actuelle."""
        if self.current_session and device_id not in self.current_session.devices_connected:
            self.current_session.devices_connected.append(device_id)
    
    def update_session_transfer(self, bytes_transferred: int):
        """Met à jour les statistiques de transfert de la session."""
        if self.current_session:
            self.current_session.transfers_count += 1
            self.current_session.total_bytes += bytes_transferred
    
    def get_transfer_history(self, 
                           days: int = 30,
                           device_id: Optional[str] = None,
                           status: Optional[TransferStatus] = None) -> List[TransferRecord]:
        """Récupère l'historique des transferts."""
        cutoff_time = time.time() - (days * 24 * 3600)
        
        # Filtrer les enregistrements en mémoire
        filtered_records = []
        for record in self.transfer_records:
            if record.timestamp < cutoff_time:
                continue
            if device_id and record.device_id != device_id:
                continue
            if status and record.status != status:
                continue
            filtered_records.append(record)
        
        # Si on a besoin de plus de données, interroger la base
        if days > 30 or len(filtered_records) < 50:
            with self.db_lock:
                conn = sqlite3.connect(str(self.db_path))
                try:
                    query = "SELECT * FROM transfers WHERE timestamp > ?"
                    params = [cutoff_time]
                    
                    if device_id:
                        query += " AND device_id = ?"
                        params.append(device_id)
                    
                    if status:
                        query += " AND status = ?"
                        params.append(status.value)
                    
                    query += " ORDER BY timestamp DESC LIMIT 1000"
                    
                    cursor = conn.execute(query, params)
                    
                    db_records = []
                    for row in cursor.fetchall():
                        file_types = json.loads(row[12]) if row[12] else []
                        record = TransferRecord(
                            id=row[0],
                            timestamp=row[1],
                            direction=TransferDirection(row[2]),
                            status=TransferStatus(row[3]),
                            device_id=row[4],
                            device_name=row[5],
                            device_ip=row[6],
                            file_count=row[7],
                            total_bytes=row[8],
                            duration=row[9],
                            average_speed=row[10],
                            error_message=row[11] or "",
                            file_types=file_types
                        )
                        db_records.append(record)
                    
                    return db_records
                    
                finally:
                    conn.close()
        
        return sorted(filtered_records, key=lambda x: x.timestamp, reverse=True)
    
    def get_transfer_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Calcule les statistiques des transferts."""
        records = self.get_transfer_history(days)
        
        if not records:
            return {
                'total_transfers': 0,
                'successful_transfers': 0,
                'failed_transfers': 0,
                'total_bytes': 0,
                'total_files': 0,
                'average_speed': 0,
                'fastest_speed': 0,
                'slowest_speed': 0,
                'most_active_device': None,
                'most_transferred_file_type': None
            }
        
        # Calculs de base
        total_transfers = len(records)
        successful = [r for r in records if r.status == TransferStatus.COMPLETED]
        failed = [r for r in records if r.status == TransferStatus.FAILED]
        
        total_bytes = sum(r.total_bytes for r in successful)
        total_files = sum(r.file_count for r in successful)
        
        # Vitesses
        speeds = [r.average_speed for r in successful if r.average_speed > 0]
        average_speed = statistics.mean(speeds) if speeds else 0
        fastest_speed = max(speeds) if speeds else 0
        slowest_speed = min(speeds) if speeds else 0
        
        # Appareil le plus actif
        device_activity = {}
        for record in records:
            device_id = record.device_id
            if device_id not in device_activity:
                device_activity[device_id] = {'count': 0, 'name': record.device_name}
            device_activity[device_id]['count'] += 1
        
        most_active_device = None
        if device_activity:
            most_active_id = max(device_activity.keys(), 
                               key=lambda x: device_activity[x]['count'])
            most_active_device = {
                'device_id': most_active_id,
                'device_name': device_activity[most_active_id]['name'],
                'transfer_count': device_activity[most_active_id]['count']
            }
        
        # Type de fichier le plus transféré
        file_type_counts = {}
        for record in successful:
            for file_type in record.file_types:
                file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
        
        most_transferred_file_type = None
        if file_type_counts:
            most_transferred_file_type = max(file_type_counts.keys(), 
                                           key=file_type_counts.get)
        
        return {
            'total_transfers': total_transfers,
            'successful_transfers': len(successful),
            'failed_transfers': len(failed),
            'success_rate': len(successful) / total_transfers * 100 if total_transfers > 0 else 0,
            'total_bytes': total_bytes,
            'total_files': total_files,
            'average_speed': average_speed,
            'fastest_speed': fastest_speed,
            'slowest_speed': slowest_speed,
            'most_active_device': most_active_device,
            'most_transferred_file_type': most_transferred_file_type,
            'file_type_distribution': file_type_counts
        }
    
    def get_device_statistics(self) -> List[DeviceStats]:
        """Récupère les statistiques de tous les appareils."""
        return list(self.device_stats.values())
    
    def get_device_stats_by_id(self, device_id: str) -> Optional[DeviceStats]:
        """Récupère les statistiques d'un appareil spécifique."""
        return self.device_stats.get(device_id)
    
    def get_network_usage_over_time(self, days: int = 7) -> List[Dict[str, Any]]:
        """Récupère l'utilisation réseau dans le temps."""
        records = self.get_transfer_history(days)
        
        # Grouper par heure
        usage_by_hour = {}
        for record in records:
            if record.status != TransferStatus.COMPLETED:
                continue
            
            # Arrondir à l'heure
            hour_timestamp = int(record.timestamp // 3600) * 3600
            date_str = datetime.fromtimestamp(hour_timestamp).strftime('%Y-%m-%d %H:00')
            
            if date_str not in usage_by_hour:
                usage_by_hour[date_str] = {
                    'timestamp': hour_timestamp,
                    'date': date_str,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'transfers_sent': 0,
                    'transfers_received': 0,
                    'files_sent': 0,
                    'files_received': 0
                }
            
            stats = usage_by_hour[date_str]
            if record.direction == TransferDirection.SENT:
                stats['bytes_sent'] += record.total_bytes
                stats['transfers_sent'] += 1
                stats['files_sent'] += record.file_count
            else:
                stats['bytes_received'] += record.total_bytes
                stats['transfers_received'] += 1
                stats['files_received'] += record.file_count
        
        # Convertir en liste triée
        usage_list = list(usage_by_hour.values())
        usage_list.sort(key=lambda x: x['timestamp'])
        
        return usage_list
    
    def get_performance_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Calcule les métriques de performance."""
        records = self.get_transfer_history(days)
        successful_records = [r for r in records if r.status == TransferStatus.COMPLETED]
        
        if not successful_records:
            return {
                'average_transfer_time': 0,
                'average_file_size': 0,
                'network_efficiency': 0,
                'peak_performance_hour': None,
                'performance_trend': 'stable'
            }
        
        # Temps de transfert moyen
        transfer_times = [r.duration for r in successful_records if r.duration > 0]
        average_transfer_time = statistics.mean(transfer_times) if transfer_times else 0
        
        # Taille de fichier moyenne
        file_sizes = []
        for record in successful_records:
            if record.file_count > 0:
                avg_file_size = record.total_bytes / record.file_count
                file_sizes.append(avg_file_size)
        
        average_file_size = statistics.mean(file_sizes) if file_sizes else 0
        
        # Efficacité réseau (vitesse réelle vs vitesse théorique)
        speeds = [r.average_speed for r in successful_records if r.average_speed > 0]
        if speeds:
            max_theoretical_speed = 200 * 1024 * 1024  # 200 MB/s
            current_avg_speed = statistics.mean(speeds)
            network_efficiency = (current_avg_speed / max_theoretical_speed) * 100
        else:
            network_efficiency = 0
        
        # Heure de pic de performance
        hourly_speeds = {}
        for record in successful_records:
            if record.average_speed <= 0:
                continue
            hour = datetime.fromtimestamp(record.timestamp).hour
            if hour not in hourly_speeds:
                hourly_speeds[hour] = []
            hourly_speeds[hour].append(record.average_speed)
        
        peak_performance_hour = None
        best_avg_speed = 0
        for hour, speeds_list in hourly_speeds.items():
            avg_speed = statistics.mean(speeds_list)
            if avg_speed > best_avg_speed:
                best_avg_speed = avg_speed
                peak_performance_hour = hour
        
        # Tendance de performance (simplifié)
        performance_trend = 'stable'
        if len(successful_records) >= 10:
            recent_records = successful_records[:5]  # 5 plus récents
            older_records = successful_records[-5:]  # 5 plus anciens
            
            recent_avg_speed = statistics.mean([r.average_speed for r in recent_records 
                                              if r.average_speed > 0])
            older_avg_speed = statistics.mean([r.average_speed for r in older_records 
                                             if r.average_speed > 0])
            
            if recent_avg_speed > older_avg_speed * 1.1:
                performance_trend = 'improving'
            elif recent_avg_speed < older_avg_speed * 0.9:
                performance_trend = 'declining'
        
        return {
            'average_transfer_time': average_transfer_time,
            'average_file_size': average_file_size,
            'network_efficiency': network_efficiency,
            'peak_performance_hour': peak_performance_hour,
            'performance_trend': performance_trend
        }
    
    def export_statistics(self, file_path: str, days: int = 30) -> bool:
        """Exporte les statistiques vers un fichier JSON."""
        try:
            export_data = {
                'export_info': {
                    'generated_at': datetime.now().isoformat(),
                    'period_days': days,
                    'datashare_version': '1.0'
                },
                'transfer_statistics': self.get_transfer_statistics(days),
                'device_statistics': [asdict(stats) for stats in self.get_device_statistics()],
                'network_usage_over_time': self.get_network_usage_over_time(days),
                'performance_metrics': self.get_performance_metrics(days),
                'transfer_history': [asdict(record) for record in self.get_transfer_history(days)]
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Statistiques exportées vers {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export : {e}")
            return False
    
    def cleanup_old_data(self, days_to_keep: int = None):
        """Nettoie les anciennes données."""
        if days_to_keep is None:
            days_to_keep = self.cleanup_days
        
        cutoff_time = time.time() - (days_to_keep * 24 * 3600)
        
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                # Nettoyer les transferts
                cursor = conn.execute("DELETE FROM transfers WHERE timestamp < ?", (cutoff_time,))
                transfers_deleted = cursor.rowcount
                
                # Nettoyer les sessions réseau
                cursor = conn.execute("DELETE FROM network_sessions WHERE start_time < ?", (cutoff_time,))
                sessions_deleted = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Nettoyage effectué : {transfers_deleted} transferts, "
                          f"{sessions_deleted} sessions supprimés")
                
            finally:
                conn.close()
        
        # Recharger les données en mémoire
        self._load_recent_data()
    
    def get_database_size(self) -> Dict[str, Any]:
        """Récupère les informations sur la taille de la base de données."""
        db_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
        
        with self.db_lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                # Compter les enregistrements
                cursor = conn.execute("SELECT COUNT(*) FROM transfers")
                total_transfers = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM device_stats")
                total_devices = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM network_sessions")
                total_sessions = cursor.fetchone()[0]
                
                return {
                    'database_size_bytes': db_size_bytes,
                    'database_size_mb': db_size_bytes / (1024 * 1024),
                    'total_transfer_records': total_transfers,
                    'total_device_records': total_devices,
                    'total_session_records': total_sessions
                }
                
            finally:
                conn.close()


def main():
    """Fonction de test et démonstration."""
    print("📊 GESTIONNAIRE DE STATISTIQUES DATASHARE")
    print("=" * 60)
    
    # Initialiser le gestionnaire
    stats_manager = StatisticsManager()
    
    print(f"✅ Gestionnaire initialisé")
    print(f"🗄️ Base de données : {stats_manager.db_path}")
    
    # Simuler quelques transferts pour les tests
    print(f"\n🧪 SIMULATION DE DONNÉES DE TEST :")
    
    import random
    
    # Créer quelques transferts fictifs
    test_devices = [
        ("device001", "Alice's Phone", "192.168.1.100"),
        ("device002", "Bob's Laptop", "192.168.1.101"), 
        ("device003", "Carol's Tablet", "192.168.1.102")
    ]
    
    for i in range(10):
        device_id, device_name, device_ip = random.choice(test_devices)
        
        # Enregistrer la connexion
        stats_manager.record_device_connection(device_id, device_name, device_ip)
        
        # Créer un transfert fictif
        transfer = TransferRecord(
            id=f"transfer_{i:03d}",
            timestamp=time.time() - random.randint(0, 7*24*3600),  # Derniers 7 jours
            direction=random.choice([TransferDirection.SENT, TransferDirection.RECEIVED]),
            status=TransferStatus.COMPLETED if random.random() > 0.1 else TransferStatus.FAILED,
            device_id=device_id,
            device_name=device_name,
            device_ip=device_ip,
            file_count=random.randint(1, 20),
            total_bytes=random.randint(1024*1024, 100*1024*1024),  # 1MB à 100MB
            duration=random.uniform(10, 300),  # 10s à 5min
            average_speed=random.uniform(1*1024*1024, 50*1024*1024),  # 1MB/s à 50MB/s
            error_message="",
            file_types=random.sample(['jpg', 'pdf', 'mp4', 'docx', 'zip'], random.randint(1, 3))
        )
        
        stats_manager.record_transfer(transfer)
    
    print(f"✅ {len(test_devices)} appareils et 10 transferts simulés")
    
    # Afficher les statistiques
    print(f"\n📈 STATISTIQUES DES TRANSFERTS (30 jours) :")
    transfer_stats = stats_manager.get_transfer_statistics(30)
    for key, value in transfer_stats.items():
        if isinstance(value, float):
            if 'speed' in key.lower() or 'bytes' in key.lower():
                if value > 1024*1024:
                    print(f"  {key} : {value/(1024*1024):.2f} MB/s" if 'speed' in key else f"{value/(1024*1024):.2f} MB")
                else:
                    print(f"  {key} : {value:.2f}")
            else:
                print(f"  {key} : {value:.2f}")
        elif isinstance(value, dict) and value:
            print(f"  {key} : {value}")
        elif value is not None:
            print(f"  {key} : {value}")
    
    print(f"\n📱 STATISTIQUES DES APPAREILS :")
    device_stats = stats_manager.get_device_statistics()
    for stats in device_stats:
        print(f"  {stats.device_name} ({stats.device_id[:8]}...) :")
        print(f"    Connexions : {stats.total_connections}")
        print(f"    Transferts réussis : {stats.successful_transfers}")
        print(f"    Données envoyées : {stats.total_bytes_sent/(1024*1024):.1f} MB")
        print(f"    Données reçues : {stats.total_bytes_received/(1024*1024):.1f} MB")
        print(f"    Vitesse moyenne : {stats.average_speed/(1024*1024):.1f} MB/s")
        print()
    
    print(f"\n⚡ MÉTRIQUES DE PERFORMANCE :")
    perf_metrics = stats_manager.get_performance_metrics(30)
    for key, value in perf_metrics.items():
        if isinstance(value, float):
            if 'size' in key.lower():
                print(f"  {key} : {value/(1024*1024):.2f} MB")
            elif 'time' in key.lower():
                print(f"  {key} : {value:.1f} secondes")
            else:
                print(f"  {key} : {value:.2f}")
        else:
            print(f"  {key} : {value}")
    
    # Informations sur la base de données
    print(f"\n🗄️ INFORMATIONS BASE DE DONNÉES :")
    db_info = stats_manager.get_database_size()
    for key, value in db_info.items():
        print(f"  {key} : {value}")
    
    print(f"\n✅ Test terminé")

if __name__ == "__main__":
    main()
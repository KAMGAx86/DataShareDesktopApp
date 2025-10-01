"""
Système de notifications pour DataShare

Ce module gère :
- Notifications système (Windows, Linux, macOS)
- Notifications dans l'application
- Sons d'alerte
- Historique des notifications
- Paramétrage des alertes

Auteur: DataShare Team
Version: 1.0
"""

import platform
import subprocess
import os
import threading
import time
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import json

logger = logging.getLogger(__name__)

class NotificationType(Enum):
    """Types de notifications."""
    DEVICE_DISCOVERED = "device_discovered"
    DEVICE_DISCONNECTED = "device_disconnected"
    TRANSFER_REQUEST = "transfer_request"
    TRANSFER_STARTED = "transfer_started"
    TRANSFER_COMPLETED = "transfer_completed"
    TRANSFER_FAILED = "transfer_failed"
    NETWORK_CREATED = "network_created"
    NETWORK_JOINED = "network_joined"
    NETWORK_ERROR = "network_error"
    SECURITY_ALERT = "security_alert"
    SYSTEM_INFO = "system_info"

class NotificationPriority(Enum):
    """Priorités des notifications."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class NotificationData:
    """Données d'une notification."""
    id: str
    type: NotificationType
    title: str
    message: str
    priority: NotificationPriority
    timestamp: float
    data: Dict[str, Any]
    shown: bool = False
    dismissed: bool = False
    action_taken: Optional[str] = None

class NotificationManager:
    """Gestionnaire principal des notifications."""
    
    def __init__(self, enable_system_notifications: bool = True):
        self.os_type = platform.system()
        self.enable_system_notifications = enable_system_notifications
        self.notifications: List[NotificationData] = []
        self.notification_callbacks: Dict[str, List[Callable]] = {}
        self.sound_enabled = True
        
        # Configuration des sons par type
        self.sound_files = {
            NotificationType.DEVICE_DISCOVERED: "device_found.wav",
            NotificationType.TRANSFER_REQUEST: "transfer_request.wav",
            NotificationType.TRANSFER_COMPLETED: "transfer_complete.wav",
            NotificationType.TRANSFER_FAILED: "error.wav",
            NotificationType.SECURITY_ALERT: "security_alert.wav"
        }
        
        # Messages par défaut
        self.default_messages = {
            NotificationType.DEVICE_DISCOVERED: {
                'title': '📱 Nouvel appareil',
                'message': '{device_name} est maintenant disponible'
            },
            NotificationType.DEVICE_DISCONNECTED: {
                'title': '📴 Appareil déconnecté', 
                'message': '{device_name} n\'est plus disponible'
            },
            NotificationType.TRANSFER_REQUEST: {
                'title': '📥 Demande de transfert',
                'message': '{sender_name} veut vous envoyer {file_count} fichier(s)'
            },
            NotificationType.TRANSFER_STARTED: {
                'title': '🚀 Transfert démarré',
                'message': 'Envoi vers {device_name} en cours'
            },
            NotificationType.TRANSFER_COMPLETED: {
                'title': '✅ Transfert terminé',
                'message': '{file_count} fichier(s) transféré(s) avec succès'
            },
            NotificationType.TRANSFER_FAILED: {
                'title': '❌ Transfert échoué',
                'message': 'Erreur lors du transfert : {error_message}'
            },
            NotificationType.NETWORK_CREATED: {
                'title': '🔥 Réseau créé',
                'message': 'Hotspot "{network_name}" actif'
            },
            NotificationType.NETWORK_ERROR: {
                'title': '⚠️ Erreur réseau',
                'message': 'Problème de connexion : {error_message}'
            },
            NotificationType.SECURITY_ALERT: {
                'title': '🔒 Alerte sécurité',
                'message': '{alert_message}'
            }
        }
        
        logger.info(f"NotificationManager initialisé sur {self.os_type}")
    
    def show_notification(self, 
                         notification_type: NotificationType,
                         data: Dict[str, Any] = None,
                         title: str = None,
                         message: str = None,
                         priority: NotificationPriority = NotificationPriority.NORMAL) -> str:
        """Affiche une notification."""
        
        # Générer un ID unique
        notification_id = f"{notification_type.value}_{int(time.time() * 1000)}"
        
        # Utiliser les messages par défaut si non spécifiés
        if title is None or message is None:
            default = self.default_messages.get(notification_type, {})
            if title is None:
                title = default.get('title', 'DataShare')
            if message is None:
                message = default.get('message', 'Nouvelle notification')
        
        # Formater les messages avec les données
        if data:
            try:
                title = title.format(**data)
                message = message.format(**data)
            except KeyError as e:
                logger.warning(f"Clé manquante pour le formatage : {e}")
        
        # Créer la notification
        notification = NotificationData(
            id=notification_id,
            type=notification_type,
            title=title,
            message=message,
            priority=priority,
            timestamp=time.time(),
            data=data or {}
        )
        
        # Ajouter à l'historique
        self.notifications.append(notification)
        
        # Limiter l'historique à 100 notifications
        if len(self.notifications) > 100:
            self.notifications.pop(0)
        
        # Afficher la notification
        self._display_notification(notification)
        
        # Jouer un son si activé
        if self.sound_enabled:
            self._play_notification_sound(notification_type)
        
        # Déclencher les callbacks
        self._trigger_callbacks(notification)
        
        logger.info(f"Notification affichée : {title}")
        return notification_id
    
    def _display_notification(self, notification: NotificationData):
        """Affiche la notification selon la plateforme."""
        if not self.enable_system_notifications:
            return
        
        try:
            if self.os_type == "Windows":
                self._show_windows_notification(notification)
            elif self.os_type == "Linux":
                self._show_linux_notification(notification)
            elif self.os_type == "Darwin":  # macOS
                self._show_macos_notification(notification)
            else:
                logger.warning(f"Notifications système non supportées sur {self.os_type}")
                
            notification.shown = True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage de la notification : {e}")
    
    def _show_windows_notification(self, notification: NotificationData):
        """Affiche une notification sur Windows."""
        try:
            # Méthode 1: Utiliser plyer (si disponible)
            try:
                from plyer import notification as plyer_notification
                plyer_notification.notify(
                    title=notification.title,
                    message=notification.message,
                    app_name="DataShare",
                    timeout=10
                )
                return
            except ImportError:
                pass
            
            # Méthode 2: Utiliser win10toast (si disponible)
            try:
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(
                    title=notification.title,
                    msg=notification.message,
                    icon_path=None,
                    duration=10,
                    threaded=True
                )
                return
            except ImportError:
                pass
            
            # Méthode 3: PowerShell (fallback)
            title_escaped = notification.title.replace('"', '""')
            message_escaped = notification.message.replace('"', '""')
            
            powershell_script = f'''
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

            $template = @"
            <toast>
                <visual>
                    <binding template="ToastText02">
                        <text id="1">{title_escaped}</text>
                        <text id="2">{message_escaped}</text>
                    </binding>
                </visual>
            </toast>
            "@

            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("DataShare").Show($toast)
            '''
            
            subprocess.run(['powershell', '-Command', powershell_script], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
            
        except Exception as e:
            logger.debug(f"Erreur notification Windows : {e}")
    
    def _show_linux_notification(self, notification: NotificationData):
        """Affiche une notification sur Linux."""
        try:
            # Méthode 1: notify-send (le plus commun)
            if self._command_exists('notify-send'):
                urgency = {
                    NotificationPriority.LOW: "low",
                    NotificationPriority.NORMAL: "normal", 
                    NotificationPriority.HIGH: "normal",
                    NotificationPriority.CRITICAL: "critical"
                }.get(notification.priority, "normal")
                
                cmd = [
                    'notify-send',
                    '--urgency', urgency,
                    '--expire-time', '10000',
                    '--app-name', 'DataShare',
                    notification.title,
                    notification.message
                ]
                
                subprocess.run(cmd, check=True)
                return
            
            # Méthode 2: kdialog (KDE)
            if self._command_exists('kdialog'):
                subprocess.run([
                    'kdialog',
                    '--title', 'DataShare',
                    '--passivepopup', f"{notification.title}\n{notification.message}",
                    '10'
                ])
                return
            
            # Méthode 3: zenity (GNOME)
            if self._command_exists('zenity'):
                subprocess.run([
                    'zenity',
                    '--notification',
                    '--text', f"{notification.title}\n{notification.message}"
                ])
                return
            
            logger.warning("Aucun système de notification trouvé sur Linux")
            
        except Exception as e:
            logger.debug(f"Erreur notification Linux : {e}")
    
    def _show_macos_notification(self, notification: NotificationData):
        """Affiche une notification sur macOS."""
        try:
            # Utiliser osascript
            script = f'''
            display notification "{notification.message}" with title "DataShare" subtitle "{notification.title}"
            '''
            
            subprocess.run(['osascript', '-e', script])
            
        except Exception as e:
            logger.debug(f"Erreur notification macOS : {e}")
    
    def _command_exists(self, command: str) -> bool:
        """Vérifie si une commande existe."""
        try:
            subprocess.run(['which', command], check=True, 
                         capture_output=True, text=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _play_notification_sound(self, notification_type: NotificationType):
        """Joue un son pour la notification."""
        if not self.sound_enabled:
            return
        
        sound_file = self.sound_files.get(notification_type)
        if not sound_file:
            return
        
        try:
            # Chercher le fichier son
            sound_path = self._find_sound_file(sound_file)
            if not sound_path:
                return
            
            # Jouer le son selon la plateforme
            if self.os_type == "Windows":
                import winsound
                winsound.PlaySound(sound_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
            elif self.os_type == "Linux":
                if self._command_exists('aplay'):
                    subprocess.run(['aplay', sound_path], 
                                 capture_output=True, check=False)
                elif self._command_exists('paplay'):
                    subprocess.run(['paplay', sound_path],
                                 capture_output=True, check=False)
            elif self.os_type == "Darwin":  # macOS
                subprocess.run(['afplay', sound_path],
                             capture_output=True, check=False)
                             
        except Exception as e:
            logger.debug(f"Erreur lors de la lecture du son : {e}")
    
    def _find_sound_file(self, filename: str) -> Optional[str]:
        """Trouve un fichier son dans les dossiers appropriés."""
        # Dossiers de recherche
        search_dirs = [
            os.path.join(os.path.dirname(__file__), "sounds"),
            os.path.join(os.path.dirname(__file__), "..", "resources", "sounds"),
            "/usr/share/sounds",  # Linux
            "/System/Library/Sounds"  # macOS
        ]
        
        for directory in search_dirs:
            if os.path.exists(directory):
                sound_path = os.path.join(directory, filename)
                if os.path.exists(sound_path):
                    return sound_path
        
        return None
    
    def _trigger_callbacks(self, notification: NotificationData):
        """Déclenche les callbacks pour cette notification."""
        callbacks = self.notification_callbacks.get(notification.type.value, [])
        
        for callback in callbacks:
            try:
                # Exécuter le callback dans un thread séparé
                thread = threading.Thread(
                    target=callback,
                    args=(notification,),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                logger.error(f"Erreur dans le callback de notification : {e}")
    
    def register_callback(self, notification_type: NotificationType, callback: Callable):
        """Enregistre un callback pour un type de notification."""
        if notification_type.value not in self.notification_callbacks:
            self.notification_callbacks[notification_type.value] = []
        
        self.notification_callbacks[notification_type.value].append(callback)
        logger.info(f"Callback enregistré pour {notification_type.value}")
    
    def unregister_callback(self, notification_type: NotificationType, callback: Callable):
        """Désenregistre un callback."""
        callbacks = self.notification_callbacks.get(notification_type.value, [])
        if callback in callbacks:
            callbacks.remove(callback)
            logger.info(f"Callback désenregistré pour {notification_type.value}")
    
    def get_recent_notifications(self, hours: int = 24) -> List[NotificationData]:
        """Récupère les notifications récentes."""
        cutoff_time = time.time() - (hours * 3600)
        return [n for n in self.notifications if n.timestamp > cutoff_time]
    
    def get_notifications_by_type(self, notification_type: NotificationType) -> List[NotificationData]:
        """Récupère les notifications par type."""
        return [n for n in self.notifications if n.type == notification_type]
    
    def mark_notification_dismissed(self, notification_id: str):
        """Marque une notification comme fermée."""
        for notification in self.notifications:
            if notification.id == notification_id:
                notification.dismissed = True
                logger.debug(f"Notification {notification_id} marquée comme fermée")
                break
    
    def clear_notifications(self, notification_type: Optional[NotificationType] = None):
        """Efface les notifications."""
        if notification_type:
            self.notifications = [n for n in self.notifications if n.type != notification_type]
            logger.info(f"Notifications de type {notification_type.value} effacées")
        else:
            self.notifications.clear()
            logger.info("Toutes les notifications effacées")
    
    def get_notification_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques des notifications."""
        stats = {
            'total_notifications': len(self.notifications),
            'shown_notifications': len([n for n in self.notifications if n.shown]),
            'dismissed_notifications': len([n for n in self.notifications if n.dismissed])
        }
        
        # Statistiques par type
        by_type = {}
        for notification in self.notifications:
            notification_type = notification.type.value
            if notification_type not in by_type:
                by_type[notification_type] = 0
            by_type[notification_type] += 1
        
        stats['by_type'] = by_type
        
        # Notifications récentes (24h)
        recent = self.get_recent_notifications(24)
        stats['recent_24h'] = len(recent)
        
        return stats
    
    def set_sound_enabled(self, enabled: bool):
        """Active ou désactive les sons."""
        self.sound_enabled = enabled
        logger.info(f"Sons de notification {'activés' if enabled else 'désactivés'}")
    
    def set_system_notifications_enabled(self, enabled: bool):
        """Active ou désactive les notifications système."""
        self.enable_system_notifications = enabled
        logger.info(f"Notifications système {'activées' if enabled else 'désactivées'}")


# Fonctions utilitaires pour les notifications communes
class DataShareNotifications:
    """Raccourcis pour les notifications DataShare communes."""
    
    def __init__(self, notification_manager: NotificationManager):
        self.nm = notification_manager
    
    def device_discovered(self, device_name: str, device_ip: str):
        """Notification d'appareil découvert."""
        self.nm.show_notification(
            NotificationType.DEVICE_DISCOVERED,
            data={'device_name': device_name, 'device_ip': device_ip},
            priority=NotificationPriority.LOW
        )
    
    def device_disconnected(self, device_name: str):
        """Notification d'appareil déconnecté."""
        self.nm.show_notification(
            NotificationType.DEVICE_DISCONNECTED,
            data={'device_name': device_name},
            priority=NotificationPriority.LOW
        )
    
    def transfer_request_received(self, sender_name: str, file_count: int, total_size: str):
        """Notification de demande de transfert."""
        self.nm.show_notification(
            NotificationType.TRANSFER_REQUEST,
            data={
                'sender_name': sender_name,
                'file_count': file_count,
                'total_size': total_size
            },
            priority=NotificationPriority.HIGH
        )
    
    def transfer_completed(self, file_count: int, device_name: str, direction: str):
        """Notification de transfert terminé."""
        title = "✅ Envoi terminé" if direction == "sent" else "✅ Réception terminée"
        message = f"{file_count} fichier(s) transféré(s)"
        if device_name:
            message += f" {'vers' if direction == 'sent' else 'depuis'} {device_name}"
        
        self.nm.show_notification(
            NotificationType.TRANSFER_COMPLETED,
            data={
                'file_count': file_count,
                'device_name': device_name,
                'direction': direction
            },
            title=title,
            message=message,
            priority=NotificationPriority.NORMAL
        )
    
    def transfer_failed(self, error_message: str, device_name: str = ""):
        """Notification d'échec de transfert."""
        self.nm.show_notification(
            NotificationType.TRANSFER_FAILED,
            data={
                'error_message': error_message,
                'device_name': device_name
            },
            priority=NotificationPriority.HIGH
        )
    
    def network_created(self, network_name: str, password: str = ""):
        """Notification de création de réseau."""
        message = f'Hotspot "{network_name}" créé et actif'
        if password:
            message += f"\nMot de passe : {password}"
        
        self.nm.show_notification(
            NotificationType.NETWORK_CREATED,
            data={'network_name': network_name, 'password': password},
            message=message,
            priority=NotificationPriority.NORMAL
        )
    
    def network_error(self, error_message: str):
        """Notification d'erreur réseau."""
        self.nm.show_notification(
            NotificationType.NETWORK_ERROR,
            data={'error_message': error_message},
            priority=NotificationPriority.HIGH
        )
    
    def security_alert(self, alert_message: str):
        """Notification d'alerte sécurité."""
        self.nm.show_notification(
            NotificationType.SECURITY_ALERT,
            data={'alert_message': alert_message},
            priority=NotificationPriority.CRITICAL
        )


# Instance globale
_notification_manager = None
_datashare_notifications = None

def get_notification_manager() -> NotificationManager:
    """Récupère l'instance globale du gestionnaire de notifications."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager

def get_datashare_notifications() -> DataShareNotifications:
    """Récupère l'instance globale des notifications DataShare."""
    global _datashare_notifications
    if _datashare_notifications is None:
        nm = get_notification_manager()
        _datashare_notifications = DataShareNotifications(nm)
    return _datashare_notifications


def main():
    """Fonction de test et démonstration."""
    print("🔔 SYSTÈME DE NOTIFICATIONS DATASHARE")
    print("=" * 50)
    
    # Initialiser le gestionnaire
    nm = NotificationManager()
    ds_notifications = DataShareNotifications(nm)
    
    print(f"✅ Gestionnaire initialisé sur {nm.os_type}")
    print(f"🔊 Sons activés : {nm.sound_enabled}")
    print(f"💻 Notifications système : {nm.enable_system_notifications}")
    
    # Test des différents types de notifications
    print("\n🧪 TEST DES NOTIFICATIONS :")
    
    # Appareil découvert
    ds_notifications.device_discovered("Alice's Phone", "192.168.1.100")
    time.sleep(2)
    
    # Demande de transfert
    ds_notifications.transfer_request_received("Alice", 5, "15.2 MB")
    time.sleep(2)
    
    # Transfert terminé
    ds_notifications.transfer_completed(5, "Alice's Phone", "received")
    time.sleep(2)
    
    # Réseau créé
    ds_notifications.network_created("DataShare-Alice", "12345678")
    time.sleep(2)
    
    # Erreur
    ds_notifications.transfer_failed("Connexion perdue", "Bob's Laptop")
    
    # Attendre un peu puis afficher les statistiques
    time.sleep(3)
    
    print("\n📊 STATISTIQUES DES NOTIFICATIONS :")
    stats = nm.get_notification_statistics()
    for key, value in stats.items():
        print(f"  {key} : {value}")
    
    print(f"\n📋 NOTIFICATIONS RÉCENTES (24h) :")
    recent = nm.get_recent_notifications(24)
    for notification in recent[-5:]:  # Afficher les 5 dernières
        timestamp = datetime.fromtimestamp(notification.timestamp)
        print(f"  {timestamp.strftime('%H:%M:%S')} - {notification.title} : {notification.message}")
    
    print(f"\n✅ Test terminé - {len(nm.notifications)} notifications générées")

if __name__ == "__main__":
    main()
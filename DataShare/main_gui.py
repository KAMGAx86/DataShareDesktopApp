import flet as ft
import logging
import threading
import time
from datetime import datetime
from typing import Optional, List

# Import DataShare Core
from DataShareCore import DataShareCore
from scan_network import DeviceInfo
from updater import DataShareUpdater
import ctypes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DataShareGUI")

class DataShareApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "DataShare Pro"
        self.page.window_icon = "logo.svg"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.padding = 0
        self.page.window_min_width = 800
        self.page.window_min_height = 600
        
        # Initialize Core
        self.core = DataShareCore()
        self.core_started = False
        self.updater = DataShareUpdater("6.0.0", "http://localhost:8000/update.json") # URL par défaut
        
        # UI State
        self.current_view = "dashboard"
        self.selected_nav_index = 0
        self.selected_files = []
        self.discovered_devices = []
        self.active_transfers = {} # Map transfer_id to transfer object
        
        # File Picker
        self.file_picker = ft.FilePicker(on_result=self.on_file_picked)
        self.page.overlay.append(self.file_picker)
        
        # Drag & Drop
        self.page.on_file_drop = self._on_file_drop
        
        # Setup UI
        self.setup_ui()
        
        # Start Core in background
        self.start_core_service()

    def start_core_service(self):
        """Start DataShare Core services in a separate thread to avoid blocking UI"""
        def _start():
            try:
                # Setup Callbacks BEFORE starting services
                self.core.on_device_discovered = self.on_device_discovered_callback
                self.core.on_device_lost = self.on_device_lost_callback
                self.core.on_transfer_progress = self.on_transfer_progress_callback
                self.core.on_transfer_request = self.on_transfer_request_callback
                
                success = self.core.start_services()
                if success:
                    self.core_started = True
                    self.show_snack("Services DataShare démarrés avec succès", ft.Colors.GREEN)
                    self.update_dashboard_stats()
                    self.refresh_devices()
                else:
                    self.show_snack("Erreur lors du démarrage des services", ft.Colors.RED)
            except Exception as e:
                logger.error(f"Error starting core: {e}")
                self.show_snack(f"Erreur critique: {e}", ft.Colors.RED)
        
        threading.Thread(target=_start, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # CALLBACKS (Backend -> UI)
    # ══════════════════════════════════════════════════════════════════════════
    
    def on_device_discovered_callback(self, device):
        """Called when a new device is found"""
        logger.info(f"UI Callback: Device found {device.hostname}")
        self.refresh_devices()

    def on_device_lost_callback(self, device_key):
        """Called when a device is lost"""
        logger.info(f"UI Callback: Device lost {device_key}")
        self.refresh_devices()

    def on_transfer_progress_callback(self, transfer_job):
        """Called on transfer progress"""
        # Update local state
        self.active_transfers[transfer_job.transfer_id] = transfer_job
        
        # If we are on Receive or Send view, update UI
        if self.selected_nav_index in [1, 2]:
            self.page.run_task(self.update_transfer_ui)

    def on_transfer_request_callback(self, transfer_job):
        """Called when receiving a file request"""
        def _show_dialog():
            dlg = ft.AlertDialog(
                title=ft.Text("Demande de transfert"),
                content=ft.Text(f"{transfer_job.remote_name} veut vous envoyer {len(transfer_job.files)} fichier(s).\nTotal: {self.core._format_size(transfer_job.total_size)}"),
                actions=[
                    ft.TextButton("Refuser", on_click=lambda e: self.reject_transfer(transfer_job.transfer_id, dlg)),
                    ft.TextButton("Accepter", on_click=lambda e: self.accept_transfer(transfer_job.transfer_id, dlg)),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            self.page.dialog = dlg
            dlg.open = True
            self.page.update()
        
        self.page.run_task(_show_dialog)

    def accept_transfer(self, transfer_id, dlg):
        self.core.accept_transfer(transfer_id)
        dlg.open = False
        self.page.update()
        self.show_snack("Transfert accepté", ft.Colors.GREEN)
        # Switch to receive view
        self.rail.selected_index = 2
        self.nav_change(None)

    def reject_transfer(self, transfer_id, dlg):
        self.core.reject_transfer(transfer_id)
        dlg.open = False
        self.page.update()
        self.show_snack("Transfert refusé", ft.Colors.RED)

    async def update_transfer_ui(self):
        """Updates the UI for active transfers"""
        if self.selected_nav_index == 2: # Receive View
            self.content_area.content = self.build_receive_view()
            self.content_area.update()
        elif self.selected_nav_index == 1: # Send View (optional, maybe show progress bar here too)
            pass 

    # ══════════════════════════════════════════════════════════════════════════
    # UI SETUP
    # ══════════════════════════════════════════════════════════════════════════

    def setup_ui(self):
        # Navigation Rail
        self.rail = ft.NavigationRail(
            selected_index=0,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=100,
            min_extended_width=200,
            group_alignment=-0.9,
            leading=ft.Container(
                content=ft.Icon(ft.Icons.SHARE, size=40, color=ft.Colors.BLUE),
                padding=10
            ),
            destinations=[
                ft.NavigationRailDestination(
                    icon=ft.Icons.DASHBOARD_OUTLINED,
                    selected_icon=ft.Icons.DASHBOARD,
                    label="Tableau de bord",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icons.SEND_OUTLINED,
                    selected_icon=ft.Icons.SEND,
                    label="Envoyer",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icons.DOWNLOAD_OUTLINED,
                    selected_icon=ft.Icons.DOWNLOAD,
                    label="Recevoir",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icons.SETTINGS_OUTLINED,
                    selected_icon=ft.Icons.SETTINGS,
                    label="Paramètres",
                ),
            ],
            on_change=self.nav_change,
        )

        # Content Area
        self.content_area = ft.Container(
            expand=True,
            padding=20,
            content=self.build_dashboard_view()
        )

        # Main Layout
        self.page.add(
            ft.Row(
                [
                    self.rail,
                    ft.VerticalDivider(width=1),
                    self.content_area,
                ],
                expand=True,
            )
        )

    def nav_change(self, e):
        # Handle event or manual call (e is None if manual)
        index = e.control.selected_index if e else self.rail.selected_index
        self.selected_nav_index = index
        
        if index == 0:
            self.content_area.content = self.build_dashboard_view()
        elif index == 1:
            self.content_area.content = self.build_send_view()
        elif index == 2:
            self.content_area.content = self.build_receive_view()
        elif index == 3:
            self.content_area.content = self.build_settings_view()
        
        self.content_area.update()

    # ══════════════════════════════════════════════════════════════════════════
    # VIEWS
    # ══════════════════════════════════════════════════════════════════════════

    def build_dashboard_view(self):
        # Get basic info
        app_info = self.core.get_application_info()
        user_profile = app_info['user_profile']
        network_status = app_info['network_status']
        
        # Get Recent Activity
        stats = self.core.get_transfer_statistics(days=7)
        recent_transfers = stats.get('recent_transfers', []) # Assuming this exists or we fetch from history
        
        # Build Activity List
        activity_list = ft.Column(spacing=10)
        if recent_transfers:
            for t in recent_transfers[:5]: # Show last 5
                icon = ft.Icons.UPLOAD if t['direction'] == 'sent' else ft.Icons.DOWNLOAD
                color = ft.Colors.BLUE if t['direction'] == 'sent' else ft.Colors.GREEN
                activity_list.controls.append(
                    ft.ListTile(
                        leading=ft.Icon(icon, color=color),
                        title=ft.Text(f"{t['device_name']}"),
                        subtitle=ft.Text(f"{datetime.fromtimestamp(t['timestamp']).strftime('%H:%M')} - {self.core._format_size(t['total_bytes'])}"),
                        trailing=ft.Text(t['status'], color=ft.Colors.GREY)
                    )
                )
        else:
            activity_list.controls.append(ft.Text("Aucune activité récente", italic=True, color=ft.Colors.GREY))

        return ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Row([
                    ft.Icon(ft.Icons.SHARE, size=50, color=ft.Colors.BLUE),
                    ft.Text("Tableau de bord", size=32, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Divider(),
                
                # Welcome Section
                ft.Container(
                    padding=20,
                    bgcolor=ft.Colors.BLUE_GREY_900,
                    border_radius=10,
                    content=ft.Row([
                        ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=50),
                        ft.Column([
                            ft.Text(f"Bonjour, {user_profile.get('username', 'Utilisateur')}", size=20, weight=ft.FontWeight.BOLD),
                            ft.Text(f"ID: {user_profile.get('user_id', 'N/A')}", size=12, color=ft.Colors.GREY),
                        ])
                    ])
                ),
                
                ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
                
                # Status Cards
                ft.Row([
                    self.build_stat_card(
                        "Statut Réseau", 
                        "Actif" if network_status.get('hotspot_active') or network_status.get('wifi_direct_available') else "Inactif",
                        ft.Icons.WIFI,
                        ft.Colors.GREEN if network_status.get('hotspot_active') else ft.Colors.ORANGE
                    ),
                    self.build_stat_card(
                        "Appareils Découverts", 
                        str(len(self.discovered_devices)),
                        ft.Icons.DEVICES,
                        ft.Colors.BLUE
                    ),
                    self.build_stat_card(
                        "Fichiers Reçus", 
                        str(user_profile.get('total_files_received', 0)),
                        ft.Icons.DOWNLOAD_DONE,
                        ft.Colors.PURPLE
                    ),
                ]),
                
                ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
                
                ft.Text("Activité Récente", size=20, weight=ft.FontWeight.BOLD),
                ft.Container(
                    padding=10,
                    border=ft.border.all(1, ft.Colors.GREY),
                    border_radius=10,
                    content=activity_list
                )
            ]
        )

    def build_stat_card(self, title, value, icon, color):
        return ft.Container(
            expand=True,
            padding=20,
            bgcolor=ft.Colors.BLUE_GREY_900,
            border_radius=10,
            content=ft.Column([
                ft.Icon(icon, color=color, size=30),
                ft.Text(value, size=24, weight=ft.FontWeight.BOLD),
                ft.Text(title, size=14, color=ft.Colors.GREY),
            ])
        )

    def build_send_view(self):
        # File List
        files_list = ft.Column(spacing=10)
        if self.selected_files:
            for f in self.selected_files:
                files_list.controls.append(
                    ft.Container(
                        padding=10,
                        bgcolor=ft.Colors.BLUE_GREY_900,
                        border_radius=5,
                        content=ft.Row([
                            ft.Icon(ft.Icons.INSERT_DRIVE_FILE),
                            ft.Text(f.name, expand=True),
                            ft.IconButton(ft.Icons.DELETE, icon_color=ft.Colors.RED, 
                                        on_click=lambda _, f=f: self.remove_file(f))
                        ])
                    )
                )
        else:
            files_list.controls.append(ft.Text("Aucun fichier sélectionné", italic=True))

        # Device List
        devices_list = ft.Column(spacing=10)
        if self.discovered_devices:
            for device in self.discovered_devices:
                devices_list.controls.append(
                    ft.Container(
                        padding=15,
                        bgcolor=ft.Colors.BLUE_GREY_900,
                        border_radius=10,
                        on_click=lambda _, d=device: self.send_to_device(d),
                        content=ft.Row([
                            ft.Icon(ft.Icons.COMPUTER),
                            ft.Column([
                                ft.Text(device.hostname, weight=ft.FontWeight.BOLD),
                                ft.Text(device.ip_address, size=12, color=ft.Colors.GREY),
                            ], expand=True),
                            ft.Icon(ft.Icons.SEND, color=ft.Colors.BLUE)
                        ])
                    )
                )
        else:
            devices_list.controls.append(ft.Text("Aucun appareil détecté", italic=True))

        return ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Text("Envoyer des fichiers", size=32, weight=ft.FontWeight.BOLD),
                ft.Divider(),
                
                ft.Text("1. Sélectionner des fichiers", size=20, weight=ft.FontWeight.BOLD),
                ft.ElevatedButton("Ajouter des fichiers", icon=ft.Icons.ADD, 
                                on_click=lambda _: self.file_picker.pick_files(allow_multiple=True)),
                ft.Container(content=files_list, padding=10),
                
                ft.Divider(),
                
                ft.Row([
                    ft.Text("2. Choisir un destinataire", size=20, weight=ft.FontWeight.BOLD),
                    ft.IconButton(ft.Icons.REFRESH, on_click=lambda _: self.refresh_devices())
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                
                ft.Container(content=devices_list, padding=10),
                
                ft.Divider(),
                
                ft.Text("3. Sécurité (Optionnel)", size=20, weight=ft.FontWeight.BOLD),
                self.build_pin_input(),
            ]
        )

    def build_pin_input(self):
        self.send_pin_input = ft.TextField(
            label="Code PIN (si l'autre appareil le demande)", 
            password=True, 
            can_reveal_password=True,
            icon=ft.Icons.LOCK,
            width=300
        )
        return self.send_pin_input

    def on_file_picked(self, e: ft.FilePickerResultEvent):
        if e.files:
            self.selected_files.extend(e.files)
            if self.selected_nav_index == 1:
                self.content_area.content = self.build_send_view()
                self.content_area.update()

    def _on_file_drop(self, e):
        """Gère le glisser-déposer de fichiers"""
        if not e.files:
            return
            
        self.selected_files.extend(e.files)
        
        if self.selected_nav_index == 1:
            # Si on est déjà sur l'écran d'envoi, rafraîchir
            self.content_area.content = self.build_send_view()
            self.content_area.update()
            self.show_snack(f"{len(e.files)} fichiers ajoutés", ft.Colors.GREEN)
        else:
            # Sinon, notifier l'utilisateur
            self.show_snack(f"{len(e.files)} fichiers ajoutés. Allez dans 'Envoyer'.", ft.Colors.BLUE)

    def remove_file(self, file_obj):
        self.selected_files.remove(file_obj)
        if self.selected_nav_index == 1:
            self.content_area.content = self.build_send_view()
            self.content_area.update()

    def send_to_device(self, device):
        if not self.selected_files:
            self.show_snack("Veuillez sélectionner des fichiers d'abord", ft.Colors.RED)
            return
            
        file_paths = [f.path for f in self.selected_files]
        
        def _send():
            pin = self.send_pin_input.value if hasattr(self, 'send_pin_input') else ""
            transfer_id = self.core.send_files_to_device(device.ip_address, file_paths, pin=pin)
            if transfer_id:
                self.show_snack(f"Transfert démarré vers {device.hostname}", ft.Colors.GREEN)
                self.selected_files.clear()
                # Switch to receive view to see progress
                self.rail.selected_index = 2
                self.page.run_task(lambda: self.nav_change(None))
            else:
                self.show_snack("Échec du démarrage du transfert", ft.Colors.RED)
        
        threading.Thread(target=_send).start()

    def build_receive_view(self):
        # Active Transfers (fetch from core + local state)
        active_transfers = self.core.get_active_transfers()
        
        transfers_list = ft.Column(spacing=10)
        if active_transfers:
            for t in active_transfers:
                transfers_list.controls.append(
                    ft.Container(
                        padding=10,
                        bgcolor=ft.Colors.BLUE_GREY_900,
                        border_radius=5,
                        content=ft.Column([
                            ft.Row([
                                ft.Text(f"{t.direction.upper()} - {t.remote_name}", weight=ft.FontWeight.BOLD),
                                ft.Text(f"{t.progress:.1f}%")
                            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.ProgressBar(value=t.progress / 100, color=ft.Colors.BLUE if t.direction == 'sent' else ft.Colors.GREEN),
                            ft.Row([
                                ft.Text(f"{t.speed:.1f} MB/s", size=12, color=ft.Colors.GREY),
                                ft.Text(f"ETA: {t.eta}s", size=12, color=ft.Colors.GREY)
                            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
                        ])
                    )
                )
        else:
            transfers_list.controls.append(ft.Text("Aucun transfert actif", italic=True))

        return ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Text("Réception & Transferts", size=32, weight=ft.FontWeight.BOLD),
                ft.Divider(),
                ft.ElevatedButton("Actualiser", icon=ft.Icons.REFRESH, 
                                on_click=lambda _: self.content_area.update()),
                ft.Container(content=transfers_list, padding=10)
            ]
        )

    def build_settings_view(self):
        settings = self.core.settings
        
        self.username_field = ft.TextField(label="Nom d'utilisateur", value=settings.user_profile.username)
        self.enable_pin_switch = ft.Switch(label="Activer la protection par PIN (Réception)", value=settings.security_settings.enable_pin)
        self.pin_field = ft.TextField(
            label="Votre Code PIN", 
            value=settings.security_settings.pin_code, 
            password=True, 
            can_reveal_password=True,
            helper_text="Communiquez ce code à l'expéditeur"
        )
        
        def save_settings_click(e):
            self.core.update_user_profile(username=self.username_field.value)
            self.core.update_security_settings(
                enable_pin=self.enable_pin_switch.value,
                pin_code=self.pin_field.value
            )
            self.show_snack("Paramètres sauvegardés", ft.Colors.GREEN)

        return ft.Column(
            scroll=ft.ScrollMode.AUTO,
            controls=[
                ft.Text("Paramètres", size=32, weight=ft.FontWeight.BOLD),
                ft.Divider(),
                
                ft.Text("Profil", size=20, weight=ft.FontWeight.BOLD),
                self.username_field,
                
                ft.Divider(),
                
                ft.Text("Stockage", size=20, weight=ft.FontWeight.BOLD),
                ft.TextField(label="Dossier de téléchargement", value=settings.storage_settings.default_download_folder, read_only=True),
                
                ft.Divider(),
                
                ft.Text("Sécurité", size=20, weight=ft.FontWeight.BOLD),
                self.enable_pin_switch,
                self.pin_field,
                
                ft.Divider(),
                
                ft.Text("Interface", size=20, weight=ft.FontWeight.BOLD),
                ft.Switch(label="Notifications", value=settings.interface_settings.show_notifications),
                
                ft.Divider(),
                ft.Text("Mises à jour", size=20, weight=ft.FontWeight.BOLD),
                ft.ElevatedButton("Rechercher des mises à jour", icon=ft.Icons.SYSTEM_UPDATE, on_click=self.check_update_click),

                ft.ElevatedButton("Sauvegarder", icon=ft.Icons.SAVE, on_click=save_settings_click)
            ]
        )

    def check_update_click(self, e):
        """Vérifie les mises à jour"""
        self.show_snack("Recherche de mises à jour...", ft.Colors.BLUE)
        update_info = self.updater.check_for_updates()
        if update_info:
            def dl_update(e):
                self.show_snack("Téléchargement...", ft.Colors.BLUE)
                if self.updater.download_update(update_info['download_url'], "update.exe"):
                    self.updater.apply_update("update.exe")
                    self.page.window_close()
                else:
                    self.show_snack("Erreur de téléchargement", ft.Colors.RED)
            
            self.page.dialog = ft.AlertDialog(
                title=ft.Text("Mise à jour disponible"),
                content=ft.Text(f"Version {update_info['version']} disponible.\n{update_info.get('release_notes', '')}"),
                actions=[
                    ft.TextButton("Télécharger & Installer", on_click=dl_update),
                    ft.TextButton("Annuler", on_click=lambda e: setattr(self.page.dialog, 'open', False) or self.page.update())
                ]
            )
            self.page.dialog.open = True
            self.page.update()
        else:
            self.show_snack("Aucune mise à jour détectée", ft.Colors.GREEN)

    def refresh_devices(self):
        self.discovered_devices = self.core.get_available_devices()
        # Only update UI if we are on a relevant page to avoid flickering/state loss
        if self.selected_nav_index == 1:
            self.page.run_task(lambda: self.content_area.content.controls[-1].content.update()) # Hacky update of device list container? Better to rebuild view.
            self.content_area.content = self.build_send_view()
            self.content_area.update()
        elif self.selected_nav_index == 0:
            self.content_area.content = self.build_dashboard_view()
            self.content_area.update()

    def update_dashboard_stats(self):
        if self.selected_nav_index == 0:
            self.content_area.content = self.build_dashboard_view()
            self.content_area.update()

    def show_snack(self, message, color=ft.Colors.WHITE):
        self.page.snack_bar = ft.SnackBar(content=ft.Text(message), bgcolor=color)
        self.page.snack_bar.open = True
        self.page.update()

    def on_close(self, e):
        self.core.stop_services()
        self.page.window_destroy()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main(page: ft.Page):
    # Check for admin rights
    if not is_admin():
        def close_app(e):
            page.window_destroy()

        page.dialog = ft.AlertDialog(
            title=ft.Text("Droits d'administrateur requis"),
            content=ft.Text("Cette application nécessite des privilèges d'administrateur pour gérer le Hotspot Wi-Fi et le pare-feu.\n\nVeuillez relancer l'application en tant qu'administrateur."),
            actions=[
                ft.TextButton("Quitter", on_click=close_app),
            ],
            modal=True,
        )
        page.dialog.open = True
        page.update()
        # We still let the app load but the dialog blocks interaction
    
    app = DataShareApp(page)

if __name__ == "__main__":
    ft.app(target=main, assets_dir="assets")

import threading
import customtkinter as ctk
from tkinter import messagebox
import os
import socket
from core.send_and_receive import Receive
from core.config import MANAGER, HOSTNAME
from core.state_manager import State
from core.discovery import Phare  # ✅ AJOUT


class TransferPage(ctk.CTkFrame):
    def __init__(self, parent, on_back_callback, port=32000, password=None):
        super().__init__(parent, fg_color="#1a2332")
        self.server_thread = None
        self.server = None
        self.phare = None  # ✅ AJOUT
        self.phare_thread = None  # ✅ AJOUT
        self.parent = parent
        self.on_back_callback = on_back_callback
        self.pack(fill="both", expand=True)

        # Couleurs
        self.bg_color = "#1a2332"
        self.card_color = "#1f2937"
        self.accent_color = "#3b82f6"
        self.success_color = "#10b981"
        self.warning_color = "#f59e0b"
        self.danger_color = "#ef4444"

        # Variables
        self.is_active = True
        self.pending_transfer = None

        self.port = port
        self.password = password

        # Outils de synchronisation
        self.user_response_event = threading.Event()
        self.user_decision = False

        # Obtenir l'IP locale
        self.local_ip = self.get_local_ip()

        self.create_header()
        self.create_beacon_status()
        self.create_footer()

    def get_local_ip(self):
        """Récupère l'adresse IP locale"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def start_server(self):
        """Lance le serveur Receive ET le Phare dans des threads"""
        # ✅ 1. Changer l'état global
        MANAGER.set_state(State.READY)

        # ✅ 2. Démarrer le Phare (annonce sur le réseau)
        self.phare = Phare()
        self.phare_thread = threading.Thread(target=self.phare.shouting, daemon=True)
        self.phare_thread.start()
        print("[TransferPage] Phare démarré - Diffusion de la présence")

        # ✅ 3. Démarrer le serveur de réception
        self.server = Receive(
            PORT=self.port,
            PASSWORD=self.password,
            ui_callback_request=self.handle_connection_request,
            ui_callback_progress=self.handle_progress,
            ui_callback_complete=self.handle_transfer_complete
        )

        self.server_thread = threading.Thread(target=self.server.receive_file, daemon=True)
        self.server_thread.start()
        print("[TransferPage] Serveur de réception démarré")

        self.animate_beacon()

    # --- CALLBACK 1 : DEMANDE DE CONNEXION ---
    def handle_connection_request(self, file_name, file_size, sender_ip):
        """Appelé par le backend quand quelqu'un veut envoyer un fichier"""
        self.user_response_event.clear()
        self.user_decision = False

        self.after(0, lambda: self.show_transfer_confirmation(
            HOSTNAME, sender_ip, file_name, f"{file_size / 1024 / 1024:.2f} MB"
        ))

        print("[UI] En attente de la décision utilisateur...")
        self.user_response_event.wait()

        return self.user_decision

    def handle_progress(self, current, total):
        """Appelé en continu pendant le transfert"""
        self.after(0, lambda: self.update_progress_ui(current, total))

    def handle_transfer_complete(self, file_name):
        self.after(0, lambda: self.show_transfer_complete(file_name))

    def create_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=40, pady=20)

        back_button = ctk.CTkButton(
            header_frame,
            text="← Retour",
            width=120,
            height=40,
            font=ctk.CTkFont(size=14),
            fg_color="transparent",
            hover_color=self.card_color,
            border_color="#374151",
            border_width=2,
            command=self.go_back
        )
        back_button.pack(side="left")

        logo_label = ctk.CTkLabel(
            header_frame,
            text="DATASHARE",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="white"
        )
        logo_label.pack(side="left", padx=20)

        version_label = ctk.CTkLabel(
            header_frame,
            text="V1",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.accent_color
        )
        version_label.pack(side="left")

    def create_beacon_status(self):
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(expand=True, fill="both", padx=40, pady=20)

        status_card = ctk.CTkFrame(
            main_container,
            fg_color=self.card_color,
            corner_radius=15,
            width=600,
            height=500
        )
        status_card.place(relx=0.5, rely=0.5, anchor="center")

        content_frame = ctk.CTkFrame(status_card, fg_color="transparent")
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        self.beacon_indicator = ctk.CTkLabel(
            content_frame,
            text="●",
            font=ctk.CTkFont(size=80),
            text_color=self.success_color
        )
        self.beacon_indicator.pack(pady=(0, 20))

        self.status_title = ctk.CTkLabel(
            content_frame,
            text="Phare Activé",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="white"
        )
        self.status_title.pack(pady=(0, 10))

        self.status_subtitle = ctk.CTkLabel(
            content_frame,
            text="En attente de connexion...",
            font=ctk.CTkFont(size=16),
            text_color="#9ca3af"
        )
        self.status_subtitle.pack(pady=(0, 30))

        info_frame = ctk.CTkFrame(content_frame, fg_color="#0f1419", corner_radius=10)
        info_frame.pack(pady=(0, 30), padx=40, fill="x")

        info_items = [
            ("Appareil", HOSTNAME),
            ("Adresse IP", self.local_ip),
            ("Port", str(self.port)),
            ("Statut", "Visible sur le réseau")
        ]

        for label, value in info_items:
            item_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=8)

            ctk.CTkLabel(
                item_frame,
                text=label + " :",
                font=ctk.CTkFont(size=13),
                text_color="#6b7280"
            ).pack(side="left")

            ctk.CTkLabel(
                item_frame,
                text=value,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="white"
            ).pack(side="right")

        self.deactivate_button = ctk.CTkButton(
            content_frame,
            text="Désactiver le Phare",
            width=200,
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=self.danger_color,
            hover_color="#dc2626",
            corner_radius=8,
            command=self.deactivate_beacon
        )
        self.deactivate_button.pack()

        self.animate_beacon()

    def animate_beacon(self):
        """Animation du point lumineux du phare"""
        if self.is_active:
            current_color = self.beacon_indicator.cget("text_color")
            if current_color == self.success_color:
                self.beacon_indicator.configure(text_color="#065f46")
            else:
                self.beacon_indicator.configure(text_color=self.success_color)
            self.after(800, self.animate_beacon)

    def show_transfer_confirmation(self, sender_name, sender_ip, file_name, file_size):
        """Affiche la boîte de dialogue de confirmation de transfert"""
        confirmation_window = ctk.CTkToplevel(self)
        confirmation_window.title("Demande de Transfert")
        confirmation_window.geometry("500x500")
        confirmation_window.configure(fg_color=self.bg_color)
        confirmation_window.resizable(False, False)

        confirmation_window.transient(self)
        confirmation_window.grab_set()

        icon_label = ctk.CTkLabel(
            confirmation_window,
            text="⚠️",
            font=ctk.CTkFont(size=60)
        )
        icon_label.pack(pady=(30, 20))

        title_label = ctk.CTkLabel(
            confirmation_window,
            text="Demande de Transfert Entrante",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="white"
        )
        title_label.pack(pady=(0, 20))

        info_frame = ctk.CTkFrame(confirmation_window, fg_color=self.card_color, corner_radius=10)
        info_frame.pack(padx=40, pady=(0, 10), fill="x")

        transfer_info = [
            ("Expéditeur", sender_name),
            ("Adresse IP", sender_ip),
            ("Fichier", file_name),
            ("Taille", file_size)
        ]

        for label, value in transfer_info:
            item_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=8)

            ctk.CTkLabel(
                item_frame,
                text=label + " :",
                font=ctk.CTkFont(size=13),
                text_color="#9ca3af"
            ).pack(side="left")

            ctk.CTkLabel(
                item_frame,
                text=value,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="white"
            ).pack(side="right")

        warning_label = ctk.CTkLabel(
            confirmation_window,
            text="Acceptez-vous ce transfert ?",
            font=ctk.CTkFont(size=14),
            text_color="#9ca3af"
        )
        warning_label.pack(pady=(10, 30))

        buttons_frame = ctk.CTkFrame(confirmation_window, fg_color="transparent")
        buttons_frame.pack(pady=(0, 30))

        refuse_button = ctk.CTkButton(
            buttons_frame,
            text="Refuser",
            width=150,
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="transparent",
            hover_color=self.card_color,
            border_color=self.danger_color,
            border_width=2,
            text_color=self.danger_color,
            corner_radius=8,
            command=lambda: self.refuse_transfer(confirmation_window, file_name)
        )
        refuse_button.pack(side="left", padx=10)

        accept_button = ctk.CTkButton(
            buttons_frame,
            text="Accepter",
            width=150,
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=self.success_color,
            hover_color="#059669",
            corner_radius=8,
            command=lambda: self.accept_transfer(confirmation_window, file_name, file_size)
        )
        accept_button.pack(side="left", padx=10)

    def refuse_transfer(self, window, file_name):
        """Refuse le transfert"""
        window.destroy()
        self.user_decision = False
        self.user_response_event.set()

    def accept_transfer(self, window, file_name, file_size):
        """Accepte le transfert et lance le téléchargement"""
        window.destroy()
        self.create_progress_window(file_name)
        self.user_decision = True
        self.user_response_event.set()

    def show_transfer_complete(self, file_name):
        """Affiche le message de transfert terminé"""
        success_window = ctk.CTkToplevel(self)
        success_window.title("Transfert Terminé")
        success_window.geometry("450x300")
        success_window.configure(fg_color=self.bg_color)
        success_window.resizable(False, False)

        success_window.transient(self)
        success_window.grab_set()

        icon_label = ctk.CTkLabel(
            success_window,
            text="✅",
            font=ctk.CTkFont(size=60)
        )
        icon_label.pack(pady=(30, 20))

        title_label = ctk.CTkLabel(
            success_window,
            text="Transfert Réussi !",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.success_color
        )
        title_label.pack(pady=(0, 10))

        message_label = ctk.CTkLabel(
            success_window,
            text=f"Le fichier '{file_name}' a été reçu avec succès.",
            font=ctk.CTkFont(size=14),
            text_color="#9ca3af",
            wraplength=380
        )
        message_label.pack(pady=(0, 30))

        buttons_frame = ctk.CTkFrame(success_window, fg_color="transparent")
        buttons_frame.pack()

        open_button = ctk.CTkButton(
            buttons_frame,
            text="Ouvrir le Dossier",
            width=180,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=self.accent_color,
            hover_color="#2563eb",
            corner_radius=8,
            command=lambda: self.open_download_folder(success_window)
        )
        open_button.pack(side="left", padx=10)

        close_button = ctk.CTkButton(
            buttons_frame,
            text="Fermer",
            width=120,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="transparent",
            hover_color=self.card_color,
            border_color="#374151",
            border_width=2,
            corner_radius=8,
            command=success_window.destroy
        )
        close_button.pack(side="left", padx=10)

    def open_download_folder(self, window):
        """Ouvre le dossier de téléchargement"""
        window.destroy()
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")

        import platform
        import subprocess

        if platform.system() == "Windows":
            os.startfile(downloads_path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.Popen(["open", downloads_path])
        else:  # Linux
            subprocess.Popen(["xdg-open", downloads_path])

    def go_back(self):
        """Retour à l'accueil avec nettoyage"""
        self.deactivate_beacon()

    def deactivate_beacon(self):
        """Désactive le phare"""
        self.is_active = False

        # ✅ Arrêter le Phare
        print("[TransferPage] Arrêt du Phare...")
        MANAGER.set_state(State.OFFLINE)

        # Attendre un peu que le thread du Phare se termine
        if self.phare_thread and self.phare_thread.is_alive():
            self.phare_thread.join(timeout=3)

        # ✅ Arrêter le serveur
        if self.server:
            self.server.stop()

        self.on_back_callback()

    def create_footer(self):
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.pack(side="bottom", pady=20)

        footer_label = ctk.CTkLabel(
            footer_frame,
            text=f"Hôte local : {HOSTNAME} | Port : {self.port}",
            font=ctk.CTkFont(size=14),
            text_color="#6b7280"
        )
        footer_label.pack()

    def create_progress_window(self, file_name):
        """Crée juste la fenêtre, sans la boucle de simulation"""
        self.progress_window = ctk.CTkToplevel(self)
        self.progress_window.title("Transfert en cours")
        self.progress_window.geometry("500x300")
        self.progress_window.transient(self)
        self.progress_window.grab_set()

        ctk.CTkLabel(
            self.progress_window,
            text="Réception en cours...",
            font=("Arial", 20, "bold")
        ).pack(pady=20)

        self.progress_bar = ctk.CTkProgressBar(self.progress_window, width=400)
        self.progress_bar.pack(pady=20)
        self.progress_bar.set(0)

        self.lbl_progress_text = ctk.CTkLabel(self.progress_window, text="0%")
        self.lbl_progress_text.pack()

    def update_progress_ui(self, current, total):
        """Met à jour la barre créée ci-dessus"""
        if hasattr(self, 'progress_window') and self.progress_window.winfo_exists():
            ratio = current / total
            self.progress_bar.set(ratio)
            self.lbl_progress_text.configure(
                text=f"{int(ratio * 100)}% - {current / 1024 / 1024:.1f} MB"
            )

            if current >= total:
                self.progress_window.destroy()
import time

import customtkinter as ctk
from tkinter import filedialog, messagebox
import socket
import threading
import os

from core.discovery import Scanner
from core.send_and_receive import Send


class SendPage(ctk.CTkFrame):
    def __init__(self, parent, return_callback):
        super().__init__(parent, fg_color="#1a2332")
        self.p_bar = None
        self.progress_win = None
        self.return_callback = return_callback
        self.scanning = False
        self.discovered_devices = []
        self.selected_file = None
        self.scanner = Scanner()

        self.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        # En-tête avec bouton retour
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=40, pady=(20, 0))

        return_btn = ctk.CTkButton(
            header_frame,
            text="← Retour",
            font=("Arial", 14),
            fg_color="#2d3748",
            hover_color="#374151",
            width=120,
            height=40,
            command=self.go_back
        )
        return_btn.pack(side="left")

        # Logo
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(pady=(20, 10))

        logo_label = ctk.CTkLabel(
            logo_frame,
            text="DATASHARE",
            font=("Arial", 32, "bold"),
            text_color="white"
        )
        logo_label.pack(side="left")

        v1_label = ctk.CTkLabel(
            logo_frame,
            text="V1",
            font=("Arial", 32, "bold"),
            text_color="#3b82f6"
        )
        v1_label.pack(side="left")

        # Titre et description
        title_label = ctk.CTkLabel(
            self,
            text="Envoyer des fichiers",
            font=("Arial", 28, "bold"),
            text_color="white"
        )
        title_label.pack(pady=(30, 5))

        desc_label = ctk.CTkLabel(
            self,
            text="Sélectionnez un fichier et choisissez un appareil",
            font=("Arial", 14),
            text_color="#94a3b8"
        )
        desc_label.pack(pady=(0, 30))

        # Container principal
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=40, pady=20)

        # Section gauche - Sélection de fichier
        left_frame = ctk.CTkFrame(main_container, fg_color="#0f1419", corner_radius=15)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        file_title = ctk.CTkLabel(
            left_frame,
            text="Fichier à envoyer",
            font=("Arial", 18, "bold"),
            text_color="white"
        )
        file_title.pack(pady=(20, 15))

        # Zone de fichier sélectionné
        self.file_frame = ctk.CTkFrame(left_frame, fg_color="#1a2332", corner_radius=10)
        self.file_frame.pack(fill="x", padx=20, pady=10)

        self.file_label = ctk.CTkLabel(
            self.file_frame,
            text="Aucun fichier sélectionné",
            font=("Arial", 14),
            text_color="#64748b"
        )
        self.file_label.pack(pady=30)

        # Bouton sélectionner fichier
        select_file_btn = ctk.CTkButton(
            left_frame,
            text="📁 Sélectionner un fichier",
            font=("Arial", 16, "bold"),
            fg_color="#3b82f6",
            hover_color="#2563eb",
            height=50,
            corner_radius=10,
            command=self.select_file
        )
        select_file_btn.pack(pady=20, padx=20, fill="x")

        # Info fichier
        self.file_info_label = ctk.CTkLabel(
            left_frame,
            text="",
            font=("Arial", 12),
            text_color="#64748b"
        )
        self.file_info_label.pack(pady=(0, 20))

        # Section droite - Liste des appareils
        right_frame = ctk.CTkFrame(main_container, fg_color="#0f1419", corner_radius=15)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))

        devices_header = ctk.CTkFrame(right_frame, fg_color="transparent")
        devices_header.pack(fill="x", padx=20, pady=(20, 10))

        devices_title = ctk.CTkLabel(
            devices_header,
            text="Appareils disponibles",
            font=("Arial", 18, "bold"),
            text_color="white"
        )
        devices_title.pack(side="left")

        # Bouton scanner
        self.scan_btn = ctk.CTkButton(
            devices_header,
            text="🔍 Scanner",
            font=("Arial", 14, "bold"),
            fg_color="#10b981",
            hover_color="#059669",
            width=120,
            height=35,
            corner_radius=8,
            command=self.start_scan
        )
        self.scan_btn.pack(side="right")

        # Frame scrollable pour les appareils
        self.devices_scroll = ctk.CTkScrollableFrame(
            right_frame,
            fg_color="#1a2332",
            corner_radius=10
        )
        self.devices_scroll.pack(fill="both", expand=True, padx=20, pady=(10, 20))

        # Message initial
        self.no_devices_label = ctk.CTkLabel(
            self.devices_scroll,
            text="Cliquez sur 'Scanner' pour découvrir des appareils",
            font=("Arial", 14),
            text_color="#64748b"
        )
        self.no_devices_label.pack(pady=50)

        # Informations de l'hôte local
        local_info = ctk.CTkLabel(
            self,
            text=f"Hôte local : {socket.gethostname()}",
            font=("Arial", 12),
            text_color="#475569"
        )
        local_info.pack(side="bottom", pady=10)

    def select_file(self):
        """Ouvre le dialogue de sélection de fichier"""
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier à envoyer",
            filetypes=[("Tous les fichiers", "*.*")]
        )

        if filename:
            self.selected_file = filename
            basename = os.path.basename(filename)
            filesize = os.path.getsize(filename)

            # Formater la taille
            if filesize < 1024:
                size_str = f"{filesize} B"
            elif filesize < 1024 * 1024:
                size_str = f"{filesize / 1024:.1f} KB"
            else:
                size_str = f"{filesize / (1024 * 1024):.1f} MB"

            self.file_label.configure(
                text=f"📄 {basename}",
                text_color="white"
            )
            self.file_info_label.configure(
                text=f"Taille : {size_str}"
            )

    def start_scan(self):
        """Lance le scan du réseau"""
        if self.scanning:
            return

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Recherche...")

        # Lancer l'écoute dans un thread pour ne pas bloquer l'UI
        thread = threading.Thread(
            target=self.scanner.listening,
            args=(self.on_devices_found,),
            daemon=True
        )
        thread.start()

    def update_devices_list(self):
        """Met à jour la liste des appareils découverts"""
        # Effacer tous les widgets
        for widget in self.devices_scroll.winfo_children():
            widget.destroy()

        if not self.discovered_devices:
            self.no_devices_label = ctk.CTkLabel(
                self.devices_scroll,
                text="Aucun appareil trouvé sur le réseau",
                font=("Arial", 14),
                text_color="#64748b"
            )
            self.no_devices_label.pack(pady=50)
        else:
            for device in self.discovered_devices:
                self.create_device_card(device)

        self.scanning = False
        self.scan_btn.configure(state="normal", text="🔍 Scanner")

    def create_device_card(self, device):
        """Crée une carte pour chaque appareil découvert"""
        card = ctk.CTkFrame(
            self.devices_scroll,
            fg_color="#0f1419",
            corner_radius=10,
            border_width=2,
            border_color="#2d3748"
        )
        card.pack(fill="x", pady=8, padx=5)

        # Container principal
        card_content = ctk.CTkFrame(card, fg_color="transparent")
        card_content.pack(fill="x", padx=15, pady=12)

        # Colonne gauche - Icône et info
        left_section = ctk.CTkFrame(card_content, fg_color="transparent")
        left_section.pack(side="left", fill="x", expand=True)

        # Indicateur de statut
        status_color = "#10b981" if device["online"] else "#64748b"
        status_indicator = ctk.CTkLabel(
            left_section,
            text="●",
            font=("Arial", 24),
            text_color=status_color
        )
        status_indicator.pack(side="left", padx=(0, 10))

        # Info appareil
        info_frame = ctk.CTkFrame(left_section, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)

        name_label = ctk.CTkLabel(
            info_frame,
            text=device["name"],
            font=("Arial", 16, "bold"),
            text_color="white",
            anchor="w"
        )
        name_label.pack(anchor="w")

        ip_label = ctk.CTkLabel(
            info_frame,
            text=f"IP : {device['ip']}",
            font=("Arial", 12),
            text_color="#94a3b8",
            anchor="w"
        )
        ip_label.pack(anchor="w")

        port_label = ctk.CTkLabel(
            info_frame,
            text=f"Port : {device['port']}",
            font=("Arial", 12),
            text_color="#94a3b8",
            anchor="w"
        )
        port_label.pack(anchor="w")

        # Bouton envoyer
        send_btn = ctk.CTkButton(
            card_content,
            text="📤 Envoyer",
            font=("Arial", 14, "bold"),
            fg_color="#3b82f6",
            hover_color="#2563eb",
            width=120,
            height=40,
            corner_radius=8,
            command=lambda d=device: self.send_file_to_device(d)
        )
        send_btn.pack(side="right", padx=(10, 0))

        if not device["online"]:
            send_btn.configure(state="disabled", fg_color="#374151")

    def send_file_to_device(self, device):
        """Envoie le fichier sélectionné à l'appareil"""
        if not self.selected_file:
            messagebox.showerror("Erreur", "Veuillez d'abord sélectionner un fichier")
            return

        # Demander le mot de passe
        password = ctk.CTkInputDialog(
            text="Entrez le mot de passe du destinataire:",
            title="Sécurité"
        ).get_input()

        if not password:
            return

        # Création d'une fenêtre de progression
        self.progress_win = ctk.CTkToplevel(self)
        self.progress_win.title("Transfert en cours")
        self.progress_win.geometry("400x200")
        self.progress_win.attributes("-topmost", True)

        lbl = ctk.CTkLabel(
            self.progress_win,
            text=f"Envoi vers {device['name']}",
            font=("Arial", 14, "bold")
        )
        lbl.pack(pady=20)

        self.p_bar = ctk.CTkProgressBar(self.progress_win, width=300)
        self.p_bar.pack(pady=10)
        self.p_bar.set(0)

        # Fonction de transfert
        def run_transfer():
            sender = Send(
                IP=device['ip'],
                PORT=device['port'],
                file_path=self.selected_file,
                PASSWORD=password,
                progress_callback=self.update_ui
            )
            success, msg = sender.send_file()

            # Fermer la popup
            if self.progress_win and self.progress_win.winfo_exists():
                self.after(0, self.progress_win.destroy)

            if success:
                self.after(0, lambda: messagebox.showinfo(
                    "Succès",
                    f"Fichier '{os.path.basename(self.selected_file)}' envoyé avec succès !"
                ))
            else:
                self.after(0, lambda: messagebox.showerror(
                    "Erreur",
                    f"Échec de l'envoi : {msg}"
                ))

        threading.Thread(target=run_transfer, daemon=True).start()

    def on_devices_found(self, devices_tuple_list):
        """Callback appelé par le Scanner"""
        formatted_devices = []
        for ip, info in devices_tuple_list:
            formatted_devices.append({
                "name": info['pc'],
                "ip": ip,
                "port": info['port'],
                "online": info['status'] == "READY"
            })

        self.discovered_devices = formatted_devices
        self.after(0,
                   self.update_devices_list)

    def update_ui(self, current, total):
        """Met à jour la barre de progression"""
        if self.p_bar and self.progress_win and self.progress_win.winfo_exists():
            percent = current / total
            self.after(0, lambda: self.p_bar.set(percent))

    def go_back(self):
        """Retour à l'accueil avec nettoyage"""
        # Arrêter le scanner
        if self.scanner:
            self.scanner.running = False

        self.return_callback()
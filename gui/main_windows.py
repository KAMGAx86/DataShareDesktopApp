import socket
import customtkinter as ctk
from tkinter import messagebox
from core.discovery import Phare
from core.state_manager import State
from core.config import MANAGER
from core.send_and_receive import Receive
import threading


class DataShareApp(ctk.CTkFrame):  # ✅ CORRECTION : Hérite de CTkFrame, pas CTk
    def __init__(self, parent, on_receive_click, on_send_click):
        super().__init__(parent, fg_color="#1a2332")
        self.pack(fill="both", expand=True)  # ✅ AJOUT : Pack le frame

        # Callbacks
        self.on_receive_click = on_receive_click
        self.on_send_click = on_send_click

        # Connexion au backend
        self.phare_thread = None
        self.receiver_thread = None
        self.receiver = None
        self.password_entry = None
        self.activate_button = None
        self.mode_label = None
        self.mode_indicator = None
        self.phare = Phare()

        # nom de l'ordinateur
        self.hostname = socket.gethostname()

        # Couleurs personnalisées
        self.bg_color = "#1a2332"
        self.card_color = "#1f2937"
        self.accent_color = "#3b82f6"

        # En-tête avec logo et mode
        self.create_header()

        # Titre principal
        self.create_title()

        # Conteneur pour les deux cartes
        self.create_cards()

        # Pied de page avec l'hôte local
        self.create_footer()

    def create_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=40, pady=20)

        # Logo
        logo_label = ctk.CTkLabel(
            header_frame,
            text="DATASHARE",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="white"
        )
        logo_label.pack(side="left")

        version_label = ctk.CTkLabel(
            header_frame,
            text="V1",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.accent_color
        )
        version_label.pack(side="left")

        # Mode hors ligne
        mode_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        mode_frame.pack(side="right")

        self.mode_indicator = ctk.CTkLabel(
            mode_frame,
            text="●",
            font=ctk.CTkFont(size=16),
            text_color="#6b7280"
        )
        self.mode_indicator.pack(side="left", padx=(0, 5))

        self.mode_label = ctk.CTkLabel(
            mode_frame,
            text="Mode Hors-ligne",
            font=ctk.CTkFont(size=14),
            text_color="#9ca3af"
        )
        self.mode_label.pack(side="left")

    def create_title(self):
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(pady=(20, 10))

        title = ctk.CTkLabel(
            title_frame,
            text="Que souhaitez-vous faire ?",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color="white"
        )
        title.pack()

        subtitle = ctk.CTkLabel(
            title_frame,
            text="Partage de fichiers sécurisé sur réseau local",
            font=ctk.CTkFont(size=16),
            text_color="#9ca3af"
        )
        subtitle.pack(pady=(5, 0))

    def create_cards(self):
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.pack(expand=True, fill="both", padx=40, pady=30)

        # Configuration de la grille
        cards_frame.grid_columnconfigure(0, weight=1)
        cards_frame.grid_columnconfigure(1, weight=1)
        cards_frame.grid_rowconfigure(0, weight=1)

        # Carte Recevoir
        self.create_receive_card(cards_frame)

        # Carte Envoyer
        self.create_send_card(cards_frame)

    def create_receive_card(self, parent):
        receive_card = ctk.CTkFrame(
            parent,
            fg_color=self.card_color,
            corner_radius=15
        )
        receive_card.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")

        # Effet de survol
        receive_card.bind("<Enter>", lambda e: self.on_card_hover(receive_card, True))
        receive_card.bind("<Leave>", lambda e: self.on_card_hover(receive_card, False))

        # Contenu centré
        content_frame = ctk.CTkFrame(receive_card, fg_color="transparent")
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Icône (simulée avec un emoji/texte)
        icon_label = ctk.CTkLabel(
            content_frame,
            text="📥",
            font=ctk.CTkFont(size=60)
        )
        icon_label.pack(pady=(0, 20))

        # Titre
        title = ctk.CTkLabel(
            content_frame,
            text="Recevoir",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="white"
        )
        title.pack(pady=(0, 15))

        # Description
        description = ctk.CTkLabel(
            content_frame,
            text="Devenir visible sur le réseau et attendre un transfert.",
            font=ctk.CTkFont(size=14),
            text_color="#9ca3af",
            wraplength=400
        )
        description.pack(pady=(0, 25))

        # Label mot de passe
        password_label = ctk.CTkLabel(
            content_frame,
            text="Mot de passe de réception :",
            font=ctk.CTkFont(size=13),
            text_color=self.accent_color
        )
        password_label.pack(anchor="w", pady=(0, 8))

        # Champ mot de passe
        self.password_entry = ctk.CTkEntry(
            content_frame,
            width=350,
            height=45,
            placeholder_text="Ex: 123456",
            font=ctk.CTkFont(size=14),
            fg_color="#0f1419",
            border_color="#374151",
            border_width=1
        )
        self.password_entry.pack(pady=(0, 30))

        # Bouton
        self.activate_button = ctk.CTkButton(
            content_frame,
            text="Activer le Phare",
            width=200,
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=self.accent_color,
            hover_color="#2563eb",
            corner_radius=8,
            command=self.activate_beacon
        )
        self.activate_button.pack()

    def create_send_card(self, parent):
        send_card = ctk.CTkFrame(
            parent,
            fg_color=self.card_color,
            corner_radius=15
        )
        send_card.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")

        # Effet de survol
        send_card.bind("<Enter>", lambda e: self.on_card_hover(send_card, True))
        send_card.bind("<Leave>", lambda e: self.on_card_hover(send_card, False))

        # Contenu centré
        content_frame = ctk.CTkFrame(send_card, fg_color="transparent")
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Icône
        icon_label = ctk.CTkLabel(
            content_frame,
            text="📡",
            font=ctk.CTkFont(size=60)
        )
        icon_label.pack(pady=(0, 20))

        # Titre
        title = ctk.CTkLabel(
            content_frame,
            text="Envoyer",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="white"
        )
        title.pack(pady=(0, 15))

        # Description
        description = ctk.CTkLabel(
            content_frame,
            text="Scanner le réseau pour trouver des appareils disponibles.",
            font=ctk.CTkFont(size=14),
            text_color="#9ca3af",
            wraplength=400
        )
        description.pack(pady=(0, 80))

        # Bouton
        scan_button = ctk.CTkButton(
            content_frame,
            text="Lancer le Scanner",
            width=200,
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="transparent",
            hover_color="#1f2937",
            border_color=self.accent_color,
            border_width=2,
            corner_radius=8,
            command=self.launch_scanner
        )
        scan_button.pack()

    def create_footer(self):
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.pack(side="bottom", pady=20)

        footer_label = ctk.CTkLabel(
            footer_frame,
            text=f"Hôte local : {self.hostname}",
            font=ctk.CTkFont(size=14),
            text_color="#6b7280"
        )
        footer_label.pack()

    def on_card_hover(self, card, is_hovering):
        """Effet de survol pour les cartes"""
        if is_hovering:
            card.configure(fg_color="#2d3748")
        else:
            card.configure(fg_color=self.card_color)

    def activate_beacon(self):
        """Modifié pour naviguer vers la page de réception"""
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("Attention", "Veuillez définir un mot de passe.")
            self.password_entry.configure(border_color="red")
            return

        # ✅ Réinitialiser la bordure si OK
        self.password_entry.configure(border_color="#374151")

        # ✅ Navigation vers la page de réception
        self.on_receive_click(port=32000, password=password)

    def launch_scanner(self):
        """Modifié pour naviguer vers la page d'envoi"""
        self.on_send_click()


# Test standalone (optionnel)
if __name__ == "__main__":
    def test_receive(port, password):
        print(f"[TEST] Navigation vers Receive - Port: {port}, Password: {password}")


    def test_send():
        print("[TEST] Navigation vers Send")


    app = ctk.CTk()
    app.title("Test DataShare")
    app.geometry("1400x750")
    ctk.set_appearance_mode("dark")

    home = DataShareApp(app, on_receive_click=test_receive, on_send_click=test_send)
    app.mainloop()
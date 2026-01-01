import customtkinter as ctk
from gui.main_windows import DataShareApp
from gui.receive_page import TransferPage
from gui.send_page import SendPage
from core.config import MANAGER
from core.state_manager import State


class AppController(ctk.CTk):
    """Contrôleur principal de l'application"""

    def __init__(self):
        super().__init__()

        self.title("DataShare V1")
        self.geometry("1400x750")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Container pour les pages
        self.current_page = None

        # Afficher la page d'accueil
        self.show_home()

    def clear_page(self):
        """Nettoie la page actuelle"""
        if self.current_page:
            self.current_page.pack_forget()
            self.current_page.destroy()
            self.current_page = None

    def show_home(self):
        """Affiche la page d'accueil"""
        self.clear_page()

        # On crée un Frame qui contient DataShareApp
        self.current_page = ctk.CTkFrame(self, fg_color="transparent")
        self.current_page.pack(fill="both", expand=True)

        # Injecter les callbacks
        home = DataShareApp(
            self.current_page,
            on_receive_click=self.show_receive_page,
            on_send_click=self.show_send_page
        )

    def show_receive_page(self, port, password):
        """Affiche la page de réception"""
        self.clear_page()
        self.current_page = TransferPage(
            self,
            on_back_callback=self.show_home,
            port=port,
            password=password
        )
        # Démarrer le serveur
        self.current_page.start_server()

    def show_send_page(self):
        """Affiche la page d'envoi"""
        self.clear_page()
        self.current_page = SendPage(self, return_callback=self.show_home)


if __name__ == "__main__":
    app = AppController()
    app.mainloop()
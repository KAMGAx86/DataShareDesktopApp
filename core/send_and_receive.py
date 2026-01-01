import socket #pour le reseaux
import os #pour la tailles des fichiers
import struct # pour le pre-header ( la taille de l'entete)
import  hashlib #pour l'integrite
import logging #pour les message d'erreur et de succes
import json# pour convertir les dict en json
import shutil# pour verifier l'espace disponible
from .state_manager import StateManager,State
from .config import MANAGER

#configuration pour afficher les log dans le terminal
logging.basicConfig(
    level=logging.INFO, # pour le terminal
    format= '%(asctime)s - %(levelname)s - %(message)s'
)


def dict_to_json_bytes(data: dict) -> bytes:
        
    #serialisation en json
    json_string: str = json.dumps(data, ensure_ascii=False)
        
    #encodage en UTF-8 (transformation en bytes/octets)
    json_bytes: bytes = json_string.encode('utf-8')
        
    return json_bytes

class Send:
    """_summary_: envoie de fichier
    """
    def __init__(self,IP: str,PORT: int,file_path: str,PASSWORD: str,progress_callback=None):
        self.sock: socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # creation du socket pour des ipv4 et utilisation du protocole TCP
        self.server_ip: str = IP
        self.server_port: int = PORT
        self.FILE_SIZE: int = os.path.getsize(filename=file_path)#taille du fichier en octet
        self.FILE_NAME: str = os.path.basename(file_path)
        self.FILE_PATH: str = file_path 
        self.HASH_SIZE: int = 64
        self.PASSWORD = PASSWORD
        self.NONCE : bytes
        self.SIGNATURE : str
        self.progress_callback = progress_callback # fonction UI appeler

    def send_file(self):
        try:
            self.sock.connect((self.server_ip, self.server_port))

            # 1. Authentification (Nonce + Signature)
            nonce = self.sock.recv(32)
            signature = hashlib.sha256(self.PASSWORD.encode() + nonce).hexdigest()

            header = dict_to_json_bytes({
                'password': signature,
                'file_name': self.FILE_NAME,
                'file_size': self.FILE_SIZE,
                'hash_size': 64,
            })

            self.sock.sendall(struct.pack('>I', len(header)))
            self.sock.sendall(header)

            # 2. Réponse du serveur
            response = self.sock.recv(2).decode('utf-8')

            if response == 'OK':
                sha256 = hashlib.sha256()
                cumul_envoye = 0

                with open(self.FILE_PATH, 'rb') as f:
                    while True:
                        # On utilise des morceaux de 64Ko pour une barre de progression fluide
                        chunk = f.read(64 * 1024)
                        if not chunk: break

                        sha256.update(chunk)
                        self.sock.sendall(chunk)

                        cumul_envoye += len(chunk)
                        if self.progress_callback:
                            # On informe l'interface
                            self.progress_callback(cumul_envoye, self.FILE_SIZE)

                # 3. Signature finale
                self.sock.sendall(sha256.hexdigest().encode('utf-8'))
                return True, "Succès"
            else:
                return False, f"Refusé par le serveur ({response})"

        except Exception as e:
            return False, str(e)
        finally:
            self.sock.close()
                
                

def receive_exact_data(client_sock: socket,data_length: int) -> bytes:
    """
    Reçoit exactement data_length octets depuis la socket.
    Retourne les données reçues, ou pas de donnee si la connexion est fermée.
    
    Args:
        client_sock (socket)
        data_length (int)
    """
    
    receive_data: bytes = b"" # Accumulateur pour les donnees
    remaining_length: int = data_length
    
    while remaining_length > 0:
        #Recoit au plus remaining_length octets
        chunk: bytes = client_sock.recv(remaining_length)
        
        if not chunk:
            logging.warning("connexion interrompue brutalement")
            return b""
        
        receive_data +=chunk
        remaining_length -= len(chunk)
        
    return receive_data

                
class Receive:
    def __init__(self,PORT: int,PASSWORD: str,ui_callback_request=None,ui_callback_progress=None,ui_callback_complete=None):
        self.sock: socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # creation du socket pour des ipv4 et utilisation du protocole TCP
        self.ip: str = '0.0.0.0'
        self.port = PORT
        self.PASSWORD = PASSWORD
        self.state_manager = MANAGER   # permet de gerer les etats     
        try:
            self.sock.bind((self.ip, self.port))
            self.sock.listen()
            logging.info(f"Serveur en attente sur {self.ip}:{self.port}")
        except Exception as e:
            logging.error(f"Erreur bind: {e}")

        # Les fonction que l'interface va nous donner
        self.ui_callback_request = ui_callback_request
        self.ui_callback_progress = ui_callback_progress
        self.ui_callback_complete = ui_callback_complete

        self.running = True
        
    def stop(self):
        """Arrete le serveur proprement"""
        self.running = False
        try:
            self.sock.close()
        except:
            pass

        # Helper pour remplacer ton receive_to_file et gérer la barre de progression
    def receive_to_file_with_callback(self, client_socket, data_length, file_name):
            received = 0
            file_path = os.path.join(os.path.expanduser("~"), "Downloads", file_name)
            hasher = hashlib.sha256()

            try:
                with open(file_path, 'wb') as f:
                    while received < data_length:
                        chunk = client_socket.recv(4096)
                        if not chunk: break
                        f.write(chunk)
                        hasher.update(chunk)
                        received += len(chunk)

                        # ✅ Mise à jour plus fluide (tous les 2 chunks = 20KB)
                        if self.ui_callback_progress and received % (4096 * 5) == 0:
                            self.ui_callback_progress(received, data_length)

                return True, hasher.hexdigest()
            except Exception as e:
                print(e)
                return False, None


    def receive_file(self):
        
        nonce: bytes
        try:
            while self.running:
                # On met un timeout pour vérifier self.running régulièrement
                self.sock.settimeout(1.0)
                try:
                    client_sock, addr = self.sock.accept()
                except socket.timeout:
                    continue  # On boucle pour revérifier self.running
                except OSError:
                    break  # Socket fermée

                # Une fois connecté, on remet le socket en mode bloquant standard
                client_sock.settimeout(None)
                try:
                    self.state_manager.set_state(State.BUSY) # passer en mode occuper lors d'une reception
                    nonce = os.urandom(32)
                    client_sock.sendall(nonce)
                    
                    PRE_HEADER: bytes =receive_exact_data(client_sock,4)
                    
                    HEARDER_SIZE: int = struct.unpack('>I',PRE_HEADER)[0]
                    
                    logging.info(f"talle de l'en-tete {HEARDER_SIZE}")
                    
                    HEADER: bytes = receive_exact_data(client_sock,HEARDER_SIZE)
                    
                    JSON: json = HEADER.decode()
                    
                    HEADER_dict: dict = json.loads(JSON)
                    
                    signature_attentue: str = hashlib.sha256(self.PASSWORD.encode()  + nonce).hexdigest()# la signature pour verificatrion
                    
                    #verifier le mot de passe
                    if HEADER_dict['password'] != signature_attentue:
                        client_sock.sendall(b'AU')
                        client_sock.close()
                        continue
                    
                    # Récupère le chemin du dossier Downloads de l'utilisateur
                    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
                    
                    # verification de l'espace disque
                    total: int; used: int; free: int; total, used, free= shutil.disk_usage(downloads_path)
                    
                    if HEADER_dict['file_size'] > free:
                        client_sock.sendall(b"SP")
                        client_sock.close()
                        continue

                    if self.ui_callback_request:
                        # On appelle la fonction de l'UI et on attend la réponse (True/False)
                        user_accepted = self.ui_callback_request(
                            HEADER_dict['file_name'],
                            HEADER_dict['file_size'],
                            addr[0]  # IP de l'envoyeur
                        )

                        if not user_accepted:
                            logging.info("Transfert refusé par l'utilisateur.")
                            client_sock.sendall(b"NO")  # Code pour refus
                            client_sock.close()
                            continue
                    
                    client_sock.sendall(b"OK")
                    
                    success, hash_integrity = self.receive_to_file_with_callback(client_socket=client_sock,data_length=HEADER_dict['file_size'],file_name=HEADER_dict['file_name'])
                    
                    if success:
                        # Verification du hash...
                        hash = receive_exact_data(client_sock,HEADER_dict['hash_size']).decode('utf-8')
                        if hash_integrity == hash:
                            logging.info(f"Envoie reussie de {HEADER_dict['file_size']}")
                            if self.ui_callback_complete:
                                self.ui_callback_complete(HEADER_dict['file_name'])
                        else:
                            logging.error("Erreur Hash")

                    client_sock.close()
                    self.state_manager.set_state(State.READY)

                except Exception as e:
                    # Si n'importe quoi plante avec CE client, on logue l'erreur
                    logging.error(f"Erreur lors du traitement du client : {e}")
                    if client_sock: client_sock.close()
                    self.state_manager.set_state(State.READY)

        except Exception as e:
            logging.info(f"Erreur  serveur: {e}")
                
             
        



# --- FONCTION MAIN DE TEST ---

def run_serveur():
    print("\n" + "="*30)
    print("      MODE SERVEUR (RECEPTION)")
    print("="*30)
    
    port = int(input("Port à écouter (ex: 5005) : ") or 3200)
    mdp = input("Définissez le mot de passe : ")
    
    try:
        # Initialisation du serveur (bind + listen se font dans le __init__)
        serveur = Receive(PORT=port, PASSWORD=mdp)
        # Boucle infinie d'écoute
        serveur.receive_file()
    except KeyboardInterrupt:
        print("\n[!] Serveur arrêté manuellement.")
    except Exception as e:
        print(f"\n[!] Erreur fatale serveur : {e}")

def run_client():
    print("\n" + "="*30)
    print("      MODE CLIENT (ENVOI)")
    print("="*30)
    
    ip_dest = input("Adresse IP du serveur (ex: 127.0.0.1 ou 192.168.1.45) : ") or "127.0.0.1"
    port_dest = int(input("Port du serveur (ex: 5005) : ") or 3200)
    chemin = input("Chemin complet du fichier à envoyer : ")
    
    if not os.path.exists(chemin):
        print(f"Erreur : Le fichier '{chemin}' est introuvable.")
        return
        
    mdp = input("Mot de passe : ")

    try:
        client = Send(
            IP=ip_dest, 
            PORT=port_dest, 
            file_path=chemin, 
            PASSWORD=mdp
        )
        client.send_file()
    except Exception as e:
        print(f"\n[!] Erreur client : {e}")

if __name__ == "__main__":
    # On s'assure que le dossier de destination existe pour le test
    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_path):
        os.makedirs(downloads_path)

    print("BIENVENUE DANS VOTRE SYSTÈME DE TRANSFERT SÉCURISÉ")
    print("1. Agir comme SERVEUR (Attendre un fichier)")
    print("2. Agir comme CLIENT (Envoyer un fichier)")
    
    try:
        choix = input("\nVotre choix (1 ou 2) : ")
        
        if choix == "1":
            run_serveur()
        elif choix == "2":
            run_client()
        else:
            print("Choix invalide, fermeture.")
    except KeyboardInterrupt:
        print("\nProgramme quitté.") 
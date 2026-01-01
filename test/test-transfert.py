"""
Script de diagnostic réseau pour DataShare
Lance un Phare ET un Scanner pour tester la découverte
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import socket
import threading
import time
from core.discovery import Phare, Scanner
from core.state_manager import State, StateManager
from core.config import MANAGER

def test_udp_broadcast():
    """Test basique de broadcast UDP"""
    print("\n" + "="*50)
    print("TEST 1 : Broadcast UDP Basique")
    print("="*50)
    
    # Émetteur
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Récepteur
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if os.name == 'nt':
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    try:
        receiver.bind(('', 32002))  # Port de test
        receiver.settimeout(2)
        
        print("[OK] Récepteur bindé sur port 32002")
        
        # Envoi
        message = b"TEST_DATASHARE"
        sender.sendto(message, ('<broadcast>', 32002))
        print(f"[OK] Message envoyé : {message}")
        
        # Réception
        data, addr = receiver.recvfrom(1024)
        print(f"[OK] Message reçu de {addr[0]} : {data}")
        print("✅ Le broadcast UDP fonctionne !\n")
        return True
        
    except socket.timeout:
        print("❌ ERREUR : Aucun message reçu (timeout)")
        print("   → Le firewall bloque peut-être le trafic UDP")
        return False
    except Exception as e:
        print(f"❌ ERREUR : {e}")
        return False
    finally:
        sender.close()
        receiver.close()


def test_phare_scanner():
    """Test du Phare et du Scanner ensemble"""
    print("\n" + "="*50)
    print("TEST 2 : Phare + Scanner DataShare")
    print("="*50)
    
    # Mettre l'état en READY
    MANAGER.set_state(State.READY)
    
    # Lancer le Phare
    phare = Phare()
    thread_phare = threading.Thread(target=phare.shouting, daemon=True)
    thread_phare.start()
    print("[OK] Phare lancé")
    
    # Attendre un peu
    time.sleep(1)
    
    # Lancer le Scanner
    scanner = Scanner()
    devices_found = []
    
    def callback(devices):
        nonlocal devices_found
        devices_found = devices
        if devices:
            print(f"\n[OK] {len(devices)} appareil(s) trouvé(s) :")
            for ip, info in devices:
                print(f"   - {info['pc']} ({ip}) - Port {info['port']} - Status {info['status']}")
    
    print("[OK] Scanner lancé, écoute pendant 5 secondes...")
    
    # Lancer le scanner dans un thread
    scanner_thread = threading.Thread(
        target=scanner.listening, 
        args=(callback,), 
        daemon=True
    )
    scanner_thread.start()
    
    # Attendre 5 secondes
    time.sleep(5)
    
    # Arrêter
    scanner.running = False
    MANAGER.set_state(State.OFFLINE)
    
    time.sleep(1)
    
    if devices_found:
        print(f"\n✅ Test réussi ! {len(devices_found)} appareil(s) détecté(s)")
        return True
    else:
        print("\n❌ ERREUR : Aucun appareil détecté")
        print("   Causes possibles :")
        print("   1. Firewall bloque le port UDP 32001")
        print("   2. Le port est déjà utilisé")
        print("   3. Problème de permissions réseau")
        return False


def check_ports():
    """Vérifie si les ports sont disponibles"""
    print("\n" + "="*50)
    print("VÉRIFICATION DES PORTS")
    print("="*50)
    
    ports_to_check = [
        (32000, "TCP", "Serveur de réception"),
        (32001, "UDP", "Discovery (Phare/Scanner)")
    ]
    
    for port, protocol, description in ports_to_check:
        try:
            if protocol == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', port))
            s.close()
            print(f"[OK] Port {port}/{protocol} ({description}) est LIBRE")
        except OSError as e:
            print(f"[❌] Port {port}/{protocol} ({description}) est OCCUPÉ ou INACCESSIBLE")
            print(f"    Erreur : {e}")


def get_network_info():
    """Affiche les informations réseau"""
    print("\n" + "="*50)
    print("INFORMATIONS RÉSEAU")
    print("="*50)
    
    hostname = socket.gethostname()
    print(f"Nom de l'ordinateur : {hostname}")
    
    try:
        # IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Adresse IP locale : {local_ip}")
    except:
        print("Adresse IP locale : NON DÉTECTÉE")
    
    print(f"Système d'exploitation : {os.name}")


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════╗
║     DATASHARE - DIAGNOSTIC RÉSEAU               ║
╚══════════════════════════════════════════════════╝
    """)
    
    # Infos réseau
    get_network_info()
    
    # Vérification des ports
    check_ports()
    
    # Test UDP basique
    test1_ok = test_udp_broadcast()
    
    if test1_ok:
        # Test Phare/Scanner
        test2_ok = test_phare_scanner()
        
        if test2_ok:
            print("\n" + "="*50)
            print("✅ TOUS LES TESTS SONT PASSÉS !")
            print("="*50)
            print("\nVotre application devrait fonctionner correctement.")
            print("Lancez maintenant : python main.py")
        else:
            print("\n" + "="*50)
            print("⚠️  PROBLÈME DÉTECTÉ")
            print("="*50)
            print("\nLe broadcast UDP fonctionne mais le Phare/Scanner ne communique pas.")
            print("Vérifiez que le fichier core/discovery.py a bien été mis à jour.")
    else:
        print("\n" + "="*50)
        print("❌ ÉCHEC DES TESTS")
        print("="*50)
        print("\nLe broadcast UDP ne fonctionne pas.")
        print("Solution : Désactiver temporairement votre firewall et réessayer.")
        print("\nWindows : Panneau de configuration → Pare-feu Windows → Désactiver")
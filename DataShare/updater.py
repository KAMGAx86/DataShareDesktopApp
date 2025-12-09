import requests
import json
import os
import sys
import logging
import threading
from typing import Dict, Any, Optional
import subprocess

logger = logging.getLogger("Updater")

class DataShareUpdater:
    def __init__(self, current_version: str, update_url: str):
        self.current_version = current_version
        self.update_url = update_url # URL de l'API (ex: http://votre-domaine.com/api/update)
    
    def check_for_updates(self) -> Optional[Dict[str, Any]]:
        """
        Vérifie si une mise à jour est disponible.
        Retourne les infos de la version si update dispo, sinon None.
        """
        try:
            logger.info(f"Vérification des mises à jour sur {self.update_url}...")
            response = requests.get(self.update_url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("version")
                
                if self._is_newer(latest_version):
                    logger.info(f"Nouvelle version trouvée: {latest_version}")
                    return data
                else:
                    logger.info("Application à jour.")
                    return None
            else:
                logger.warning(f"Erreur API de mise à jour: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Échec de la vérification des mises à jour: {e}")
            return None

    def _is_newer(self, remote_version: str) -> bool:
        """Compare les versions sémantiques (x.y.z)"""
        try:
            v1_parts = [int(p) for p in self.current_version.split('.')]
            v2_parts = [int(p) for p in remote_version.split('.')]
            return v2_parts > v1_parts
        except:
            return False

    def download_update(self, download_url: str, save_path: str, progress_callback=None):
        """Télécharge le fichier de mise à jour"""
        try:
            response = requests.get(download_url, stream=True)
            total_length = response.headers.get('content-length')
            
            with open(save_path, 'wb') as f:
                if total_length is None:
                    f.write(response.content)
                    if progress_callback: progress_callback(1.0)
                else:
                    dl = 0
                    total_length = int(total_length)
                    for data in response.iter_content(chunk_size=4096):
                        dl += len(data)
                        f.write(data)
                        if progress_callback:
                            progress_callback(dl / total_length)
                            
            return True
        except Exception as e:
            logger.error(f"Erreur de téléchargement: {e}")
            return False

    def apply_update(self, updater_exe_path: str):
        """
        Lance l'exécutable d'installation téléchargé et quitte.
        Pour une mise à jour silencieuse, l'installateur doit supporter des flags.
        """
        try:
            logger.info(f"Lancement de la mise à jour: {updater_exe_path}")
            subprocess.Popen([updater_exe_path])
            sys.exit(0) # Quitter l'application actuelle
        except Exception as e:
            logger.error(f"Erreur au lancement de la mise à jour: {e}")

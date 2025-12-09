# Documentation du Code Source - DataShare Pro

Ce document détaille la structure et le fonctionnement de chaque fichier du projet DataShare Pro.

## 📂 Structure Générale

Le projet est divisé en plusieurs modules, chacun gérant une responsabilité spécifique (GUI, Réseau, Transfert, Core).

---

## 📄 Fichiers Principaux

### 1. `main_gui.py` (Interface Utilisateur)
**Rôle** : Point d'entrée de l'application graphique.
- **Libs** : `flet`, `DataShareCore`.
- **Fonctionnement** : 
    - Initialise l'interface Flet (NavigationRail, Views).
    - Lance le service `DataShareCore` dans un thread d'arrière-plan.
    - Écoute les événements (callbacks) pour la découverte d'appareils et la progression des transferts.
    - Gère le Drag & Drop et la vérification des mises à jour (`updater.py`).
    - Vérifie les droits d'administrateur au démarrage (`is_admin()`).

### 2. `DataShareCore.py` (Orchestrateur)
**Rôle** : Cerveau central de l'application.
- **Rôle** : Coordonne les modules de bas niveau.
- **Fonctionnalités** :
    - Démarre/Arrête les services (scan réseau, hotspot, serveurs de transfert).
    - Expose une API unifiée pour l'interface graphique.
    - Gère la logique métier (acceptation/refus de transfert).

### 3. `unified_file_transfer.py` (Gestionnaire de Transfert)
**Rôle** : Interface unifiée pour `send.py` et `receive.py`.
- **Rôle** : Simplifie l'utilisation des modules d'envoi et de réception.
- **Fonctionnalités** :
    - Maintient la liste des transferts actifs.
    - Normalise les données (UnifiedTransferJob) pour l'affichage.

### 4. `updater.py` (Système de Mise à Jour)
**Rôle** : Client de mise à jour automatique.
- **Fonctionnement** :
    - `check_for_updates()` : Interroge une API distante (JSON).
    - `download_update()` : Télécharge le nouvel installateur.
    - `apply_update()` : Lance l'installation et ferme l'app.

---

## 🔧 Modules de Bas Niveau

### 5. `receive.py` (Serveur de Réception)
**Rôle** : Gère la réception des fichiers via TCP.
- **Architecture** : Serveur TCP multi-threadé.
- **Particularités** : 
    - Utilise `mmap` pour écrire les gros fichiers efficacement.
    - Pipeline de déchiffrement parallèle.
    - Protocole binaire personnalisé.

### 6. `send.py` (Client d'Envoi)
**Rôle** : Envoie les fichiers.
- **Particularités** : 
    - Découpe les fichiers en chunks.
    - Gère la compression (LZ4) et le chiffrement (ChaCha20).
    - Optimisation TCP (buffers 64MB).

### 7. `scan_network.py` (Découverte)
**Rôle** : Scanne le réseau pour trouver d'autres instances DataShare.
- **Technique** : Envoie des paquets UDP broadcast/multicast pour se signaler et écouter les autres.

### 8. `alert_windows.py` (Notifications)
**Rôle** : Système de notifications natives.
- **Libs** : `win10toast` ou notifications système selon l'OS.

### 9. `user_config.py` (Configuration)
**Rôle** : Gère la persistance des paramètres (JSON).
- **Données** : Pseudo, dossier de téléchargement, préférences.

### 10. `stats.py` (Statistiques)
**Rôle** : Enregistre l'historique des transferts.
- **Stockage** : Base de données locale (SQLite ou JSON log) pour les graphiques d'activité.

---

## ⚠️ Notes de Sécurité Importantes

- **Droits Admin** : Requis pour configurer le Hotspot Wi-Fi (via `netsh`).
- **Ports** : 
    - TCP 32001 (Transfert)
    - UDP 32002 (Découverte)
- **Données** : Les fichiers reçus sont stockés par défaut dans `Downloads/DataShare`.

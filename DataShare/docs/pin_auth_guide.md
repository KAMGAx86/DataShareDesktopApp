# Authentification par PIN - Guide Utilisateur

## Aperçu
DataShare Pro v6.0 intègre désormais une fonctionnalité de sécurité optionnelle pour protéger vos réceptions de fichiers : l'authentification par code PIN.

## Comment activer la protection

1. Ouvrez l'onglet **Paramètres**.
2. Dans la section **Sécurité**, activez l'option **"Activer la protection par PIN"**.
3. Définissez votre **Code PIN** secret (par défaut "0000").
4. Cliquez sur **Sauvegarder**.

Désormais, tout appareil essayant de vous envoyer des fichiers devra fournir ce code PIN pour initier le transfert.

## Comment envoyer un fichier vers un appareil protégé

1. Allez dans l'onglet **Envoyer**.
2. Sélectionnez vos fichiers et choisissez le destinataire.
3. Dans la section **Sécurité (Optionnel)**, entrez le Code PIN que le destinataire vous a communiqué.
4. Cliquez sur **Envoyer**.

Si le PIN est correct, le transfert commencera immédiatement. Sinon, il sera rejeté.

## Détails Techniques

- Le PIN est envoyé de manière sécurisée lors du handshake initial (Protocole v7.0).
- Le PIN n'est jamais stocké en clair dans les logs, seulement dans votre configuration locale.
- Cette fonctionnalité est compatible avec le mode Turbo et le Chiffrement.

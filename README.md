# Surveillance IP

Deux outils complémentaires pour surveiller une liste d'adresses IP (modules à
serveur web embarqué, caméras, imprimantes, NAS, automates…), savoir ce qu'il y
a derrière et ouvrir leur page web.

## 1. `index.html` — l'application (sans installation)

Une page web autonome : **enregistre le fichier et ouvre-le en double-cliquant**
(aucune installation, tout reste dans ton navigateur).

- Vérifie si chaque adresse **répond ou non** (test de connexion HTTP/S) avec
  temps de réponse, rafraîchissement automatique.
- **Libellé** éditable par adresse + champ **Notes** + champ **Port de switch**.
- Ouvre la **page web** de chaque appareil d'un clic.
- **Ajout par plage** : `192.168.1.1-254`, `192.168.1.10-192.168.1.50`,
  `192.168.1.0/24`.
- Indices sur l'appareil : icône (favicon) + ports web détectés (bouton
  *Analyser*).
- **Import / Export JSON** (l'import *fusionne* : met à jour sans dupliquer).

> Limite : un navigateur ne peut pas lire le *titre* d'une page ni l'en-tête
> `Server` d'un autre appareil (règle de sécurité CORS), ni le port du switch.
> C'est le rôle du second outil.

> **Windows sans Python ?** Utilise `analyseur.ps1` (PowerShell, déjà présent
> dans Windows, rien à installer) — mêmes fonctions que la version Python.
> Voir la section 3 plus bas.

## 2. `analyseur.py` — l'analyse locale (Python, sans `pip`)

Script en **pur Python 3** (bibliothèque standard uniquement, rien à installer).
Il lit ce que le navigateur ne peut pas, puis génère un JSON à **réimporter**
dans l'application.

Pour chaque adresse :
- le **titre** de la page et l'en-tête **`Server`** (même derrière une demande
  de mot de passe : le *realm* est récupéré) ;
- le **type de serveur embarqué** déduit (GoAhead, Boa, lwIP, RomPager…) ;
- un **libellé** proposé (le titre en priorité) ;
- (option) le **port du switch** via **SNMP** : table de commutation MAC du
  switch croisée avec la table ARP.

### Utilisation

```bash
# Depuis l'export JSON de l'application :
python analyseur.py --in surveillance-ip.json --out analyse.json

# Ou directement depuis une plage / des IP :
python analyseur.py --range 192.168.1.0/24 --out analyse.json
python analyseur.py --ips 192.168.1.10 192.168.1.20 --out analyse.json

# En ajoutant le port de switch via SNMP (IP du switch connue) :
python analyseur.py --in surveillance-ip.json --out analyse.json \
       --switch 192.168.1.2 --community public

# SANS connaître l'IP du switch : découverte automatique des switches SNMP.
# L'outil scanne la plage, trouve les switches et donne, pour chaque module,
# le switch (nom + IP) ET le port :
python analyseur.py --in surveillance-ip.json --out analyse.json \
       --discover 192.168.1.0/24 --community public

# Plusieurs switches connus : répète --switch.
python analyseur.py --in surveillance-ip.json --out analyse.json \
       --switch 192.168.1.253 --switch 192.168.1.254 --community public
```

Puis, dans l'application : **Importer** → choisis `analyse.json`. Les libellés
vides se remplissent (sans écraser ceux saisis à la main), et le
type / `Server` / titre / port de switch s'affichent sur chaque carte.

### À savoir pour le port de switch (SNMP)

- Il est lu **sur le switch** (c'est lui qui sait), pas sur le module : il faut
  l'**IP du switch** et sa **communauté SNMP en lecture** (souvent `public`).
- La correspondance IP ↔ MAC vient de la table ARP de **la machine qui lance le
  script** (à exécuter depuis le même réseau/sous-réseau que les modules), et de
  la table ARP du switch s'il est routeur (L3).
- Avec plusieurs switches (`--switch` répété ou `--discover`), l'outil retient
  automatiquement le **port d'accès** de chaque module (celui qui porte le moins
  d'adresses MAC), pas les ports de liaison entre switches.
- **Sans SNMP, c'est impossible** : depuis l'IP seule, on ne peut obtenir que la
  MAC (via ARP), qui ne dit ni le switch ni le port. Le port est une donnée
  physique que seul le switch connaît. Switches non-managés → à faire à la main.

### État des ports du switch (fermé / libre / actif)

Pour savoir, port par port, si un port est **désactivé (fermé)**, **libre (rien
branché / lien down)** ou **actif**, ajoute `--ports` :

```bash
python analyseur.py --discover 10.122.103.0/24 --community public --ports
```

Ça écrit `ports.json` (nom personnalisable : `--ports mon_rapport.json`) et
affiche un tableau :

```
=== Etat des ports de switch ===
  SWITCH                 PORT           ETAT                                   APPAREILS
  SW-Test (10.122.103.1) Gi1/0/1        Actif (lien up)                        2
  SW-Test (10.122.103.1) Gi1/0/2        Desactive (ferme)                      0
  SW-Test (10.122.103.1) Gi1/0/3        Libre (active mais rien branche...)    0
```

- **Actif** : le port est activé et un lien est présent (câble + appareil).
- **Désactivé (fermé)** : le port est administrativement coupé sur le switch.
- **Libre** : le port est activé mais aucun lien (rien branché, ou appareil éteint).
- « Appareils » = nombre d'adresses MAC apprises sur ce port.

`python analyseur.py -h` affiche toutes les options.

## 3. `analyseur.ps1` — même chose en PowerShell (Windows, sans Python)

Version PowerShell de l'analyseur, pour Windows sans Python. **Rien à
installer** (PowerShell est livré avec Windows).

```powershell
# 1) Vérifier que tout est bon (encodage SNMP, plages, détection) :
powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -SelfTest

# 2) Analyser (depuis l'export de l'app) + port de switch :
powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -In surveillance-ip.json -Out analyse.json -Switch 192.168.1.2 -Community public

# Ou depuis une plage / des IP :
powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -Range 192.168.1.0/24 -Out analyse.json
powershell -ExecutionPolicy Bypass -File .\analyseur.ps1 -Ips 192.168.1.10,192.168.1.20 -Out analyse.json
```

- `-ExecutionPolicy Bypass` autorise seulement ce lancement, sans rien changer
  au réglage de ta machine.
- Lance **`-SelfTest` en premier** : il vérifie en une seconde que l'encodage
  SNMP et le reste fonctionnent sur ta machine avant de te fier au résultat.
- Le JSON produit est identique à celui de la version Python : réimporte-le
  dans l'application via **Importer**.

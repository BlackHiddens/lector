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

# En ajoutant le port de switch via SNMP :
python analyseur.py --in surveillance-ip.json --out analyse.json \
       --switch 192.168.1.2 --community public
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
- Un module derrière un switch en cascade apparaît sur le port de liaison
  (uplink) — comportement normal du niveau 2.

`python analyseur.py -h` affiche toutes les options.

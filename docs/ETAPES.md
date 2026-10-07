# Lire une base HFSQL (PC SOFT) depuis Laravel — grandes étapes

Ce document décrit, étape par étape, comment ce projet de démonstration a été
construit et comment le mettre en route pour prouver qu'une base **HFSQL
Client/Serveur** peut être lue depuis **Laravel**.

## Principe général

PHP ne sait pas parler nativement le protocole HFSQL. Le pont utilisé ici est
**ODBC** :

```
Laravel (PHP)  →  extension PHP "odbc"  →  pilote ODBC HFSQL (PC SOFT)  →  serveur HFSQL (port 4900)
```

Le pilote ODBC HFSQL est fourni gratuitement par PC SOFT (installé avec
WINDEV/WEBDEV/HFSQL Control Center, ou téléchargeable seul depuis l'espace
"Téléchargements" du site PC SOFT : *"Pilote ODBC pour HFSQL"*).

---

## Étape 1 — Prérequis côté serveur web (machine qui exécute Laravel)

1. **PHP 8.2+** avec Composer.
2. **Extension PHP `odbc` activée** : dans `php.ini`, décommenter :
   ```ini
   extension=odbc
   ```
   puis redémarrer le serveur web (ou le terminal pour `php artisan serve`).
   Vérification : `php -m | findstr odbc` (Windows) ou `php -m | grep odbc`.
3. **Pilote ODBC HFSQL installé** :
   - Sous Windows : exécuter l'installeur PC SOFT, puis vérifier sa présence
     dans *Administrateur de sources de données ODBC* (onglet **Pilotes**,
     entrée "HFSQL").
   - ⚠️ **Cohérence 32/64 bits** : le pilote doit être dans la même
     architecture que PHP (PHP 64 bits ⇒ pilote ODBC 64 bits).
4. **Serveur HFSQL accessible** : le serveur HFSQL Client/Serveur écoute par
   défaut sur le **port 4900** ; ouvrir ce port dans le pare-feu si besoin.

> Remarque : HFSQL "Classic" (fichiers `.fic` locaux sans serveur) est aussi
> accessible via le même pilote ODBC, mais via un DSN pointant vers le
> répertoire des fichiers. Le mode "DSN Windows" du formulaire couvre ce cas.

## Étape 2 — Création du projet Laravel

```bash
composer create-project laravel/laravel lector
cd lector
cp .env.example .env        # déjà fait si create-project a été utilisé
php artisan key:generate
```

Particularité de ce projet : dans `.env`, la session est stockée en
**fichiers** (`SESSION_DRIVER=file`) pour qu'aucune base SQL locale ne soit
nécessaire — la seule base utilisée est la base HFSQL distante.

## Étape 3 — Intégration de Bootstrap

Bootstrap 5 est chargé **via CDN** dans le gabarit
`resources/views/layouts/app.blade.php` : aucune compilation `npm`/Vite n'est
requise pour lancer la démonstration. (Pour un vrai projet, on pourrait
installer Bootstrap via npm et Vite.)

## Étape 4 — Le service d'accès HFSQL

Fichier : `app/Services/HfsqlService.php`

C'est la seule classe qui parle à HFSQL. Elle encapsule les fonctions
`odbc_*` de PHP :

| Méthode          | Rôle                                                            |
|------------------|-----------------------------------------------------------------|
| `connect()`      | Construit la chaîne de connexion et ouvre la connexion ODBC      |
| `listTables()`   | Liste les tables via le catalogue ODBC (`odbc_tables`)           |
| `previewTable()` | Lit les 50 premières lignes d'une table (`SELECT TOP 50 * ...`)  |
| `disconnect()`   | Ferme la connexion                                               |

Chaîne de connexion en mode direct (mots-clés attendus par le pilote PC SOFT) :

```
Driver={HFSQL};Server Name=<serveur>;Server Port=<port>;Database=<base>;
```

L'utilisateur et le mot de passe sont passés séparément à `odbc_connect()`
(dans une chaîne unique, ce seraient `UID=...;PWD=...;`).
Par défaut sur un serveur HFSQL fraîchement installé : utilisateur `admin`,
mot de passe vide.

> ⚠️ Cette chaîne n'a pas pu être testée contre un vrai serveur HFSQL lors de
> la rédaction : c'est précisément le but de ce projet de test. Si le pilote
> refuse un mot-clé, ajuster dans `HfsqlService::connect()` selon la
> documentation PC SOFT de votre version.

Détails d'implémentation notables :

- **Filtrage du catalogue** : `odbc_tables()` renvoie aussi des tables
  système ; seules les entrées de type `TABLE` sont conservées.
- **Encodage** : HFSQL stocke souvent ses chaînes en ANSI (Windows-1252) ;
  les valeurs non UTF-8 sont converties avant affichage.
- **Anti-injection SQL** : le nom de table demandé dans l'URL est validé
  contre la liste réelle des tables avant toute requête.

## Étape 5 — Le contrôleur et les routes

Fichiers : `app/Http/Controllers/HfsqlController.php` et `routes/web.php`

| Route                  | Méthode | Action                                        |
|------------------------|---------|-----------------------------------------------|
| `/`                    | GET     | Formulaire de connexion                       |
| `/connect`             | POST    | Valide + teste la connexion, mémorise en session |
| `/tables`              | GET     | Liste toutes les tables de la base            |
| `/tables/{table}`      | GET     | Aperçu des 50 premières lignes d'une table    |
| `/disconnect`          | POST    | Oublie les paramètres de connexion            |

Les paramètres de connexion sont **conservés en session** entre les pages :
chaque page rouvre une connexion ODBC courte (pattern "connexion à la
demande"), ce qui évite de maintenir une connexion persistante.

## Étape 6 — Les vues Bootstrap

| Vue                                   | Rôle                                   |
|---------------------------------------|----------------------------------------|
| `layouts/app.blade.php`               | Gabarit commun (navbar, alertes, CDN)  |
| `hfsql/connect.blade.php`             | Formulaire de connexion (2 modes)      |
| `hfsql/tables.blade.php`              | Grille de cartes listant les tables    |
| `hfsql/table.blade.php`               | Tableau d'aperçu du contenu            |

Le formulaire propose deux modes :

- **Connexion directe** : serveur, port (4900 par défaut), base, identifiants ;
- **DSN Windows** : nom d'une source de données déjà déclarée dans
  l'administrateur ODBC (utile aussi pour HFSQL Classic).

## Étape 7 — Lancement et test

```bash
php artisan serve
```

Puis ouvrir <http://127.0.0.1:8000> :

1. saisir les informations du serveur HFSQL (ex. `localhost` / `4900` /
   nom de la base / `admin` / mot de passe vide) ;
2. cliquer sur **Connecter** — en cas d'échec, le message d'erreur ODBC
   exact s'affiche en haut de page ;
3. la liste de **toutes les tables** de la base s'affiche ;
4. cliquer sur une table pour prévisualiser ses 50 premières lignes.

## Dépannage rapide

| Symptôme                                            | Piste                                                        |
|-----------------------------------------------------|--------------------------------------------------------------|
| "L'extension PHP 'odbc' n'est pas activée"          | Décommenter `extension=odbc` dans le bon `php.ini`           |
| "Data source name not found…"                       | Pilote HFSQL absent, ou architecture 32/64 bits différente de PHP |
| Timeout / "Unable to connect"                       | Serveur HFSQL arrêté, mauvais port, pare-feu bloquant 4900   |
| Erreur d'authentification                           | Vérifier utilisateur/mot de passe dans le Centre de Contrôle HFSQL |
| Accents mal affichés                                | Conversion Windows-1252 → UTF-8 (déjà gérée dans le service) |

## Se connecter depuis un outil tiers (ex. Boomi)

Les paramètres validés avec ce testeur (serveur, port 4900, base,
utilisateur, mot de passe) sont les mêmes quel que soit le client. Mais la
**technologie d'accès** dépend du client :

- **Client natif Windows / PHP / Python (pyodbc)…** : ODBC, avec la chaîne de
  l'étape 4.
- **Client Java (dont les Atoms Boomi)** : Java passe par **JDBC**, pas par
  ODBC (le pont JDBC-ODBC a disparu du JDK depuis Java 8). Il faut donc soit
  un **pilote JDBC pour HFSQL** (à confirmer auprès de PC SOFT pour votre
  version : nom de la classe, format d'URL et fichier `.jar`), soit un
  **pont ODBC→JDBC tiers**, soit passer par une **API intermédiaire** (par
  exemple exposer ce projet Laravel en JSON et l'appeler depuis Boomi avec le
  connecteur HTTP Client).

## Limites (volontaires) de cette démonstration

- Le mot de passe est conservé **en session en clair** le temps de la
  navigation : acceptable pour un test, à durcir en production.
- Lecture seule : aucune écriture vers HFSQL n'est implémentée (mais
  `odbc_exec` accepterait `INSERT`/`UPDATE` selon les droits).
- Pas de pagination : l'aperçu est limité aux 50 premières lignes.

## Pour aller plus loin

- Pagination et tri des aperçus de tables.
- Affichage de la structure des tables (`odbc_columns()` donne les colonnes,
  types et tailles).
- Export CSV/Excel des données lues, ou API JSON pour des outils
  d'intégration.
- Écriture vers HFSQL (INSERT/UPDATE) après validation des droits.

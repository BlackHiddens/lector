# Lecteur HFSQL — Laravel × HFSQL (PC SOFT)

Projet d'exemple **Laravel + Bootstrap 5** dont le but est de **prouver
qu'une base HFSQL (PC SOFT) peut être lue depuis Laravel**, via le pilote
ODBC HFSQL.

## Ce que fait l'application

1. Un formulaire permet de saisir les informations de connexion à un
   serveur HFSQL (serveur, port, base, utilisateur, mot de passe — ou un
   DSN Windows) puis de cliquer sur **Connecter**.
2. Si la connexion réussit, **toutes les tables** de la base HFSQL sont
   listées.
3. Un clic sur une table affiche un **aperçu de ses 50 premières lignes**.

## Démarrage rapide

Prérequis : PHP 8.2+ avec l'extension `odbc` activée, Composer, et le
**pilote ODBC HFSQL de PC SOFT** installé (même architecture 32/64 bits
que PHP). Détails complets dans [`docs/ETAPES.md`](docs/ETAPES.md).

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan serve
```

Puis ouvrir <http://127.0.0.1:8000>.

## Où regarder dans le code

| Fichier | Rôle |
|---|---|
| `app/Services/HfsqlService.php` | Toute la communication ODBC avec HFSQL (connexion, liste des tables, lecture) |
| `app/Http/Controllers/HfsqlController.php` | Orchestration formulaire → session → vues |
| `routes/web.php` | Les 5 routes de l'application |
| `resources/views/layouts/app.blade.php` | Gabarit Bootstrap commun |
| `resources/views/hfsql/*.blade.php` | Formulaire, liste des tables, aperçu |
| `docs/ETAPES.md` | **Documentation des grandes étapes** (construction + mise en route + dépannage) |

Le code est commenté en français à chaque étape clé.

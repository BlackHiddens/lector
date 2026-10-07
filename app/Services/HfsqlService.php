<?php

namespace App\Services;

use RuntimeException;

/**
 * Service d'accès à une base HFSQL Client/Serveur (PC SOFT).
 *
 * La communication passe par le pilote ODBC "HFSQL" fourni par PC SOFT
 * (installé avec WINDEV/WEBDEV ou téléchargeable sur le site de PC SOFT).
 * Côté PHP, on s'appuie sur l'extension "odbc" (php_odbc) qui doit être
 * activée dans le php.ini du serveur qui héberge Laravel.
 *
 * Deux modes de connexion sont proposés :
 *  - "driver" : chaîne de connexion directe vers le pilote HFSQL
 *               (pas besoin de déclarer une source de données Windows) ;
 *  - "dsn"    : utilisation d'un DSN déclaré dans l'administrateur
 *               de sources de données ODBC de Windows.
 */
class HfsqlService
{
    /**
     * Ressource de connexion ODBC ouverte (ou null si non connecté).
     *
     * @var resource|null
     */
    private $connection = null;

    /**
     * Ouvre la connexion vers le serveur HFSQL à partir des informations
     * saisies dans le formulaire.
     *
     * @param array $params Tableau associatif : mode, dsn, server, port,
     *                      database, username, password.
     *
     * @throws RuntimeException si l'extension ODBC est absente ou si la
     *                          connexion échoue (message ODBC remonté).
     */
    public function connect(array $params): void
    {
        // L'extension ODBC est indispensable : on le vérifie tout de suite
        // pour renvoyer un message clair plutôt qu'une erreur PHP obscure.
        if (! function_exists('odbc_connect')) {
            throw new RuntimeException(
                "L'extension PHP 'odbc' n'est pas activée. "
                . "Activez 'extension=odbc' dans votre php.ini puis redémarrez le serveur web."
            );
        }

        // Construction de la chaîne de connexion selon le mode choisi.
        if (($params['mode'] ?? 'driver') === 'dsn') {
            // Mode DSN : tout est déjà décrit dans la source de données Windows.
            $connectionString = 'DSN=' . $params['dsn'] . ';';
        } else {
            // Mode driver direct : on décrit entièrement la connexion.
            // "Server Name" et "Server Port" sont les mots-clés attendus
            // par le pilote ODBC HFSQL de PC SOFT.
            $connectionString = sprintf(
                'Driver={HFSQL};Server Name=%s;Server Port=%s;Database=%s;',
                $params['server'],
                $params['port'] ?: '4900', // 4900 = port par défaut d'un serveur HFSQL
                $params['database']
            );
        }

        // Les identifiants sont passés séparément à odbc_connect().
        // L'opérateur @ est volontaire : on récupère l'erreur proprement
        // via odbc_errormsg() pour l'afficher dans l'interface.
        $connection = @odbc_connect(
            $connectionString,
            $params['username'] ?? '',
            $params['password'] ?? ''
        );

        if ($connection === false) {
            throw new RuntimeException(
                'Connexion HFSQL impossible : ' . (odbc_errormsg() ?: error_get_last()['message'] ?? 'erreur inconnue')
            );
        }

        $this->connection = $connection;
    }

    /**
     * Retourne la liste des tables (fichiers de données HFSQL) de la base.
     *
     * On interroge le catalogue ODBC via odbc_tables() : c'est la méthode
     * la plus fiable, car elle est fournie par le pilote lui-même.
     *
     * @return array<int, string> Noms des tables, triés par ordre alphabétique.
     */
    public function listTables(): array
    {
        $this->assertConnected();

        $result = odbc_tables($this->connection);
        if ($result === false) {
            throw new RuntimeException('Lecture du catalogue impossible : ' . odbc_errormsg($this->connection));
        }

        $tables = [];
        while ($row = odbc_fetch_array($result)) {
            // Le catalogue renvoie aussi des vues/tables système : on ne
            // conserve que les tables "utilisateur" (fichiers .fic HFSQL).
            $type = strtoupper(trim($row['TABLE_TYPE'] ?? ''));
            if ($type === 'TABLE') {
                $tables[] = $row['TABLE_NAME'];
            }
        }
        odbc_free_result($result);

        sort($tables, SORT_NATURAL | SORT_FLAG_CASE);

        return $tables;
    }

    /**
     * Lit les premières lignes d'une table pour l'aperçu.
     *
     * @param string $table Nom de la table (validé en amont contre la liste
     *                      réelle des tables pour éviter toute injection SQL).
     * @param int    $limit Nombre maximum de lignes à ramener.
     *
     * @return array{columns: array<int,string>, rows: array<int,array>}
     */
    public function previewTable(string $table, int $limit = 50): array
    {
        $this->assertConnected();

        // HFSQL comprend la syntaxe "SELECT TOP n". Le nom de table est
        // encadré de guillemets doubles pour supporter espaces et accents.
        $sql = sprintf('SELECT TOP %d * FROM "%s"', $limit, str_replace('"', '', $table));

        $result = @odbc_exec($this->connection, $sql);
        if ($result === false) {
            throw new RuntimeException(
                "Lecture de la table « {$table} » impossible : " . odbc_errormsg($this->connection)
            );
        }

        // Récupération des noms de colonnes à partir des métadonnées ODBC.
        $columns = [];
        $columnCount = odbc_num_fields($result);
        for ($i = 1; $i <= $columnCount; $i++) {
            $columns[] = odbc_field_name($result, $i);
        }

        // Récupération des lignes. Les valeurs non UTF-8 (HFSQL stocke
        // souvent en ANSI) sont converties pour ne pas casser l'affichage.
        $rows = [];
        while ($row = odbc_fetch_array($result)) {
            $rows[] = array_map(
                fn ($value) => (is_string($value) && ! mb_check_encoding($value, 'UTF-8'))
                    ? mb_convert_encoding($value, 'UTF-8', 'Windows-1252')
                    : $value,
                $row
            );
        }
        odbc_free_result($result);

        return ['columns' => $columns, 'rows' => $rows];
    }

    /**
     * Ferme proprement la connexion ODBC.
     */
    public function disconnect(): void
    {
        if ($this->connection !== null) {
            odbc_close($this->connection);
            $this->connection = null;
        }
    }

    /**
     * Garde-fou interne : lève une exception si aucune connexion n'est ouverte.
     */
    private function assertConnected(): void
    {
        if ($this->connection === null) {
            throw new RuntimeException('Aucune connexion HFSQL active.');
        }
    }

    /**
     * Libération automatique de la connexion en fin de requête HTTP.
     */
    public function __destruct()
    {
        $this->disconnect();
    }
}

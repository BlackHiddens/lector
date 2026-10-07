<?php

namespace App\Http\Controllers;

use App\Services\HfsqlService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use RuntimeException;

/**
 * Contrôleur principal du testeur de connexion HFSQL.
 *
 * Cycle de vie :
 *  1. showForm()   : affiche le formulaire de connexion (page d'accueil) ;
 *  2. connect()    : valide le formulaire, teste la connexion, mémorise les
 *                    paramètres en session puis redirige vers la liste ;
 *  3. tables()     : se reconnecte avec les paramètres en session et affiche
 *                    toutes les tables de la base ;
 *  4. showTable()  : aperçu des premières lignes d'une table ;
 *  5. disconnect() : oublie les paramètres de connexion (retour à l'accueil).
 *
 * NOTE : les paramètres (y compris le mot de passe) sont stockés en session
 * le temps de la navigation. C'est acceptable pour un projet de démonstration,
 * mais à durcir (chiffrement, coffre-fort, etc.) pour un usage en production.
 */
class HfsqlController extends Controller
{
    /** Clé de session sous laquelle sont rangés les paramètres de connexion. */
    private const SESSION_KEY = 'hfsql.connection';

    public function __construct(private readonly HfsqlService $hfsql)
    {
    }

    /**
     * Page d'accueil : formulaire de connexion HFSQL.
     */
    public function showForm(Request $request): View
    {
        return view('hfsql.connect', [
            // On pré-remplit le formulaire avec la dernière saisie connue.
            'previous' => $request->session()->get(self::SESSION_KEY, []),
        ]);
    }

    /**
     * Soumission du formulaire : on tente réellement la connexion.
     * En cas d'échec, retour au formulaire avec le message d'erreur ODBC.
     */
    public function connect(Request $request): RedirectResponse
    {
        // Validation des champs. Les champs serveur/base ne sont requis
        // qu'en mode "driver" ; le champ DSN qu'en mode "dsn".
        $params = $request->validate([
            'mode'     => 'required|in:driver,dsn',
            'dsn'      => 'required_if:mode,dsn|nullable|string|max:255',
            'server'   => 'required_if:mode,driver|nullable|string|max:255',
            'port'     => 'nullable|integer|between:1,65535',
            'database' => 'required_if:mode,driver|nullable|string|max:255',
            'username' => 'nullable|string|max:255',
            'password' => 'nullable|string|max:255',
        ]);

        try {
            // Test de connexion immédiat : si les informations sont fausses,
            // l'utilisateur le sait tout de suite.
            $this->hfsql->connect($params);
            $this->hfsql->disconnect();
        } catch (RuntimeException $e) {
            return back()->withInput()->withErrors(['connection' => $e->getMessage()]);
        }

        // Connexion validée : on mémorise les paramètres pour les pages suivantes.
        $request->session()->put(self::SESSION_KEY, $params);

        return redirect()->route('hfsql.tables');
    }

    /**
     * Liste de toutes les tables de la base HFSQL connectée.
     */
    public function tables(Request $request): View|RedirectResponse
    {
        $params = $request->session()->get(self::SESSION_KEY);

        // Pas de paramètres en session => l'utilisateur n'est pas "connecté".
        if (! $params) {
            return redirect()->route('hfsql.form');
        }

        try {
            $this->hfsql->connect($params);
            $tables = $this->hfsql->listTables();
        } catch (RuntimeException $e) {
            // La base a pu devenir injoignable depuis la connexion initiale.
            return redirect()->route('hfsql.form')->withErrors(['connection' => $e->getMessage()]);
        }

        return view('hfsql.tables', [
            'tables'   => $tables,
            'database' => $params['mode'] === 'dsn' ? $params['dsn'] : $params['database'],
        ]);
    }

    /**
     * Aperçu du contenu d'une table (50 premières lignes).
     */
    public function showTable(Request $request, string $table): View|RedirectResponse
    {
        $params = $request->session()->get(self::SESSION_KEY);

        if (! $params) {
            return redirect()->route('hfsql.form');
        }

        try {
            $this->hfsql->connect($params);

            // Sécurité : on vérifie que la table demandée existe réellement
            // dans la base avant d'exécuter la requête (anti-injection).
            $tables = $this->hfsql->listTables();
            if (! in_array($table, $tables, true)) {
                abort(404, "Table inconnue : {$table}");
            }

            $preview = $this->hfsql->previewTable($table);
        } catch (RuntimeException $e) {
            return redirect()->route('hfsql.tables')->withErrors(['connection' => $e->getMessage()]);
        }

        return view('hfsql.table', [
            'table'   => $table,
            'columns' => $preview['columns'],
            'rows'    => $preview['rows'],
        ]);
    }

    /**
     * Déconnexion : on oublie simplement les paramètres mémorisés.
     */
    public function disconnect(Request $request): RedirectResponse
    {
        $request->session()->forget(self::SESSION_KEY);

        return redirect()->route('hfsql.form')->with('status', 'Déconnecté de la base HFSQL.');
    }
}

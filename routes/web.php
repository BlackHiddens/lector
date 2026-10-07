<?php

use App\Http\Controllers\HfsqlController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Routes du testeur de connexion HFSQL
|--------------------------------------------------------------------------
|
| Toute l'application tourne autour d'un seul contrôleur :
|  - GET  /               : formulaire de connexion (page d'accueil)
|  - POST /connect        : tentative de connexion à la base HFSQL
|  - GET  /tables         : liste des tables de la base connectée
|  - GET  /tables/{table} : aperçu du contenu d'une table
|  - POST /disconnect     : oubli des paramètres de connexion
|
*/

Route::get('/', [HfsqlController::class, 'showForm'])->name('hfsql.form');
Route::post('/connect', [HfsqlController::class, 'connect'])->name('hfsql.connect');
Route::get('/tables', [HfsqlController::class, 'tables'])->name('hfsql.tables');
Route::get('/tables/{table}', [HfsqlController::class, 'showTable'])->name('hfsql.table');
Route::post('/disconnect', [HfsqlController::class, 'disconnect'])->name('hfsql.disconnect');

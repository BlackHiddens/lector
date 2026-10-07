{{--
    Formulaire de connexion à la base HFSQL.

    Deux modes au choix (onglets radio) :
      - "Connexion directe" : serveur / port / base / identifiants,
        transmis tels quels au pilote ODBC HFSQL ;
      - "DSN Windows" : nom d'une source de données déjà déclarée dans
        l'administrateur ODBC de Windows.

    Le formulaire est pré-rempli avec la dernière saisie ($previous)
    ou avec les valeurs old() en cas d'erreur de validation.
--}}
@extends('layouts.app')

@section('title', 'Connexion')

@section('content')
<div class="row justify-content-center">
    <div class="col-lg-6 col-md-8">
        <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-plug"></i> Connexion à une base HFSQL
            </div>
            <div class="card-body">
                <form method="POST" action="{{ route('hfsql.connect') }}">
                    @csrf

                    @php
                        // Valeur affichée = saisie en erreur (old) > session > défaut.
                        $val = fn (string $field, $default = '') => old($field, $previous[$field] ?? $default);
                    @endphp

                    {{-- Choix du mode de connexion --}}
                    <div class="btn-group w-100 mb-3" role="group" aria-label="Mode de connexion">
                        <input type="radio" class="btn-check" name="mode" id="mode-driver" value="driver"
                               @checked($val('mode', 'driver') === 'driver')
                               onchange="toggleMode()">
                        <label class="btn btn-outline-primary" for="mode-driver">Connexion directe</label>

                        <input type="radio" class="btn-check" name="mode" id="mode-dsn" value="dsn"
                               @checked($val('mode') === 'dsn')
                               onchange="toggleMode()">
                        <label class="btn btn-outline-primary" for="mode-dsn">DSN Windows</label>
                    </div>

                    {{-- Bloc "connexion directe" --}}
                    <div id="block-driver">
                        <div class="row g-3">
                            <div class="col-8">
                                <label for="server" class="form-label">Serveur HFSQL</label>
                                <input type="text" class="form-control @error('server') is-invalid @enderror"
                                       id="server" name="server" placeholder="ex. : localhost ou 192.168.1.10"
                                       value="{{ $val('server') }}">
                                @error('server')<div class="invalid-feedback">{{ $message }}</div>@enderror
                            </div>
                            <div class="col-4">
                                <label for="port" class="form-label">Port</label>
                                <input type="number" class="form-control @error('port') is-invalid @enderror"
                                       id="port" name="port" placeholder="4900"
                                       value="{{ $val('port', 4900) }}">
                                @error('port')<div class="invalid-feedback">{{ $message }}</div>@enderror
                            </div>
                            <div class="col-12">
                                <label for="database" class="form-label">Base de données</label>
                                <input type="text" class="form-control @error('database') is-invalid @enderror"
                                       id="database" name="database" placeholder="Nom de la base HFSQL"
                                       value="{{ $val('database') }}">
                                @error('database')<div class="invalid-feedback">{{ $message }}</div>@enderror
                            </div>
                        </div>
                    </div>

                    {{-- Bloc "DSN Windows" (masqué par défaut) --}}
                    <div id="block-dsn" class="d-none">
                        <label for="dsn" class="form-label">Nom du DSN</label>
                        <input type="text" class="form-control @error('dsn') is-invalid @enderror"
                               id="dsn" name="dsn" placeholder="Source déclarée dans l'administrateur ODBC"
                               value="{{ $val('dsn') }}">
                        @error('dsn')<div class="invalid-feedback">{{ $message }}</div>@enderror
                    </div>

                    {{-- Identifiants (communs aux deux modes) --}}
                    <div class="row g-3 mt-1">
                        <div class="col-6">
                            <label for="username" class="form-label">Utilisateur</label>
                            <input type="text" class="form-control" id="username" name="username"
                                   placeholder="admin" value="{{ $val('username', 'admin') }}">
                        </div>
                        <div class="col-6">
                            <label for="password" class="form-label">Mot de passe</label>
                            <input type="password" class="form-control" id="password" name="password"
                                   placeholder="(vide par défaut sur HFSQL)">
                        </div>
                    </div>

                    <div class="d-grid mt-4">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="bi bi-lightning-charge"></i> Connecter
                        </button>
                    </div>
                </form>
            </div>
            <div class="card-footer text-muted small">
                <i class="bi bi-info-circle"></i>
                Le pilote ODBC HFSQL de PC SOFT et l'extension PHP <code>odbc</code>
                doivent être installés sur le serveur qui exécute Laravel
                (voir <code>docs/ETAPES.md</code>).
            </div>
        </div>
    </div>
</div>

{{-- Affiche le bon bloc de champs selon le mode coché --}}
<script>
    function toggleMode() {
        const dsnMode = document.getElementById('mode-dsn').checked;
        document.getElementById('block-driver').classList.toggle('d-none', dsnMode);
        document.getElementById('block-dsn').classList.toggle('d-none', !dsnMode);
    }
    toggleMode(); // état initial (utile après une erreur de validation)
</script>
@endsection

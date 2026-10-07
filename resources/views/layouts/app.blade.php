{{--
    Gabarit principal de l'application.

    Bootstrap 5 est chargé depuis le CDN officiel : aucune étape de
    compilation (npm/vite) n'est nécessaire pour lancer la démonstration.
    Chaque page vient remplir la section "content".
--}}
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', 'Lecteur HFSQL') — Laravel × HFSQL</title>

    {{-- Bootstrap 5 (CSS) via CDN --}}
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    {{-- Icônes Bootstrap --}}
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
</head>
<body class="bg-light d-flex flex-column min-vh-100">

    {{-- Barre de navigation commune à toutes les pages --}}
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
        <div class="container">
            <a class="navbar-brand" href="{{ route('hfsql.form') }}">
                <i class="bi bi-database"></i> Lecteur HFSQL
            </a>
            <span class="navbar-text text-white-50 small">
                Preuve de concept : lire une base HFSQL (PC SOFT) depuis Laravel
            </span>
        </div>
    </nav>

    <main class="container py-4 flex-grow-1">
        {{-- Message d'information éventuel (ex. : "Déconnecté") --}}
        @if (session('status'))
            <div class="alert alert-info alert-dismissible fade show" role="alert">
                <i class="bi bi-info-circle"></i> {{ session('status') }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        @endif

        {{-- Erreur de connexion ODBC remontée par le contrôleur --}}
        @error('connection')
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="bi bi-exclamation-triangle"></i> {{ $message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        @enderror

        @yield('content')
    </main>

    <footer class="text-center text-muted small py-3 border-top bg-white">
        Projet d'exemple Laravel + Bootstrap — connexion HFSQL via ODBC
    </footer>

    {{-- Bootstrap 5 (JS, pour les alertes refermables et le collapse) --}}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
            integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
            crossorigin="anonymous"></script>
</body>
</html>

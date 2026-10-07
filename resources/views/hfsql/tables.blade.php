{{--
    Liste des tables (fichiers de données) de la base HFSQL connectée.
    Chaque table est cliquable et mène vers un aperçu de son contenu.
--}}
@extends('layouts.app')

@section('title', 'Tables')

@section('content')
<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4 mb-0">
        <i class="bi bi-table"></i> Tables de la base
        <span class="badge bg-primary">{{ $database }}</span>
    </h1>

    {{-- Bouton de déconnexion (POST pour éviter un simple lien GET) --}}
    <form method="POST" action="{{ route('hfsql.disconnect') }}">
        @csrf
        <button type="submit" class="btn btn-outline-danger btn-sm">
            <i class="bi bi-box-arrow-right"></i> Se déconnecter
        </button>
    </form>
</div>

@if (count($tables) === 0)
    {{-- Base vide ou droits insuffisants sur le catalogue --}}
    <div class="alert alert-warning">
        <i class="bi bi-exclamation-circle"></i>
        Aucune table trouvée dans cette base (base vide ou droits insuffisants).
    </div>
@else
    <p class="text-muted">
        {{ count($tables) }} table(s) trouvée(s). Cliquez sur une table pour prévisualiser son contenu.
    </p>

    <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-3">
        @foreach ($tables as $table)
            <div class="col">
                <a href="{{ route('hfsql.table', ['table' => $table]) }}"
                   class="card card-body text-decoration-none shadow-sm h-100
                          d-flex flex-row align-items-center gap-2">
                    <i class="bi bi-file-earmark-spreadsheet fs-4 text-primary"></i>
                    <span class="fw-semibold text-body">{{ $table }}</span>
                </a>
            </div>
        @endforeach
    </div>
@endif
@endsection

{{--
    Aperçu du contenu d'une table HFSQL : les 50 premières lignes,
    affichées dans un tableau Bootstrap avec défilement horizontal.
--}}
@extends('layouts.app')

@section('title', $table)

@section('content')
<div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4 mb-0">
        <i class="bi bi-file-earmark-spreadsheet"></i> Table
        <span class="badge bg-primary">{{ $table }}</span>
    </h1>
    <a href="{{ route('hfsql.tables') }}" class="btn btn-outline-secondary btn-sm">
        <i class="bi bi-arrow-left"></i> Retour aux tables
    </a>
</div>

@if (count($rows) === 0)
    <div class="alert alert-warning">
        <i class="bi bi-exclamation-circle"></i> Cette table est vide.
    </div>
@else
    <p class="text-muted">Aperçu limité aux {{ count($rows) }} première(s) ligne(s).</p>

    {{-- table-responsive : le tableau défile horizontalement si besoin --}}
    <div class="table-responsive shadow-sm rounded bg-white">
        <table class="table table-striped table-hover table-sm align-middle mb-0">
            <thead class="table-dark">
                <tr>
                    @foreach ($columns as $column)
                        <th scope="col" class="text-nowrap">{{ $column }}</th>
                    @endforeach
                </tr>
            </thead>
            <tbody>
                @foreach ($rows as $row)
                    <tr>
                        @foreach ($columns as $column)
                            <td class="text-nowrap">
                                {{-- Les valeurs longues sont tronquées pour garder le tableau lisible --}}
                                {{ \Illuminate\Support\Str::limit((string) ($row[$column] ?? ''), 80) }}
                            </td>
                        @endforeach
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
@endif
@endsection

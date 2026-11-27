import { useState } from 'react';
import { CATEGORY_LABELS, NOTE_CATEGORIES } from '../api/client';
import { AlertBanner } from './AlertBanner';

function formatTimestamp(isoString) {
  if (!isoString) {
    return '';
  }
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) {
    return isoString;
  }
  return date.toLocaleDateString('es-ES', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function NoteList({
  notes,
  meta,
  status,
  error,
  selectedNoteId,
  categoryFilter,
  onCategoryChange,
  onPageChange,
  onSelectNote,
  onEditNote,
  onDeleteNote,
  onRetry,
  onCreateFirst,
  deletingId = null,
}) {
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);

  function renderContent() {
    if (status === 'loading') {
      return (
        <div className="sv-status-box" role="status" aria-live="polite">
          Cargando notas cifradas…
        </div>
      );
    }

    if (status === 'error') {
      return (
        <AlertBanner
          type="error"
          message={error || 'No se pudieron cargar tus notas.'}
          actionLabel="Reintentar"
          onAction={onRetry}
        />
      );
    }

    if (status === 'empty' || notes.length === 0) {
      const hasFilter = Boolean(categoryFilter);
      return (
        <div className="sv-empty-card">
          <h2 className="sv-empty-title">
            {hasFilter
              ? 'Sin notas en esta categoría'
              : 'Tu bóveda está vacía'}
          </h2>
          <p className="sv-empty-text">
            {hasFilter
              ? 'No hay notas guardadas bajo la categoría seleccionada.'
              : 'Crea tu primera nota privada cifrada para empezar.'}
          </p>
          {hasFilter ? (
            <button
              type="button"
              className="sv-btn sv-btn-secondary"
              onClick={() => onCategoryChange('')}
            >
              Ver todas las categorías
            </button>
          ) : (
            <button
              type="button"
              className="sv-btn sv-btn-primary"
              onClick={onCreateFirst}
            >
              Crear primera nota
            </button>
          )}
        </div>
      );
    }

    return (
      <>
        <ul className="sv-note-list" aria-label="Listado de notas cifradas">
          {notes.map((note) => {
            const isSelected = note.id === selectedNoteId;
            const isConfirming = confirmDeleteId === note.id;
            const isDeleting = deletingId === note.id;

            return (
              <li
                key={note.id}
                className={`sv-note-item${isSelected ? ' sv-note-item-selected' : ''}`}
              >
                <button
                  type="button"
                  className="sv-note-select-btn"
                  aria-pressed={isSelected}
                  onClick={() => onSelectNote(note)}
                >
                  <span className="sv-note-item-title">{note.title}</span>
                  <span className="sv-note-meta">
                    <span className="sv-badge">
                      {CATEGORY_LABELS[note.category] || note.category}
                    </span>
                    <span className="sv-badge sv-badge-key">v{note.key_version}</span>
                    {note.updated_at && (
                      <span>{formatTimestamp(note.updated_at)}</span>
                    )}
                  </span>
                </button>

                <div className="sv-note-item-actions">
                  {!isConfirming ? (
                    <>
                      <button
                        type="button"
                        className="sv-btn sv-btn-secondary sv-btn-sm"
                        onClick={() => onEditNote(note)}
                        aria-label={`Editar ${note.title}`}
                      >
                        Editar
                      </button>
                      <button
                        type="button"
                        className="sv-btn sv-btn-danger-outline sv-btn-sm"
                        onClick={() => setConfirmDeleteId(note.id)}
                        aria-label={`Eliminar ${note.title}`}
                      >
                        Eliminar
                      </button>
                    </>
                  ) : (
                    <div className="sv-delete-confirm" role="group" aria-label={`Confirmar eliminación de ${note.title}`}>
                      <span>¿Eliminar esta nota?</span>
                      <button
                        type="button"
                        className="sv-btn sv-btn-danger sv-btn-sm"
                        disabled={isDeleting}
                        onClick={async () => {
                          await onDeleteNote(note.id);
                          setConfirmDeleteId(null);
                        }}
                      >
                        {isDeleting ? 'Eliminando…' : 'Confirmar eliminación'}
                      </button>
                      <button
                        type="button"
                        className="sv-btn sv-btn-secondary sv-btn-sm"
                        disabled={isDeleting}
                        onClick={() => setConfirmDeleteId(null)}
                      >
                        Cancelar
                      </button>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>

        {meta && meta.totalPages > 1 && (
          <nav className="sv-pagination" aria-label="Paginación de notas">
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              disabled={meta.page <= 1}
              onClick={() => onPageChange(meta.page - 1)}
            >
              Anterior
            </button>
            <span>
              Página {meta.page} de {meta.totalPages} ({meta.total} notas)
            </span>
            <button
              type="button"
              className="sv-btn sv-btn-secondary sv-btn-sm"
              disabled={meta.page >= meta.totalPages}
              onClick={() => onPageChange(meta.page + 1)}
            >
              Siguiente
            </button>
          </nav>
        )}
      </>
    );
  }

  return (
    <section aria-label="Tus notas">
      <div className="sv-toolbar">
        <label htmlFor="vault-category-filter" className="sv-label">
          Filtrar por categoría
        </label>
        <select
          id="vault-category-filter"
          className="sv-select"
          value={categoryFilter}
          onChange={(e) => onCategoryChange(e.target.value)}
        >
          <option value="">Todas las categorías</option>
          {NOTE_CATEGORIES.map((cat) => (
            <option key={cat} value={cat}>
              {CATEGORY_LABELS[cat]}
            </option>
          ))}
        </select>
      </div>

      {renderContent()}
    </section>
  );
}

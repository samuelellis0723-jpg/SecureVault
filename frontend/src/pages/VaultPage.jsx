import { useEffect, useState } from 'react';
import { CATEGORY_LABELS, notesApi } from '../api/client';
import { AlertBanner } from '../components/AlertBanner';
import { Layout } from '../components/Layout';
import { NoteForm } from '../components/NoteForm';
import { NoteList } from '../components/NoteList';
import { useAuth } from '../context/AuthContext';

const PAGE_LIMIT = 20;

const EMPTY_META = {
  total: 0,
  page: 1,
  limit: PAGE_LIMIT,
  totalPages: 0,
};

function isSessionAuthError(err) {
  return err && (err.status === 401 || err.code === 'UNAUTHORIZED');
}

export function VaultPage() {
  const { resetSession } = useAuth();

  const [categoryFilter, setCategoryFilter] = useState('');
  const [page, setPage] = useState(1);
  const [reloadTick, setReloadTick] = useState(0);

  const [listState, setListState] = useState({
    status: 'loading',
    items: [],
    meta: EMPTY_META,
    error: '',
  });

  const [panelMode, setPanelMode] = useState('idle'); // 'idle' | 'view' | 'create' | 'edit'
  const [selectedNoteId, setSelectedNoteId] = useState(null);
  const [detailRequest, setDetailRequest] = useState(null);
  const [detailState, setDetailState] = useState({
    status: 'idle', // 'idle' | 'loading' | 'ready' | 'error'
    note: null,
    error: '',
  });

  const [isSaving, setIsSaving] = useState(false);
  const [formError, setFormError] = useState('');
  const [deletingId, setDeletingId] = useState(null);
  const [feedback, setFeedback] = useState({ type: 'success', message: '' });

  // Cargar listado paginado de notas con cancelación AbortController.
  useEffect(() => {
    const controller = new AbortController();
    setListState((prev) => ({ ...prev, status: 'loading', error: '' }));

    notesApi
      .list({
        page,
        limit: PAGE_LIMIT,
        category: categoryFilter,
        signal: controller.signal,
      })
      .then(({ items, meta }) => {
        setListState({
          status: items.length === 0 ? 'empty' : 'ready',
          items,
          meta,
          error: '',
        });
      })
      .catch((err) => {
        if (err && err.name === 'AbortError') {
          return;
        }
        if (isSessionAuthError(err)) {
          resetSession();
          return;
        }
        setListState({
          status: 'error',
          items: [],
          meta: EMPTY_META,
          error: err.message || 'No se pudieron cargar las notas cifradas.',
        });
      });

    return () => controller.abort();
  }, [page, categoryFilter, reloadTick]);

  // Cargar detalle descifrado bajo demanda con cancelación AbortController.
  useEffect(() => {
    if (!detailRequest || !detailRequest.id) {
      return undefined;
    }

    const controller = new AbortController();
    setDetailState({ status: 'loading', note: null, error: '' });

    notesApi
      .getById(detailRequest.id, { signal: controller.signal })
      .then((fullNote) => {
        setDetailState({ status: 'ready', note: fullNote, error: '' });
      })
      .catch((err) => {
        if (err && err.name === 'AbortError') {
          return;
        }
        if (isSessionAuthError(err)) {
          resetSession();
          return;
        }
        setDetailState({
          status: 'error',
          note: null,
          error: err.message || 'No se pudo descifrar la nota seleccionada.',
        });
      });

    return () => controller.abort();
  }, [detailRequest]);

  function triggerReload() {
    setReloadTick((prev) => prev + 1);
  }

  function requestNoteDetail(noteId) {
    setDetailRequest((prev) => ({
      id: noteId,
      seq: prev ? prev.seq + 1 : 1,
    }));
  }

  function handleCategoryChange(nextCategory) {
    setCategoryFilter(nextCategory);
    setPage(1);
  }

  function handleStartCreate() {
    setFormError('');
    setSelectedNoteId(null);
    setDetailRequest(null);
    setDetailState({ status: 'idle', note: null, error: '' });
    setPanelMode('create');
  }

  function handleSelectNote(note) {
    setFormError('');
    setSelectedNoteId(note.id);
    setPanelMode('view');
    requestNoteDetail(note.id);
  }

  function handleStartEdit(note) {
    setFormError('');
    setSelectedNoteId(note.id);
    setPanelMode('edit');
    if (!detailState.note || detailState.note.id !== note.id) {
      requestNoteDetail(note.id);
    }
  }

  async function handleSaveNote(values) {
    setFormError('');
    setIsSaving(true);

    try {
      let saved;
      if (panelMode === 'edit' && detailState.note) {
        saved = await notesApi.update(detailState.note.id, values);
        setFeedback({ type: 'success', message: 'Nota actualizada y re-cifrada correctamente.' });
      } else {
        saved = await notesApi.create(values);
        setFeedback({ type: 'success', message: 'Nota guardada y cifrada correctamente.' });
      }

      setDetailRequest(null);
      setDetailState({ status: 'ready', note: saved, error: '' });
      setSelectedNoteId(saved.id);
      setPanelMode('view');
      triggerReload();
    } catch (err) {
      if (isSessionAuthError(err)) {
        resetSession();
        return;
      }
      setFormError(err.message || 'No se pudo guardar la nota.');
    } finally {
      setIsSaving(false);
    }
  }

  async function handleDeleteNote(noteId) {
    setDeletingId(noteId);
    setFeedback({ type: 'success', message: '' });

    try {
      await notesApi.remove(noteId);
      if (selectedNoteId === noteId) {
        setSelectedNoteId(null);
        setDetailRequest(null);
        setDetailState({ status: 'idle', note: null, error: '' });
        setPanelMode('idle');
      }
      setFeedback({ type: 'success', message: 'Nota eliminada permanentemente.' });
      triggerReload();
    } catch (err) {
      if (isSessionAuthError(err)) {
        resetSession();
        return;
      }
      setFeedback({
        type: 'error',
        message: err.message || 'No se pudo eliminar la nota.',
      });
    } finally {
      setDeletingId(null);
    }
  }

  function renderRightPanel() {
    if (panelMode === 'create') {
      return (
        <NoteForm
          key="create-note"
          onSubmit={handleSaveNote}
          onCancel={() => {
            setPanelMode('idle');
            setFormError('');
          }}
          isSubmitting={isSaving}
          serverError={formError}
          onDismissError={() => setFormError('')}
        />
      );
    }

    if (panelMode === 'edit') {
      if (detailState.status === 'loading') {
        return (
          <div className="sv-status-box" role="status" aria-live="polite">
            Cargando nota para editar…
          </div>
        );
      }
      if (detailState.status === 'error') {
        return (
          <AlertBanner
            type="error"
            message={detailState.error}
            actionLabel="Cerrar"
            onAction={() => setPanelMode('idle')}
          />
        );
      }
      if (detailState.note) {
        return (
          <NoteForm
            key={`edit-${detailState.note.id}`}
            initialNote={detailState.note}
            onSubmit={handleSaveNote}
            onCancel={() => {
              setPanelMode('view');
              setFormError('');
            }}
            isSubmitting={isSaving}
            serverError={formError}
            onDismissError={() => setFormError('')}
          />
        );
      }
    }

    if (panelMode === 'view') {
      if (detailState.status === 'loading') {
        return (
          <div className="sv-status-box" role="status" aria-live="polite">
            Descifrando nota…
          </div>
        );
      }
      if (detailState.status === 'error') {
        return (
          <AlertBanner
            type="error"
            message={detailState.error}
            actionLabel="Reintentar"
            onAction={() => {
              if (selectedNoteId) {
                requestNoteDetail(selectedNoteId);
              }
            }}
          />
        );
      }
      if (detailState.note) {
        const note = detailState.note;
        return (
          <article className="sv-card" aria-labelledby="note-detail-heading">
            <div className="sv-detail-header">
              <div>
                <h2 id="note-detail-heading" className="sv-detail-title">
                  {note.title}
                </h2>
                <div className="sv-note-meta">
                  <span className="sv-badge">
                    {CATEGORY_LABELS[note.category] || note.category}
                  </span>
                  <span className="sv-badge sv-badge-key">
                    Llave v{note.key_version}
                  </span>
                </div>
              </div>
              <div className="sv-actions">
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  onClick={() => setPanelMode('edit')}
                >
                  Editar nota
                </button>
                <button
                  type="button"
                  className="sv-btn sv-btn-secondary sv-btn-sm"
                  onClick={() => {
                    setSelectedNoteId(null);
                    setDetailState({ status: 'idle', note: null, error: '' });
                    setPanelMode('idle');
                  }}
                >
                  Cerrar vista
                </button>
              </div>
            </div>
            <pre className="sv-detail-content">{note.content}</pre>
          </article>
        );
      }
    }

    return (
      <div className="sv-empty-card">
        <h2 className="sv-empty-title">Selecciona una nota o crea una nueva</h2>
        <p className="sv-empty-text">
          Cada nota se descifra bajo demanda en el servidor y se muestra solo en esta sesión.
        </p>
        <button
          type="button"
          className="sv-btn sv-btn-primary"
          onClick={handleStartCreate}
        >
          Nueva nota
        </button>
      </div>
    );
  }

  return (
    <Layout>
      <div className="sv-vault-header">
        <h1 className="sv-vault-title">Bóveda de notas cifradas</h1>
        <button
          type="button"
          className="sv-btn sv-btn-primary"
          onClick={handleStartCreate}
        >
          Nueva nota
        </button>
      </div>

      <AlertBanner
        type={feedback.type}
        message={feedback.message}
        onDismiss={() => setFeedback({ type: 'success', message: '' })}
      />

      <div className="sv-vault-grid">
        <NoteList
          notes={listState.items}
          meta={listState.meta}
          status={listState.status}
          error={listState.error}
          selectedNoteId={selectedNoteId}
          categoryFilter={categoryFilter}
          onCategoryChange={handleCategoryChange}
          onPageChange={(nextPage) => setPage(nextPage)}
          onSelectNote={handleSelectNote}
          onEditNote={handleStartEdit}
          onDeleteNote={handleDeleteNote}
          onRetry={triggerReload}
          onCreateFirst={handleStartCreate}
          deletingId={deletingId}
        />

        <div>{renderRightPanel()}</div>
      </div>
    </Layout>
  );
}

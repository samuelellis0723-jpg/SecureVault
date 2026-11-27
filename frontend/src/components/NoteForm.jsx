import { useState } from 'react';
import { CATEGORY_LABELS, NOTE_CATEGORIES } from '../api/client';
import { AlertBanner } from './AlertBanner';

const MAX_TITLE_LENGTH = 200;
const MAX_CONTENT_LENGTH = 50000;

function validateNoteFields({ title, category, content }) {
  const errors = {};
  const trimmedTitle = title.trim();
  const trimmedContent = content.trim();

  if (!trimmedTitle) {
    errors.title = 'El título es obligatorio.';
  } else if (trimmedTitle.length > MAX_TITLE_LENGTH) {
    errors.title = `El título no puede superar ${MAX_TITLE_LENGTH} caracteres.`;
  }

  if (!NOTE_CATEGORIES.includes(category)) {
    errors.category = 'Selecciona una categoría válida.';
  }

  if (!trimmedContent) {
    errors.content = 'El contenido de la nota es obligatorio.';
  } else if (trimmedContent.length > MAX_CONTENT_LENGTH) {
    errors.content = `El contenido no puede superar ${MAX_CONTENT_LENGTH} caracteres.`;
  }

  return errors;
}

export function NoteForm({
  initialNote = null,
  onSubmit,
  onCancel,
  isSubmitting = false,
  serverError = '',
  onDismissError,
}) {
  const isEditing = Boolean(initialNote && initialNote.id);
  const [title, setTitle] = useState(initialNote ? initialNote.title : '');
  const [category, setCategory] = useState(
    initialNote && NOTE_CATEGORIES.includes(initialNote.category)
      ? initialNote.category
      : 'general'
  );
  const [content, setContent] = useState(initialNote ? initialNote.content : '');
  const [errors, setErrors] = useState({});

  function handleSubmit(event) {
    event.preventDefault();
    const nextErrors = validateNoteFields({ title, category, content });
    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    setErrors({});
    onSubmit({
      title: title.trim(),
      category,
      content: content.trim(),
    });
  }

  return (
    <section className="sv-card" aria-labelledby="note-form-heading">
      <h2 id="note-form-heading" className="sv-card-title">
        {isEditing ? 'Editar nota cifrada' : 'Nueva nota cifrada'}
      </h2>
      <p className="sv-card-subtitle">
        El título y el contenido se cifran en servidor con AES-256-GCM antes de almacenarse.
      </p>

      <AlertBanner type="error" message={serverError} onDismiss={onDismissError} />

      <form className="sv-form" onSubmit={handleSubmit} noValidate>
        <div className="sv-field">
          <label htmlFor="note-title" className="sv-label">
            Título
          </label>
          <input
            id="note-title"
            name="title"
            type="text"
            className="sv-input"
            maxLength={MAX_TITLE_LENGTH}
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              if (errors.title) setErrors((prev) => ({ ...prev, title: '' }));
            }}
            aria-invalid={Boolean(errors.title)}
            aria-describedby={errors.title ? 'note-title-error' : undefined}
            required
          />
          {errors.title && (
            <p id="note-title-error" className="sv-field-error" role="alert">
              {errors.title}
            </p>
          )}
        </div>

        <div className="sv-field">
          <label htmlFor="note-category" className="sv-label">
            Categoría
          </label>
          <select
            id="note-category"
            name="category"
            className="sv-select"
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              if (errors.category) setErrors((prev) => ({ ...prev, category: '' }));
            }}
            aria-invalid={Boolean(errors.category)}
            aria-describedby={errors.category ? 'note-category-error' : undefined}
          >
            {NOTE_CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {CATEGORY_LABELS[cat]}
              </option>
            ))}
          </select>
          {errors.category && (
            <p id="note-category-error" className="sv-field-error" role="alert">
              {errors.category}
            </p>
          )}
        </div>

        <div className="sv-field">
          <label htmlFor="note-content" className="sv-label">
            Contenido
          </label>
          <textarea
            id="note-content"
            name="content"
            className="sv-textarea"
            maxLength={MAX_CONTENT_LENGTH}
            value={content}
            onChange={(e) => {
              setContent(e.target.value);
              if (errors.content) setErrors((prev) => ({ ...prev, content: '' }));
            }}
            aria-invalid={Boolean(errors.content)}
            aria-describedby={errors.content ? 'note-content-error' : 'note-content-hint'}
            required
          />
          <p id="note-content-hint" className="sv-hint">
            {content.length} / {MAX_CONTENT_LENGTH} caracteres
          </p>
          {errors.content && (
            <p id="note-content-error" className="sv-field-error" role="alert">
              {errors.content}
            </p>
          )}
        </div>

        <div className="sv-actions">
          <button
            type="submit"
            className="sv-btn sv-btn-primary"
            disabled={isSubmitting}
          >
            {isSubmitting
              ? 'Guardando…'
              : isEditing
                ? 'Guardar cambios'
                : 'Guardar nota'}
          </button>
          <button
            type="button"
            className="sv-btn sv-btn-secondary"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            Cancelar
          </button>
        </div>
      </form>
    </section>
  );
}

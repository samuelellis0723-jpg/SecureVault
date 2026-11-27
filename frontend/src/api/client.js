const API_BASE = '/api/v1';

const MUTATING_METHODS = new Set(['POST', 'PATCH', 'DELETE']);

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const NOTE_CATEGORIES = [
  'general',
  'personal',
  'finanzas',
  'credenciales',
  'documentos',
];

export const CATEGORY_LABELS = {
  general: 'General',
  personal: 'Personal',
  finanzas: 'Finanzas',
  credenciales: 'Credenciales',
  documentos: 'Documentos',
};

const FALLBACK_ERROR_MESSAGES = {
  VALIDATION_ERROR: 'Revisa los datos ingresados e inténtalo de nuevo.',
  UNAUTHORIZED: 'Tu sesión ha expirado. Inicia sesión nuevamente.',
  MFA_REQUIRED: 'Debes completar la verificación de dos pasos (TOTP).',
  INVALID_CREDENTIALS: 'Correo electrónico o contraseña incorrectos.',
  INVALID_TOTP_CODE: 'El código de 6 dígitos no es válido o ya expiró.',
  INVALID_RECOVERY_CODE: 'El código de recuperación no es válido o ya fue utilizado.',
  CSRF_INVALID: 'La verificación de seguridad (CSRF) falló. Recarga e inténtalo de nuevo.',
  REGISTRATION_DISABLED: 'El registro de nuevas cuentas está deshabilitado.',
  FORBIDDEN: 'No tienes permiso para realizar esta acción.',
  NOT_FOUND: 'El recurso solicitado no existe o no está disponible.',
  EMAIL_ALREADY_EXISTS: 'Ya existe una cuenta registrada con este correo electrónico.',
  TOTP_ALREADY_ENABLED: 'La autenticación de dos pasos ya está activada en esta cuenta.',
  ACCOUNT_LOCKED: 'Cuenta bloqueada temporalmente por demasiados intentos fallidos. Espera 15 minutos.',
  RATE_LIMITED: 'Demasiadas solicitudes. Espera un momento e inténtalo nuevamente.',
  INTERNAL_ERROR: 'Ocurrió un error interno en el servidor. Inténtalo más tarde.',
  NETWORK_ERROR: 'No se pudo conectar con el servidor. Verifica tu conexión e inténtalo de nuevo.',
};

// Token CSRF mantenido exclusivamente en memoria del proceso JS (nunca en storage del navegador).
let csrfToken = null;

export function getCsrfToken() {
  return csrfToken;
}

export function setCsrfToken(token) {
  csrfToken = typeof token === 'string' && token.length > 0 ? token : null;
}

export function clearCsrfToken() {
  csrfToken = null;
}

export function isValidUuid(value) {
  return typeof value === 'string' && UUID_REGEX.test(value);
}

export class ApiError extends Error {
  constructor({ status = 0, code = 'UNKNOWN_ERROR', message, details = null }) {
    const safeMessage =
      message ||
      FALLBACK_ERROR_MESSAGES[code] ||
      'No se pudo completar la solicitud.';
    super(safeMessage);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function buildHeaders({ method, hasBody }) {
  const headers = {
    Accept: 'application/json',
  };

  if (hasBody) {
    headers['Content-Type'] = 'application/json; charset=utf-8';
  }

  if (MUTATING_METHODS.has(method) && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  return headers;
}

async function parseJsonSafely(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export async function apiRequest(path, { method = 'GET', body, signal } = {}) {
  const upperMethod = method.toUpperCase();
  const hasBody = body !== undefined;

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: upperMethod,
      credentials: 'same-origin',
      headers: buildHeaders({ method: upperMethod, hasBody }),
      body: hasBody ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw err;
    }
    throw new ApiError({
      status: 0,
      code: 'NETWORK_ERROR',
      message: FALLBACK_ERROR_MESSAGES.NETWORK_ERROR,
    });
  }

  const payload = await parseJsonSafely(response);

  if (!response.ok || !payload || payload.success === false) {
    const errObj = payload && payload.error ? payload.error : {};
    const code = errObj.code || (response.status >= 500 ? 'INTERNAL_ERROR' : 'HTTP_ERROR');
    throw new ApiError({
      status: response.status,
      code,
      message: errObj.message || FALLBACK_ERROR_MESSAGES[code],
      details: errObj.details ?? null,
    });
  }

  if (payload.data && typeof payload.data.csrf_token === 'string') {
    setCsrfToken(payload.data.csrf_token);
  }

  return payload;
}

function assertValidNoteId(id) {
  if (!isValidUuid(id)) {
    throw new ApiError({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'El identificador de la nota no es válido.',
    });
  }
}

export const authApi = {
  async register({ email, password }) {
    const payload = await apiRequest('/auth/register', {
      method: 'POST',
      body: { email: email.trim(), password },
    });
    return payload.data;
  },

  async login({ email, password }) {
    const payload = await apiRequest('/auth/login', {
      method: 'POST',
      body: { email: email.trim(), password },
    });
    return payload.data;
  },

  async confirmTotp({ code }) {
    const payload = await apiRequest('/auth/totp/confirm', {
      method: 'POST',
      body: { code: code.trim() },
    });
    return payload.data;
  },

  async verifyTotp({ code, recoveryCode }) {
    const body = recoveryCode
      ? { recovery_code: recoveryCode.trim() }
      : { code: String(code || '').trim() };
    const payload = await apiRequest('/auth/totp/verify', {
      method: 'POST',
      body,
    });
    return payload.data;
  },

  async logout() {
    try {
      const payload = await apiRequest('/auth/logout', {
        method: 'POST',
      });
      return payload.data;
    } finally {
      clearCsrfToken();
    }
  },

  async me({ signal } = {}) {
    const payload = await apiRequest('/auth/me', {
      method: 'GET',
      signal,
    });
    return payload.data;
  },
};

export const notesApi = {
  async list({ page = 1, limit = 20, category = '', signal } = {}) {
    const params = new URLSearchParams();
    params.set('page', String(page));
    params.set('limit', String(limit));
    if (category && NOTE_CATEGORIES.includes(category)) {
      params.set('category', category);
    }

    const payload = await apiRequest(`/notes?${params.toString()}`, {
      method: 'GET',
      signal,
    });

    return {
      items: Array.isArray(payload.data) ? payload.data : [],
      meta: payload.meta || { total: 0, page, limit, totalPages: 0 },
    };
  },

  async getById(id, { signal } = {}) {
    assertValidNoteId(id);
    const payload = await apiRequest(`/notes/${encodeURIComponent(id)}`, {
      method: 'GET',
      signal,
    });
    return payload.data;
  },

  async create({ title, content, category }) {
    const payload = await apiRequest('/notes', {
      method: 'POST',
      body: {
        title: title.trim(),
        content: content.trim(),
        category,
      },
    });
    return payload.data;
  },

  async update(id, { title, content, category }) {
    assertValidNoteId(id);
    const body = {};
    if (title !== undefined) body.title = title.trim();
    if (content !== undefined) body.content = content.trim();
    if (category !== undefined) body.category = category;

    const payload = await apiRequest(`/notes/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body,
    });
    return payload.data;
  },

  async remove(id) {
    assertValidNoteId(id);
    const payload = await apiRequest(`/notes/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    return payload.data;
  },
};

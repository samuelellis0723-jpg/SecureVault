import {
  ApiError,
  authApi,
  clearCsrfToken,
  getCsrfToken,
  notesApi,
  setCsrfToken,
} from '../api/client';

function createJsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

describe('API client (CSRF en memoria, credenciales same-origin y errores)', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearCsrfToken();
    global.fetch = jest.fn();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  test('guarda csrf_token solo en memoria desde me, register y login y envía X-CSRF-Token en POST, PATCH y DELETE', async () => {
    const setItemSpy = jest.spyOn(Storage.prototype, 'setItem');
    const getItemSpy = jest.spyOn(Storage.prototype, 'getItem');

    const noteId = '660e8400-e29b-41d4-a716-446655440001';

    global.fetch
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            authenticated: true,
            user: { id: 'u1', email: 'ana@ejemplo.com' },
            csrf_token: 'csrf-token-inicial',
          },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse(
          {
            success: true,
            data: {
              id: noteId,
              title: 'Nota 1',
              content: 'Secreto',
              category: 'finanzas',
              key_version: 1,
            },
          },
          201
        )
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            id: noteId,
            title: 'Nota 1 editada',
            content: 'Secreto 2',
            category: 'documentos',
            key_version: 1,
          },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: { deleted: true },
        })
      );

    await authApi.me();
    expect(getCsrfToken()).toBe('csrf-token-inicial');

    // GET no debe incluir X-CSRF-Token pero sí credentials: 'same-origin'
    expect(global.fetch).toHaveBeenNthCalledWith(
      1,
      '/api/v1/auth/me',
      expect.objectContaining({
        method: 'GET',
        credentials: 'same-origin',
      })
    );
    expect(global.fetch.mock.calls[0][1].headers['X-CSRF-Token']).toBeUndefined();

    // POST /notes envía X-CSRF-Token
    await notesApi.create({ title: 'Nota 1', content: 'Secreto', category: 'finanzas' });
    expect(global.fetch.mock.calls[1][1].headers['X-CSRF-Token']).toBe('csrf-token-inicial');
    expect(global.fetch.mock.calls[1][1].credentials).toBe('same-origin');

    // PATCH /notes/:id envía X-CSRF-Token
    await notesApi.update(noteId, {
      title: 'Nota 1 editada',
      content: 'Secreto 2',
      category: 'documentos',
    });
    expect(global.fetch.mock.calls[2][1].headers['X-CSRF-Token']).toBe('csrf-token-inicial');

    // DELETE /notes/:id envía X-CSRF-Token
    await notesApi.remove(noteId);
    expect(global.fetch.mock.calls[3][1].headers['X-CSRF-Token']).toBe('csrf-token-inicial');

    // Nunca se accede a localStorage ni sessionStorage
    expect(setItemSpy).not.toHaveBeenCalled();
    expect(getItemSpy).not.toHaveBeenCalled();

    setItemSpy.mockRestore();
    getItemSpy.mockRestore();
  });

  test('register y login almacenan csrf_token en memoria y no exponen métodos TOTP', async () => {
    expect(authApi.confirmTotp).toBeUndefined();
    expect(authApi.verifyTotp).toBeUndefined();

    global.fetch
      .mockResolvedValueOnce(
        createJsonResponse(
          {
            success: true,
            data: {
              user: { id: 'u-reg', email: 'nuevo@ejemplo.com' },
              csrf_token: 'csrf-register',
            },
          },
          201
        )
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            user: { id: 'u-log', email: 'ana@ejemplo.com' },
            csrf_token: 'csrf-login',
          },
        })
      );

    await authApi.register({ email: ' nuevo@ejemplo.com ', password: 'MiPasswordSegura#2026' });
    expect(getCsrfToken()).toBe('csrf-register');

    await authApi.login({ email: ' ana@ejemplo.com ', password: 'MiPasswordSegura#2026' });
    expect(getCsrfToken()).toBe('csrf-login');
  });

  test('limpia csrf_token de memoria al cerrar sesión incluso si falla el servidor', async () => {
    setCsrfToken('csrf-activo');
    global.fetch.mockResolvedValueOnce(
      createJsonResponse(
        {
          success: false,
          error: { code: 'UNAUTHORIZED', message: 'Sesión expirada' },
        },
        401
      )
    );

    await expect(authApi.logout()).rejects.toBeInstanceOf(ApiError);
    expect(getCsrfToken()).toBeNull();
  });

  test('rechaza IDs de nota que no son UUID válidos antes de consultar la API', async () => {
    await expect(notesApi.getById('no-es-uuid')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      status: 400,
    });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('convierte errores de red en ApiError seguro NETWORK_ERROR', async () => {
    global.fetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

    await expect(notesApi.list()).rejects.toMatchObject({
      name: 'ApiError',
      code: 'NETWORK_ERROR',
      status: 0,
    });
  });
});

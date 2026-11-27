import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { clearCsrfToken } from '../api/client';
import { AuthProvider } from '../context/AuthContext';
import { AppRoutes } from '../routes/AppRoutes';

function createJsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function renderVault() {
  return render(
    <MemoryRouter initialEntries={['/vault']}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </MemoryRouter>
  );
}

const AUTH_ME_OK = {
  success: true,
  data: {
    authenticated: true,
    mfa_verified: true,
    user: {
      id: '550e8400-e29b-41d4-a716-446655440000',
      email: 'ana@ejemplo.com',
      totp_enabled: true,
    },
    csrf_token: 'csrf-vault-token',
  },
};

const NOTE_ID_1 = '660e8400-e29b-41d4-a716-446655440001';
const NOTE_ID_2 = '660e8400-e29b-41d4-a716-446655440002';

describe('Bóveda de notas cifradas (estados UI, CRUD, filtrado y CSRF)', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearCsrfToken();
    global.fetch = jest.fn();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  test('muestra estado empty cuando el usuario no tiene notas', async () => {
    global.fetch
      .mockResolvedValueOnce(createJsonResponse(AUTH_ME_OK))
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      );

    renderVault();

    expect(await screen.findByText(/tu bóveda está vacía/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /crear primera nota/i })).toBeInTheDocument();
  });

  test('crea, visualiza, edita y elimina una nota enviando X-CSRF-Token en cada mutación', async () => {
    const user = userEvent.setup();

    const createdNote = {
      id: NOTE_ID_1,
      title: 'Llave de respaldo banco',
      content: 'PIN de emergencia 9012',
      category: 'finanzas',
      key_version: 1,
      created_at: '2026-11-26T18:00:00Z',
      updated_at: '2026-11-26T18:00:00Z',
    };

    const updatedNote = {
      ...createdNote,
      title: 'Llave banco actualizada',
      content: 'PIN actualizado 4455',
      category: 'documentos',
      updated_at: '2026-11-26T18:05:00Z',
    };

    global.fetch
      // 1. GET /auth/me
      .mockResolvedValueOnce(createJsonResponse(AUTH_ME_OK))
      // 2. GET /notes inicial (vacío)
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      )
      // 3. POST /notes (crear)
      .mockResolvedValueOnce(createJsonResponse({ success: true, data: createdNote }, 201))
      // 4. GET /notes (recarga tras crear)
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [
            {
              id: createdNote.id,
              title: createdNote.title,
              category: createdNote.category,
              key_version: 1,
              created_at: createdNote.created_at,
              updated_at: createdNote.updated_at,
            },
          ],
          meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
        })
      )
      // 5. PATCH /notes/:id (editar)
      .mockResolvedValueOnce(createJsonResponse({ success: true, data: updatedNote }))
      // 6. GET /notes (recarga tras editar)
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [
            {
              id: updatedNote.id,
              title: updatedNote.title,
              category: updatedNote.category,
              key_version: 1,
              created_at: updatedNote.created_at,
              updated_at: updatedNote.updated_at,
            },
          ],
          meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
        })
      )
      // 7. DELETE /notes/:id
      .mockResolvedValueOnce(createJsonResponse({ success: true, data: { deleted: true } }))
      // 8. GET /notes (recarga tras eliminar -> vacío)
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      );

    renderVault();

    // Crear primera nota
    await user.click(await screen.findByRole('button', { name: /crear primera nota/i }));
    await user.type(screen.getByLabelText(/título/i), 'Llave de respaldo banco');
    await user.selectOptions(screen.getByLabelText(/^categoría$/i), 'finanzas');
    await user.type(screen.getByLabelText(/contenido/i), 'PIN de emergencia 9012');
    await user.click(screen.getByRole('button', { name: /guardar nota/i }));

    // Verifica detalle descifrado y cabecera CSRF en POST
    expect(await screen.findByText('PIN de emergencia 9012')).toBeInTheDocument();
    const postCall = global.fetch.mock.calls.find(
      ([url, opts]) => url === '/api/v1/notes' && opts.method === 'POST'
    );
    expect(postCall[1].headers['X-CSRF-Token']).toBe('csrf-vault-token');

    // Editar nota
    await user.click(screen.getByRole('button', { name: /editar nota/i }));
    const titleInput = await screen.findByLabelText(/título/i);
    await user.clear(titleInput);
    await user.type(titleInput, 'Llave banco actualizada');
    await user.selectOptions(screen.getByLabelText(/^categoría$/i), 'documentos');
    const contentInput = screen.getByLabelText(/contenido/i);
    await user.clear(contentInput);
    await user.type(contentInput, 'PIN actualizado 4455');
    await user.click(screen.getByRole('button', { name: /guardar cambios/i }));

    expect(await screen.findByText('PIN actualizado 4455')).toBeInTheDocument();
    const patchCall = global.fetch.mock.calls.find(
      ([url, opts]) => url === `/api/v1/notes/${NOTE_ID_1}` && opts.method === 'PATCH'
    );
    expect(patchCall[1].headers['X-CSRF-Token']).toBe('csrf-vault-token');

    // Eliminar nota con confirmación accesible en dos pasos
    await user.click(
      await screen.findByRole('button', { name: /eliminar llave banco actualizada/i })
    );
    await user.click(screen.getByRole('button', { name: /confirmar eliminación/i }));

    const deleteCall = global.fetch.mock.calls.find(
      ([url, opts]) => url === `/api/v1/notes/${NOTE_ID_1}` && opts.method === 'DELETE'
    );
    expect(deleteCall[1].headers['X-CSRF-Token']).toBe('csrf-vault-token');
    expect(await screen.findByText(/tu bóveda está vacía/i)).toBeInTheDocument();
  });

  test('filtra notas por categoría enviando query param category al backend', async () => {
    const user = userEvent.setup();

    global.fetch
      .mockResolvedValueOnce(createJsonResponse(AUTH_ME_OK))
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [
            {
              id: NOTE_ID_1,
              title: 'Cuenta bancaria',
              category: 'finanzas',
              key_version: 1,
              created_at: '2026-11-26T18:00:00Z',
              updated_at: '2026-11-26T18:00:00Z',
            },
            {
              id: NOTE_ID_2,
              title: 'SSH prod',
              category: 'credenciales',
              key_version: 1,
              created_at: '2026-11-26T18:01:00Z',
              updated_at: '2026-11-26T18:01:00Z',
            },
          ],
          meta: { total: 2, page: 1, limit: 20, totalPages: 1 },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [
            {
              id: NOTE_ID_2,
              title: 'SSH prod',
              category: 'credenciales',
              key_version: 1,
              created_at: '2026-11-26T18:01:00Z',
              updated_at: '2026-11-26T18:01:00Z',
            },
          ],
          meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
        })
      );

    renderVault();

    const list = await screen.findByRole('list', { name: /listado de notas cifradas/i });
    expect(within(list).getByText('Cuenta bancaria')).toBeInTheDocument();
    expect(within(list).getByText('SSH prod')).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText(/filtrar por categoría/i), 'credenciales');

    expect(await screen.findByText('SSH prod')).toBeInTheDocument();
    expect(screen.queryByText('Cuenta bancaria')).not.toBeInTheDocument();
    expect(global.fetch).toHaveBeenLastCalledWith(
      '/api/v1/notes?page=1&limit=20&category=credenciales',
      expect.objectContaining({ method: 'GET' })
    );
  });

  test('muestra error con role="alert" ante fallo de red y permite reintentar', async () => {
    const user = userEvent.setup();

    global.fetch
      .mockResolvedValueOnce(createJsonResponse(AUTH_ME_OK))
      .mockRejectedValueOnce(new TypeError('Network failure'))
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      );

    renderVault();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/no se pudo conectar con el servidor/i);
    expect(screen.queryByText(/cargando notas cifradas/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /reintentar/i }));
    expect(await screen.findByText(/tu bóveda está vacía/i)).toBeInTheDocument();
  });

  test('seleccionar una nota del listado descarga y muestra el detalle descifrado', async () => {
    const user = userEvent.setup();

    global.fetch
      .mockResolvedValueOnce(createJsonResponse(AUTH_ME_OK))
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [
            {
              id: NOTE_ID_1,
              title: 'Respaldo pasaporte',
              category: 'documentos',
              key_version: 2,
              created_at: '2026-11-26T18:00:00Z',
              updated_at: '2026-11-26T18:00:00Z',
            },
          ],
          meta: { total: 1, page: 1, limit: 20, totalPages: 1 },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            id: NOTE_ID_1,
            title: 'Respaldo pasaporte',
            content: 'Número: P987654321 · Expira 2031',
            category: 'documentos',
            key_version: 2,
            created_at: '2026-11-26T18:00:00Z',
            updated_at: '2026-11-26T18:00:00Z',
          },
        })
      );

    renderVault();

    await user.click(await screen.findByRole('button', { name: /^respaldo pasaporte/i }));

    expect(await screen.findByText('Número: P987654321 · Expira 2031')).toBeInTheDocument();
    expect(screen.getByText(/llave v2/i)).toBeInTheDocument();
  });
});

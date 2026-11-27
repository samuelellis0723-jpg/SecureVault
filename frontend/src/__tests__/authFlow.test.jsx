import { render, screen } from '@testing-library/react';
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

function renderApp(initialEntries = ['/login']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('Flujos de autenticación estándar (registro, login, logout y rutas protegidas)', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearCsrfToken();
    global.fetch = jest.fn();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  test('registro directo autentica al usuario, redirige a /vault y muestra la bóveda sin usar localStorage', async () => {
    const user = userEvent.setup();
    const setItemSpy = jest.spyOn(Storage.prototype, 'setItem');

    global.fetch
      // 1. GET /auth/me inicial -> 401
      .mockResolvedValueOnce(
        createJsonResponse(
          { success: false, error: { code: 'UNAUTHORIZED', message: 'No autenticado' } },
          401
        )
      )
      // 2. POST /auth/register -> 201 directo con usuario y csrf_token
      .mockResolvedValueOnce(
        createJsonResponse(
          {
            success: true,
            data: {
              user: {
                id: '550e8400-e29b-41d4-a716-446655440000',
                email: 'nuevo@ejemplo.com',
              },
              csrf_token: 'csrf-registro-directo',
            },
          },
          201
        )
      )
      // 3. GET /notes al entrar a la bóveda -> vacío
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      );

    renderApp(['/register']);

    const emailInput = await screen.findByLabelText(/correo electrónico/i);
    await user.type(emailInput, 'nuevo@ejemplo.com');
    await user.type(screen.getByLabelText(/contraseña maestra/i), 'MiPasswordSegura#2026');
    await user.type(screen.getByLabelText(/confirmar contraseña/i), 'MiPasswordSegura#2026');
    await user.click(screen.getByRole('button', { name: /^crear cuenta$/i }));

    expect(
      await screen.findByRole('heading', { name: /bóveda de notas cifradas/i })
    ).toBeInTheDocument();
    expect(await screen.findByText(/tu bóveda está vacía/i)).toBeInTheDocument();
    expect(screen.getByText('nuevo@ejemplo.com')).toBeInTheDocument();

    expect(setItemSpy).not.toHaveBeenCalled();
    setItemSpy.mockRestore();
  });

  test('login directo redirige a /vault y muestra la bóveda', async () => {
    const user = userEvent.setup();

    global.fetch
      .mockResolvedValueOnce(
        createJsonResponse(
          { success: false, error: { code: 'UNAUTHORIZED', message: 'Sin sesión' } },
          401
        )
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            user: {
              id: '550e8400-e29b-41d4-a716-446655440000',
              email: 'ana@ejemplo.com',
            },
            csrf_token: 'csrf-login-directo',
          },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      );

    renderApp(['/login']);

    await user.type(await screen.findByLabelText(/correo electrónico/i), 'ana@ejemplo.com');
    await user.type(screen.getByLabelText(/^contraseña$/i), 'MiPasswordSegura#2026');
    await user.click(screen.getByRole('button', { name: /^iniciar sesión$/i }));

    expect(
      await screen.findByRole('heading', { name: /bóveda de notas cifradas/i })
    ).toBeInTheDocument();
    expect(screen.getByText('ana@ejemplo.com')).toBeInTheDocument();
  });

  test('cerrar sesión envía X-CSRF-Token y redirige a /login', async () => {
    const user = userEvent.setup();

    global.fetch
      // 1. GET /auth/me autenticado
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            authenticated: true,
            user: {
              id: '550e8400-e29b-41d4-a716-446655440000',
              email: 'ana@ejemplo.com',
            },
            csrf_token: 'csrf-sesion-activa',
          },
        })
      )
      // 2. GET /notes
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: [],
          meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
        })
      )
      // 3. POST /auth/logout
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: { logged_out: true },
        })
      );

    renderApp(['/vault']);

    expect(
      await screen.findByRole('heading', { name: /bóveda de notas cifradas/i })
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /cerrar sesión/i }));

    expect(await screen.findByRole('heading', { name: /iniciar sesión/i })).toBeInTheDocument();
    const logoutCall = global.fetch.mock.calls.find(
      ([url, opts]) => url === '/api/v1/auth/logout' && opts.method === 'POST'
    );
    expect(logoutCall).toBeDefined();
    expect(logoutCall[1].headers['X-CSRF-Token']).toBe('csrf-sesion-activa');
  });

  test('ruta protegida /vault sin sesión redirige a /login', async () => {
    global.fetch.mockResolvedValueOnce(
      createJsonResponse(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'Sin sesión' } },
        401
      )
    );

    renderApp(['/vault']);

    expect(await screen.findByRole('heading', { name: /iniciar sesión/i })).toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: /bóveda de notas cifradas/i })
    ).not.toBeInTheDocument();
  });

  test('muestra role="alert" cuando el login devuelve credenciales inválidas', async () => {
    const user = userEvent.setup();

    global.fetch
      .mockResolvedValueOnce(
        createJsonResponse(
          { success: false, error: { code: 'UNAUTHORIZED', message: 'Sin sesión' } },
          401
        )
      )
      .mockResolvedValueOnce(
        createJsonResponse(
          {
            success: false,
            error: {
              code: 'INVALID_CREDENTIALS',
              message: 'Correo o contraseña incorrectos.',
            },
          },
          401
        )
      );

    renderApp(['/login']);

    await user.type(await screen.findByLabelText(/correo electrónico/i), 'ana@ejemplo.com');
    await user.type(screen.getByLabelText(/^contraseña$/i), 'ClaveIncorrecta#2026');
    await user.click(screen.getByRole('button', { name: /^iniciar sesión$/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/correo o contraseña incorrectos/i);
  });
});

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

const SAMPLE_RECOVERY_CODES = [
  'ABCD-EFGH',
  'JKLM-NPQR',
  'STUV-WXYZ',
  '2345-6789',
  'A2B3-C4D5',
  'E6F7-G8H9',
  'J2K3-L4M5',
  'N6P7-Q8R9',
];

const SAMPLE_QR_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>';

describe('Flujos de autenticación, TOTP y códigos de recuperación', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearCsrfToken();
    global.fetch = jest.fn();
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  test('flujo de registro -> QR TOTP seguro como data URI -> confirmación -> muestra 8 códigos de recuperación sin usar localStorage', async () => {
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
      // 2. POST /auth/register -> 201 con qr_svg
      .mockResolvedValueOnce(
        createJsonResponse(
          {
            success: true,
            data: {
              csrf_token: 'csrf-pre-mfa-reg',
              totp: {
                otpauth_uri: 'otpauth://totp/SecurityVault:nuevo%40ejemplo.com?secret=JBSWY3DPEHPK3PXP',
                secret_base32: 'JBSWY3DPEHPK3PXP',
                qr_svg: SAMPLE_QR_SVG,
              },
            },
          },
          201
        )
      )
      // 3. POST /auth/totp/confirm -> 200 con 8 recovery_codes
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            user: {
              id: '550e8400-e29b-41d4-a716-446655440000',
              email: 'nuevo@ejemplo.com',
              totp_enabled: true,
            },
            csrf_token: 'csrf-completo-reg',
            recovery_codes: SAMPLE_RECOVERY_CODES,
          },
        })
      )
      // 4. GET /notes al entrar a la bóveda -> vacío
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
    await user.click(screen.getByRole('button', { name: /crear cuenta y configurar mfa/i }));

    // Verifica QR seguro renderizado vía <img src="data:image/svg+xml;charset=utf-8,...">
    const qrImg = await screen.findByRole('img', {
      name: /código qr para configurar autenticador totp/i,
    });
    expect(qrImg.getAttribute('src')).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    // Confirmar código TOTP de 6 dígitos
    await user.type(screen.getByLabelText(/código de verificación/i), '123456');
    await user.click(screen.getByRole('button', { name: /confirmar y activar mfa/i }));

    // Verificar cabecera X-CSRF-Token enviada en confirmTotp
    expect(global.fetch.mock.calls[2][0]).toBe('/api/v1/auth/totp/confirm');
    expect(global.fetch.mock.calls[2][1].headers['X-CSRF-Token']).toBe('csrf-pre-mfa-reg');

    // Modal de 8 códigos de recuperación visible en la bóveda
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    for (const code of SAMPLE_RECOVERY_CODES) {
      expect(screen.getByText(code)).toBeInTheDocument();
    }

    // Confirmar que ya los guardó cierra el modal y muestra estado vacío de la bóveda
    await user.click(screen.getByRole('button', { name: /ya los guardé/i }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(await screen.findByText(/tu bóveda está vacía/i)).toBeInTheDocument();

    expect(setItemSpy).not.toHaveBeenCalled();
    setItemSpy.mockRestore();
  });

  test('flujo de login -> verificación TOTP de 6 dígitos -> acceso a la bóveda', async () => {
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
            mfa_required: true,
            totp_enrolled: true,
            csrf_token: 'csrf-pre-login',
          },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            user: {
              id: '550e8400-e29b-41d4-a716-446655440000',
              email: 'ana@ejemplo.com',
              totp_enabled: true,
            },
            csrf_token: 'csrf-post-mfa',
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
    await user.click(screen.getByRole('button', { name: /continuar/i }));

    const totpInput = await screen.findByLabelText(/código totp/i);
    await user.type(totpInput, '654321');
    await user.click(screen.getByRole('button', { name: /verificar y abrir bóveda/i }));

    expect(global.fetch.mock.calls[2][0]).toBe('/api/v1/auth/totp/verify');
    expect(global.fetch.mock.calls[2][1].headers['X-CSRF-Token']).toBe('csrf-pre-login');
    expect(JSON.parse(global.fetch.mock.calls[2][1].body)).toEqual({ code: '654321' });

    expect(
      await screen.findByRole('heading', { name: /bóveda de notas cifradas/i })
    ).toBeInTheDocument();
  });

  test('verificación MFA permite alternar a código de recuperación XXXX-XXXX', async () => {
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
            mfa_required: true,
            totp_enrolled: true,
            csrf_token: 'csrf-pre-recovery',
          },
        })
      )
      .mockResolvedValueOnce(
        createJsonResponse({
          success: true,
          data: {
            user: {
              id: '550e8400-e29b-41d4-a716-446655440000',
              email: 'ana@ejemplo.com',
              totp_enabled: true,
            },
            csrf_token: 'csrf-post-recovery',
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
    await user.click(screen.getByRole('button', { name: /continuar/i }));

    await user.click(await screen.findByRole('button', { name: /usar código de recuperación/i }));
    const recoveryInput = screen.getByLabelText(/código de recuperación/i);
    await user.type(recoveryInput, 'abcd-efgh');
    await user.click(screen.getByRole('button', { name: /verificar y abrir bóveda/i }));

    expect(global.fetch.mock.calls[2][0]).toBe('/api/v1/auth/totp/verify');
    expect(JSON.parse(global.fetch.mock.calls[2][1].body)).toEqual({
      recovery_code: 'ABCD-EFGH',
    });
    expect(
      await screen.findByRole('heading', { name: /bóveda de notas cifradas/i })
    ).toBeInTheDocument();
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
    await user.click(screen.getByRole('button', { name: /continuar/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/correo o contraseña incorrectos/i);
  });
});

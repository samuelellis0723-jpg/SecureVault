import { Navigate, Route, Routes } from 'react-router-dom';
import { ProtectedRoute } from '../components/ProtectedRoute';
import { LoginPage } from '../pages/LoginPage';
import { RegisterPage } from '../pages/RegisterPage';
import { TotpSetupPage } from '../pages/TotpSetupPage';
import { TotpVerifyPage } from '../pages/TotpVerifyPage';
import { VaultPage } from '../pages/VaultPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/totp-setup" element={<TotpSetupPage />} />
      <Route path="/totp-verify" element={<TotpVerifyPage />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/vault" element={<VaultPage />} />
      </Route>

      <Route path="/" element={<Navigate to="/vault" replace />} />
      <Route path="*" element={<Navigate to="/vault" replace />} />
    </Routes>
  );
}

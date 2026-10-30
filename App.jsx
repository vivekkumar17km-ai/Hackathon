import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import AppLayout from './components/layout/AppLayout';
import Overview from './pages/Overview';
import Register from './pages/Register';
import Verify from './pages/Verify';
import Compare from './pages/Compare';
import ProvenanceHistory from './pages/ProvenanceHistory';
import AuditLedger from './pages/AuditLedger';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Login from './pages/Login';
import RegisterUser from './pages/RegisterUser';
import Cases from './pages/Cases';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register-account" element={<RegisterUser />} />
          <Route path="/" element={<AppLayout />}>
            <Route index element={<Overview />} />
            <Route path="register" element={<Register />} />
            <Route path="verify" element={<Verify />} />
            <Route path="compare" element={<Compare />} />
            <Route path="history" element={<ProvenanceHistory />} />
            <Route path="ledger" element={<AuditLedger />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Settings />} />
            <Route path="cases" element={<Cases />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </ThemeProvider>
  );
}

import React, { useEffect, useState } from 'react';
import { App as AntApp, ConfigProvider, Spin, message, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { SetupStatus, User } from './api';
import AppLayout from './layout/AppLayout';
import Dashboard from './pages/Dashboard';
import EchoSettings from './pages/EchoSettings';
import IPIntel from './pages/IPIntel';
import Datasets from './pages/Datasets';
import IPChain from './pages/IPChain';
import Users from './pages/Users';
import Access from './pages/Access';
import Logs from './pages/Logs';
import Monitoring from './pages/Monitoring';
import Audit from './pages/Audit';
import Notifications from './pages/Notifications';
import Integrations from './pages/Integrations';
import Fingerprints from './pages/Fingerprints';
import Security from './pages/Security';
import System from './pages/System';
import Tools from './pages/Tools';
import ApiDocs from './pages/ApiDocs';
import Account from './pages/Account';
import Login from './pages/Login';
import Setup from './pages/Setup';

const TOKEN_KEY = 'echo_token';

const themeConfig = {
  algorithm: theme.defaultAlgorithm,
  token: {
    colorPrimary: '#5b5bd6',
    colorInfo: '#5b5bd6',
    colorSuccess: '#12b76a',
    colorWarning: '#f79009',
    colorError: '#f04438',
    borderRadius: 10,
    fontSize: 14,
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif',
    colorBgLayout: '#f4f6fb',
    colorText: '#0f172a',
    colorTextSecondary: '#64748b',
    controlHeight: 36,
  },
  components: {
    Card: { borderRadiusLG: 16 },
    Table: { headerBg: '#f7f9fc', headerColor: '#475569', rowHoverBg: '#f8faff', borderColor: '#eef2f7' },
    Menu: { itemBg: 'transparent', itemSelectedBg: '#eef2ff', itemSelectedColor: '#4f46e5' },
    Layout: { headerBg: '#ffffff', siderBg: '#ffffff' },
    Modal: { borderRadiusLG: 16 },
    Segmented: { trackBg: '#eef2f9' },
  },
};

const Loading: React.FC<{ text: string }> = ({ text }) => (
  <div
    style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 14,
      background: '#f4f6fb',
      color: '#64748b',
    }}
  >
    <Spin size="large" />
    <span style={{ fontSize: 13 }}>{text}</span>
  </div>
);

const App: React.FC = () => {
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) || '');
  const [me, setMe] = useState<User | null>(null);
  const [booting, setBooting] = useState(true);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);

  const clearSession = () => {
    setToken('');
    setMe(null);
    localStorage.removeItem(TOKEN_KEY);
  };

  const handleLogin = (newToken: string) => {
    setMe(null);
    setBooting(true);
    setToken(newToken);
    localStorage.setItem(TOKEN_KEY, newToken);
    message.success('登录成功');
  };

  const handleLogout = () => {
    clearSession();
    setSetupStatus(null);
    setBooting(false);
    message.info('已退出登录');
  };

  // Resolve the account behind the stored token. A deleted/disabled account or
  // an expired token drops straight back to the login screen.
  useEffect(() => {
    if (!token) {
      setMe(null);
      return;
    }
    let cancelled = false;
    setBooting(true);
    fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } })
      .then(async res => {
        if (cancelled) return;
        if (!res.ok) {
          clearSession();
          setBooting(false);
          return;
        }
        setMe(await res.json());
        setBooting(false);
      })
      .catch(() => {
        if (cancelled) return;
        // The server is unreachable. Drop the stale token so the login screen
        // (which can be retried) is shown instead of an endless spinner.
        clearSession();
        setBooting(false);
        message.error('无法连接服务器，请检查服务是否在运行');
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  // Without a session, ask whether this is a fresh install (first-admin
  // wizard) and whether self-registration is open.
  useEffect(() => {
    if (token) return;
    let cancelled = false;
    setBooting(true);
    fetch('/api/setup/status')
      .then(res => (res.ok ? res.json() : null))
      .then((data: SetupStatus | null) => {
        if (cancelled) return;
        setSetupStatus(
          data || { needs_setup: false, allow_registration: false, registration_open: false },
        );
        setBooting(false);
      })
      .catch(() => {
        if (cancelled) return;
        setSetupStatus({ needs_setup: false, allow_registration: false, registration_open: false });
        setBooting(false);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  let content: React.ReactNode;

  if (!token) {
    if (booting || !setupStatus) {
      content = <Loading text="正在检查初始化状态…" />;
    } else if (setupStatus.needs_setup) {
      content = <Setup onLogin={handleLogin} />;
    } else {
      content = <Login onLogin={handleLogin} registrationOpen={setupStatus.registration_open} />;
    }
  } else if (!me) {
    content = <Loading text={booting ? '正在恢复会话…' : '会话不可用，请重新登录'} />;
  } else {
    const isAdmin = me.role === 'admin';
    content = (
      <Routes>
        <Route element={<AppLayout token={token} me={me} onLogout={handleLogout} />}>
          <Route index element={<Dashboard />} />
          <Route path="echo" element={<EchoSettings />} />
          <Route path="ip" element={<IPIntel />} />
          <Route path="datasets" element={<Datasets />} />
          <Route path="chain" element={<IPChain />} />
          <Route path="users" element={isAdmin ? <Users /> : <Navigate to="/" replace />} />
          <Route path="access" element={<Access />} />
          <Route path="logs" element={<Logs />} />
          <Route path="monitor" element={<Monitoring />} />
          <Route path="audit" element={<Audit />} />
          <Route path="notifications" element={<Notifications />} />
          <Route path="integrations" element={isAdmin ? <Integrations /> : <Navigate to="/" replace />} />
          <Route path="fingerprints" element={<Fingerprints />} />
          <Route path="security" element={<Security />} />
          <Route path="system" element={<System />} />
          <Route path="tools" element={<Tools />} />
          <Route path="docs" element={<ApiDocs />} />
          <Route path="account" element={<Account />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    );
  }

  return content;
};

const Root: React.FC = () => (
  <ConfigProvider locale={zhCN} theme={themeConfig}>
    <AntApp>
      <BrowserRouter basename="/ui">
        <App />
      </BrowserRouter>
    </AntApp>
  </ConfigProvider>
);

export default Root;

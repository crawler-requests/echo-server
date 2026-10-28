import React, { useState } from 'react';
import { Layout, message } from 'antd';
import Login from './Login';
import Admin from './Admin';

const { Header, Content } = Layout;

const App: React.FC = () => {
  const [token, setToken] = useState<string>(localStorage.getItem('echo_token') || '');

  const handleLogin = (newToken: string) => {
    setToken(newToken);
    localStorage.setItem('echo_token', newToken);
    message.success('登录成功');
  };

  const handleLogout = () => {
    setToken('');
    localStorage.removeItem('echo_token');
    message.info('已退出登录');
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ color: '#fff', fontSize: 20 }}>
        Echo Server 管理控制台
      </Header>
      <Content style={{ padding: '24px', maxWidth: 1200, margin: '0 auto' }}>
        {!token ? (
          <Login onLogin={handleLogin} />
        ) : (
          <Admin token={token} onLogout={handleLogout} />
        )}
      </Content>
    </Layout>
  );
};

export default App;

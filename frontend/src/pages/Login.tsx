import React, { useState } from 'react';
import { Button, Card, Form, Input, message, Tabs, Tag, Typography } from 'antd';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { api, errorText } from '../api';
import AuthShell from '../components/AuthShell';

interface Props {
  onLogin: (token: string) => void;
  registrationOpen?: boolean;
}

type Mode = 'login' | 'register';

const Login: React.FC<Props> = ({ onLogin, registrationOpen = false }) => {
  const [mode, setMode] = useState<Mode>('login');
  const [loading, setLoading] = useState(false);

  const submit = async (path: string, values: Record<string, unknown>) => {
    setLoading(true);
    try {
      const data = await api<{ token: string }>(path, undefined, {
        method: 'POST',
        body: JSON.stringify(values),
      });
      if (!data?.token) throw new Error('服务器没有返回登录令牌');
      onLogin(data.token);
    } catch (err) {
      message.error(errorText(err) || (mode === 'register' ? '注册失败' : '登录失败'));
    } finally {
      setLoading(false);
    }
  };

  const loginForm = (
    <Form layout="vertical" size="large" onFinish={values => submit('/api/login', values)}>
      <Form.Item
        name="username"
        label="用户名"
        rules={[{ required: true, message: '请输入用户名' }]}
      >
        <Input prefix={<UserOutlined />} placeholder="请输入用户名" autoComplete="username" autoFocus />
      </Form.Item>
      <Form.Item
        name="password"
        label="密码"
        rules={[{ required: true, message: '请输入密码' }]}
      >
        <Input.Password prefix={<LockOutlined />} placeholder="请输入密码" autoComplete="current-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" block loading={loading} style={{ height: 44 }}>
        登录控制台
      </Button>
    </Form>
  );

  const registerForm = (
    <Form layout="vertical" size="large" onFinish={values => submit('/api/register', values)}>
      <Form.Item
        name="username"
        label="用户名"
        rules={[
          { required: true, message: '请输入用户名' },
          { min: 3, max: 32, message: '用户名长度为 3-32 个字符' },
          { pattern: /^[A-Za-z0-9._-]+$/, message: '只能使用字母、数字、点、下划线或短横线' },
        ]}
      >
        <Input prefix={<UserOutlined />} placeholder="3-32 位，字母 / 数字 / . _ -" autoComplete="username" autoFocus />
      </Form.Item>
      <Form.Item
        name="password"
        label="密码"
        rules={[
          { required: true, message: '请输入密码' },
          { min: 5, max: 128, message: '密码长度为 5-128 个字符' },
        ]}
      >
        <Input.Password prefix={<LockOutlined />} placeholder="至少 5 个字符" autoComplete="new-password" />
      </Form.Item>
      <Form.Item
        name="confirm"
        label="确认密码"
        dependencies={['password']}
        rules={[
          { required: true, message: '请再次输入密码' },
          ({ getFieldValue }) => ({
            validator(_, value) {
              if (!value || getFieldValue('password') === value) return Promise.resolve();
              return Promise.reject(new Error('两次输入的密码不一致'));
            },
          }),
        ]}
      >
        <Input.Password prefix={<LockOutlined />} placeholder="再次输入密码" autoComplete="new-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" block loading={loading} style={{ height: 44 }}>
        注册并登录
      </Button>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: '14px 0 0' }}>
        自助注册的账号默认为只读（viewer），需要写权限请联系管理员提升。
      </Typography.Paragraph>
    </Form>
  );

  return (
    <AuthShell>
      <Card style={{ borderRadius: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <h2>{mode === 'login' ? '欢迎回来' : '创建账号'}</h2>
          <Tag color={registrationOpen ? 'green' : 'default'} style={{ marginInlineEnd: 0 }}>
            {registrationOpen ? '开放注册' : '仅授权账号'}
          </Tag>
        </div>
        <p className="auth-sub">
          {mode === 'login' ? '登录 Echo Server 管理控制台' : '注册一个只读账号，随时可由管理员提升权限'}
        </p>

        {registrationOpen ? (
          <Tabs
            activeKey={mode}
            onChange={key => setMode(key as Mode)}
            items={[
              { key: 'login', label: '登录', children: loginForm },
              { key: 'register', label: '注册', children: registerForm },
            ]}
          />
        ) : (
          loginForm
        )}
      </Card>
    </AuthShell>
  );
};

export default Login;

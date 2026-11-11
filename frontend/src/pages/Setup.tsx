import React, { useState } from 'react';
import { Alert, Button, Card, Form, Input, message, Tag, Typography } from 'antd';
import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { api, errorText } from '../api';
import AuthShell from '../components/AuthShell';

interface Props {
  onLogin: (token: string) => void;
}

// First-run wizard. The server only accepts this while the users table is
// empty, and the account it creates is always an administrator.
const Setup: React.FC<Props> = ({ onLogin }) => {
  const [loading, setLoading] = useState(false);

  const onFinish = async (values: any) => {
    setLoading(true);
    try {
      const data = await api<{ token: string }>('/api/setup', undefined, {
        method: 'POST',
        body: JSON.stringify({ username: values.username, password: values.password }),
      });
      if (!data?.token) throw new Error('服务器没有返回登录令牌');
      message.success('管理员账号已创建');
      onLogin(data.token);
    } catch (err) {
      message.error(errorText(err) || '初始化失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell>
      <Card style={{ borderRadius: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <h2>初始化管理员</h2>
          <Tag color="geekblue" style={{ marginInlineEnd: 0 }}>首次启动</Tag>
        </div>
        <p className="auth-sub">创建安装后的第一个账号，它将拥有全部管理权限。</p>

        <Alert
          type="info"
          showIcon
          icon={<SafetyCertificateOutlined />}
          style={{ marginBottom: 20 }}
          message="这个账号就是系统的所有者"
          description="请设置一个只有你知道的强密码。创建完成后，你可以决定是否允许访客自助注册，或继续手动添加账号。"
        />

        <Form layout="vertical" size="large" onFinish={onFinish}>
          <Form.Item
            name="username"
            label="管理员用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { min: 3, max: 32, message: '用户名长度为 3-32 个字符' },
              { pattern: /^[A-Za-z0-9._-]+$/, message: '只能使用字母、数字、点、下划线或短横线' },
            ]}
          >
            <Input prefix={<UserOutlined />} placeholder="例如 admin" autoComplete="username" autoFocus />
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
            创建管理员并进入控制台
          </Button>
        </Form>

        <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: '16px 0 0' }}>
          无界面部署也可在首次启动前设置 <Typography.Text code>ECHO_SERVER_ADMIN_USERNAME</Typography.Text> 与{' '}
          <Typography.Text code>ECHO_SERVER_ADMIN_PASSWORD</Typography.Text> 自动初始化。
        </Typography.Paragraph>
      </Card>
    </AuthShell>
  );
};

export default Setup;

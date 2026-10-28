import React, { useState } from 'react';
import { Card, Form, Input, Button } from 'antd';

interface Props {
  onLogin: (token: string) => void;
}

const Login: React.FC<Props> = ({ onLogin }) => {
  const [loading, setLoading] = useState(false);

  const onFinish = async (values: any) => {
    setLoading(true);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      });
      const data = await res.json();
      if (data.token) {
        onLogin(data.token);
      } else {
        alert(data.error || '登录失败');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card title="登录" style={{ width: 400, margin: '100px auto' }}>
      <Form onFinish={onFinish} initialValues={{ username: 'admin', password: 'admin' }}>
        <Form.Item name="username" rules={[{ required: true }]}>
          <Input placeholder="用户名" />
        </Form.Item>
        <Form.Item name="password" rules={[{ required: true }]}>
          <Input.Password placeholder="密码" />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading} block>
            登录
          </Button>
        </Form.Item>
      </Form>
    </Card>
  );
};

export default Login;

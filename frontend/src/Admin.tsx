import React, { useEffect, useState } from 'react';
import { Card, Switch, Button, Table, Space } from 'antd';

interface Props {
  token: string;
  onLogout: () => void;
}

interface Log {
  ts: string;
  method: string;
  path: string;
  ip: string;
  connection_type: string;
  country: string;
}

const Admin: React.FC<Props> = ({ token, onLogout }) => {
  const [cfg, setCfg] = useState<any>({});
  const [logs, setLogs] = useState<Log[]>([]);

  const load = async () => {
    const res = await fetch('/api/config', { headers: { Authorization: 'Bearer ' + token } });
    if (res.ok) setCfg(await res.json());
    const lres = await fetch('/api/logs?limit=20', { headers: { Authorization: 'Bearer ' + token } });
    if (lres.ok) setLogs(await lres.json());
  };

  const save = async () => {
    await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify(cfg),
    });
    alert('已保存');
  };

  useEffect(() => { load(); }, []);

  const columns = [
    { title: '时间', dataIndex: 'ts' },
    { title: '方法', dataIndex: 'method' },
    { title: '路径', dataIndex: 'path' },
    { title: 'IP', dataIndex: 'ip' },
    { title: '类型', dataIndex: 'connection_type' },
    { title: '国家', dataIndex: 'country' },
  ];

  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Card title="返回字段开关" extra={<Button onClick={onLogout}>退出</Button>}>
        <p><Switch checked={cfg.show_ja3 !== 'false'} onChange={v => setCfg({...cfg, show_ja3: v ? 'true':'false'})} /> JA3 / JA3Hash</p>
        <p><Switch checked={cfg.show_ip !== 'false'} onChange={v => setCfg({...cfg, show_ip: v ? 'true':'false'})} /> IP 地理位置与分类</p>
        <p><Switch checked={cfg.show_raw !== 'false'} onChange={v => setCfg({...cfg, show_raw: v ? 'true':'false'})} /> 原始 ClientHello</p>
        <Button type="primary" onClick={save}>保存配置</Button>
      </Card>
      <Card title="最近查询记录">
        <Table dataSource={logs} columns={columns} rowKey="ts" pagination={false} />
      </Card>
    </Space>
  );
};

export default Admin;

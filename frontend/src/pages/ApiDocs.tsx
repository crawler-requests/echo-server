import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Col, Input, Row, Select, Space, Table, Tag, Typography, message } from 'antd';
import { ApiOutlined, CopyOutlined, DownloadOutlined, SearchOutlined } from '@ant-design/icons';
import { EndpointDoc, getJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const METHOD_COLOR: Record<string, string> = {
  GET: 'blue',
  POST: 'green',
  PUT: 'gold',
  PATCH: 'purple',
  DELETE: 'red',
};

const AUTH_LABEL: Record<string, string> = {
  public: '公开',
  user: '登录用户',
  admin: '管理员',
  optional: '可选',
};

const ApiDocs: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  const [docs, setDocs] = useState<EndpointDoc[]>([]);
  const [q, setQ] = useState('');
  const [group, setGroup] = useState('');

  useEffect(() => {
    getJSON<EndpointDoc[]>('/api/endpoints', token)
      .then(setDocs)
      .catch(fail);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const groups = useMemo(() => Array.from(new Set(docs.map(d => d.group))), [docs]);
  const filtered = useMemo(
    () =>
      docs.filter(d => {
        if (group && d.group !== group) return false;
        const s = q.trim().toLowerCase();
        if (!s) return true;
        return [d.method, d.path, d.summary, d.group].some(v => v.toLowerCase().includes(s));
      }),
    [docs, q, group],
  );

  const copyCurl = async (d: EndpointDoc) => {
    const url = `${window.location.origin}${d.path.replace('{id}', '1')}`;
    const auth = d.auth === 'admin' || d.auth === 'user' ? ' \\\n  -H "Authorization: Bearer $TOKEN"' : '';
    const cmd = `curl -X ${d.method} "${url}"${auth}`;
    try {
      await navigator.clipboard.writeText(cmd);
      message.success('curl 已复制');
    } catch {
      message.warning('浏览器不允许自动复制');
    }
  };

  return (
    <>
      <PageHeader
        title="API 文档"
        description="控制台与回显接口的端点清单。除公开端点外，使用 Bearer JWT、共享 Token 或 X-API-Key 鉴权。"
        extra={<Button icon={<DownloadOutlined />} href="/api/openapi.json" target="_blank">OpenAPI JSON</Button>}
      />

      <Alert
        type="info"
        showIcon
        icon={<ApiOutlined />}
        style={{ marginBottom: 16 }}
        message="鉴权方式"
        description={
          <span>
            浏览器登录使用 <Text code>Authorization: Bearer &lt;JWT&gt;</Text>；脚本可使用 <Text code>X-API-Token</Text>、
            <Text code>X-API-Key</Text>，或在开启鉴权后使用 <Text code>?token=</Text>。只读账号无法调用写接口。
          </span>
        }
      />

      <Card styles={{ body: { paddingTop: 16 } }}>
        <Space wrap style={{ marginBottom: 14 }}>
          <Input
            allowClear
            prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
            placeholder="搜索路径、方法或说明"
            style={{ width: 280 }}
            value={q}
            onChange={e => setQ(e.target.value)}
          />
          <Select
            allowClear
            placeholder="全部分组"
            style={{ width: 160 }}
            value={group || undefined}
            onChange={v => setGroup(v || '')}
            options={groups.map(g => ({ value: g, label: g }))}
          />
          <Tag>{filtered.length} 个端点</Tag>
        </Space>

        <Table
          dataSource={filtered}
          rowKey={r => `${r.method}-${r.path}`}
          size="middle"
          pagination={{ pageSize: 20, showTotal: n => `共 ${n} 个端点` }}
          scroll={{ x: 820 }}
          columns={[
            { title: '方法', dataIndex: 'method', width: 90, render: (v: string) => <Tag color={METHOD_COLOR[v] || 'default'}>{v}</Tag> },
            { title: '路径', dataIndex: 'path', width: 280, render: (v: string) => <span className="mono">{v}</span> },
            { title: '说明', dataIndex: 'summary' },
            { title: '分组', dataIndex: 'group', width: 90, render: (v: string) => <Tag>{v}</Tag> },
            {
              title: '鉴权',
              dataIndex: 'auth',
              width: 100,
              render: (v: string) => <Tag color={v === 'admin' ? 'gold' : v === 'user' ? 'blue' : 'default'}>{AUTH_LABEL[v] || v}</Tag>,
            },
            {
              title: '',
              width: 54,
              render: (_: unknown, d) => <Button size="small" type="text" icon={<CopyOutlined />} onClick={() => copyCurl(d)} />,
            },
          ]}
        />
      </Card>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} md={12}>
          <Card title="快速开始">
            <pre className="code-block">{`# 登录
curl -X POST ${window.location.origin}/api/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"..."}'

# 调用回显
curl -H "Authorization: Bearer $TOKEN" \\
  "${window.location.origin}/echo?format=json"`}</pre>
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="约定">
            <Paragraph type="secondary" style={{ marginBottom: 0 }}>
              成功响应通常为 JSON；错误使用 HTTP 状态码与纯文本说明（401 未登录、403 权限不足、429 限流、503 维护中）。
              CSV/JSON 导出与数据库备份会返回 <Text code>Content-Disposition</Text> 附件。
              完整机器可读描述见 <Text code>/api/openapi.json</Text>。
            </Paragraph>
          </Card>
        </Col>
      </Row>
    </>
  );
};

export default ApiDocs;

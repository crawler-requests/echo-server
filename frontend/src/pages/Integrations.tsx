import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Descriptions,
  Form,
  Input,
  message,
  Modal,
  Popconfirm,
  Row,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import {
  ApiOutlined,
  CloudDownloadOutlined,
  CopyOutlined,
  DeleteOutlined,
  BellOutlined,
  LinkOutlined,
  NotificationOutlined,
  PlusOutlined,
  ReloadOutlined,
  SendOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { NotificationItem, Webhook, downloadFile, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const EVENTS = [
  { value: 'config.update', label: '配置变更 config.update' },
  { value: 'user.create', label: '账号创建 user.create' },
  { value: 'user.update', label: '账号更新 user.update' },
  { value: 'user.delete', label: '账号删除 user.delete' },
  { value: 'security.alert', label: '安全动作 security.alert' },
  { value: '*', label: '全部事件 *' },
];

const backupSample = `POST /your/webhook HTTP/1.1
Content-Type: application/json
X-Echo-Event: config.update
X-Echo-Signature: sha256=<hex hmac>

{"event":"config.update","actor":"admin","keys":["require_token"],"ts":"..."}`;

const Integrations: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      const [list, notes] = await Promise.all([
        getJSON<Webhook[]>('/api/webhooks', token).catch(() => []),
        getJSON<{ items: NotificationItem[] }>('/api/notifications?limit=100', token).catch(() => ({ items: [] })),
      ]);
      setHooks(list || []);
      setDeliveries((notes?.items || []).filter(n => n.source === 'webhook' || n.title?.toLowerCase().includes('webhook')));
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const create = async () => {
    try {
      const values = await form.validateFields();
      const events = (values.events || []).join(',');
      await postJSON('/api/webhooks', token, { ...values, events });
      message.success('Webhook 已创建');
      setOpen(false);
      form.resetFields();
      await load();
    } catch (err) {
      if ((err as { errorFields?: unknown }).errorFields) return;
      fail(err);
    }
  };

  const toggle = async (h: Webhook, enabled: boolean) => {
    try {
      await fetch('/api/webhooks', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ id: h.id, enabled }),
      }).then(async res => {
        if (!res.ok) throw new Error(await res.text());
      });
      await load();
    } catch (err) {
      fail(err);
    }
  };

  const remove = async (h: Webhook) => {
    try {
      await fetch(`/api/webhooks?id=${h.id}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + token } }).then(async res => {
        if (!res.ok) throw new Error(await res.text());
      });
      message.success('Webhook 已删除');
      await load();
    } catch (err) {
      fail(err);
    }
  };

  const test = async (h: Webhook) => {
    try {
      const res = await postJSON<{ http_status: number }>('/api/webhooks/test', token, { id: h.id });
      message.success(`测试事件已投递，HTTP ${res.http_status}`);
      await load();
    } catch (err) {
      fail(err);
    }
  };

  const stats = useMemo(() => {
    const enabled = hooks.filter(h => h.enabled).length;
    const events = new Set<string>();
    hooks.forEach(h =>
      (h.events || '')
        .split(',')
        .map(e => e.trim())
        .filter(Boolean)
        .forEach(e => events.add(e)),
    );
    const failed = deliveries.filter(d => d.level === 'warning' || d.level === 'error').length;
    return { total: hooks.length, enabled, events: events.size, failed };
  }, [hooks, deliveries]);

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      message.success('已复制');
    } catch {
      message.warning('浏览器不允许自动复制');
    }
  };

  const download = async (path: string, name: string) => {
    try {
      await downloadFile(path, token, name);
      message.success('开始下载');
    } catch (err) {
      fail(err);
    }
  };

  return (
    <>
      <PageHeader
        title="集成与 Webhook"
        description="把配置变更、账号调整与安全动作投递到 Slack、Telegram 或自建系统；同时提供 Prometheus、OpenAPI 与数据库备份入口。"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} disabled={!canEdit} onClick={() => setOpen(true)}>新建 Webhook</Button>
          </Space>
        }
      />

      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：Webhook 配置仅管理员可修改。" />}

      <Spin spinning={loading}>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="Webhook" value={stats.total} prefix={<NotificationOutlined />} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="已启用" value={stats.enabled} suffix={`/ ${stats.total}`} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="订阅事件" value={stats.events} suffix="类" prefix={<BellOutlined />} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card">
              <Statistic title="近期投递告警" value={stats.failed} prefix={<WarningOutlined />} valueStyle={{ color: stats.failed ? '#f04438' : '#059669' }} />
            </Card>
          </Col>
        </Row>

        <Card title="已配置的 Webhook" styles={{ body: { padding: 0 } }}>
          <Table
            dataSource={hooks}
            rowKey="id"
            pagination={false}
            scroll={{ x: 880 }}
            locale={{ emptyText: '还没有 Webhook。创建后会按订阅事件异步投递。' }}
            columns={[
              {
                title: '名称 / 地址',
                dataIndex: 'name',
                render: (_: string, h) => (
                  <div>
                    <div style={{ fontWeight: 600 }}><LinkOutlined /> {h.name}</div>
                    <div className="mono muted" style={{ maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.url}</div>
                  </div>
                ),
              },
              {
                title: '订阅事件',
                dataIndex: 'events',
                width: 230,
                render: (v: string) => (
                  <Space size={4} wrap>
                    {(v || 'all').split(',').map(e => <Tag key={e}>{e.trim() || '*'}</Tag>)}
                  </Space>
                ),
              },
              {
                title: '最近投递',
                width: 170,
                render: (_: unknown, h) => (
                  <div>
                    <Tag color={h.last_status?.startsWith('error') ? 'error' : h.last_status ? 'success' : 'default'}>
                      {h.last_status || '尚未投递'}
                    </Tag>
                    <div className="muted" style={{ fontSize: 11 }}>{h.last_sent ? fmtTime(h.last_sent) : ''}</div>
                  </div>
                ),
              },
              {
                title: '启用',
                dataIndex: 'enabled',
                width: 72,
                render: (v: boolean, h) => <Switch size="small" checked={v} disabled={!canEdit} onChange={x => toggle(h, x)} />,
              },
              {
                title: '操作',
                width: 150,
                render: (_: unknown, h) => (
                  <Space size={4}>
                    <Button size="small" icon={<SendOutlined />} disabled={!canEdit} onClick={() => test(h)}>测试</Button>
                    <Popconfirm title="删除这个 Webhook？" okText="删除" cancelText="取消" onConfirm={() => remove(h)}>
                      <Button size="small" danger type="text" icon={<DeleteOutlined />} disabled={!canEdit} />
                    </Popconfirm>
                  </Space>
                ),
              },
            ]}
          />
        </Card>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={14}>
            <Card title="投递协议">
              <Paragraph type="secondary">
                每次事件以 JSON POST 投递，请求头包含事件名与 HMAC-SHA256 签名。签名内容为原始请求体，密钥为创建 Webhook 时填写的 secret。
              </Paragraph>
              <pre className="code-block">{backupSample}</pre>
              <p className="section-note">接收端应校验 <Text code>X-Echo-Signature</Text>，并在 8 秒内返回 2xx；失败会记录状态并生成站内通知。</p>
            </Card>
          </Col>
          <Col xs={24} xl={10}>
            <Card title="运维下载">
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/system/backup', 'echo-server-backup.db')}>
                  下载 SQLite 备份
                </Button>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/export/config.json', 'echo-config.json')}>
                  导出可迁移配置
                </Button>
                <Button block icon={<ApiOutlined />} href="/api/openapi.json" target="_blank">查看 OpenAPI JSON</Button>
                <Button block icon={<ThunderboltOutlined />} href="/metrics" target="_blank">打开 Prometheus 指标</Button>
              </Space>
              <Descriptions column={1} size="small" style={{ marginTop: 16 }}>
                <Descriptions.Item label="事件投递">异步，不阻塞请求</Descriptions.Item>
                <Descriptions.Item label="超时">8 秒</Descriptions.Item>
                <Descriptions.Item label="签名">HMAC-SHA256</Descriptions.Item>
              </Descriptions>
            </Card>
          </Col>
        </Row>

        <Card title="常用模板" style={{ marginTop: 16 }}>
          <Row gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <div className="setting-tile">
                <div>
                  <div className="s-title">Slack Incoming Webhook</div>
                  <div className="s-desc">创建时把 URL 填为 Slack 的 webhook 地址，事件将以 Slack 兼容 JSON 直接展示（text 字段可按接收端要求映射）。</div>
                </div>
                <Button size="small" icon={<CopyOutlined />} onClick={() => copy('https://hooks.slack.com/services/XXX/YYY/ZZZ')}>复制示例</Button>
              </div>
            </Col>
            <Col xs={24} md={12}>
              <div className="setting-tile">
                <div>
                  <div className="s-title">Telegram Bot API</div>
                  <div className="s-desc">使用 https://api.telegram.org/bot&lt;token&gt;/sendMessage?chat_id=... 作为 URL，适合运维告警。</div>
                </div>
                <Button size="small" icon={<CopyOutlined />} onClick={() => copy('https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat_id>')}>复制示例</Button>
              </div>
            </Col>
          </Row>
        </Card>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={13}>
            <Card title="事件目录" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={[
                  { event: 'config.update', when: '任一配置键被修改', payload: 'actor, keys[]', level: '信息' },
                  { event: 'user.create', when: '管理员创建账号', payload: 'actor, username, role', level: '信息' },
                  { event: 'user.update', when: '角色 / 状态 / 密码变更', payload: 'actor, username, fields', level: '信息' },
                  { event: 'user.delete', when: '账号被删除', payload: 'actor, username', level: '警告' },
                  { event: 'security.alert', when: 'JWT 轮换、鉴权开关、Key 操作', payload: 'actor, action', level: '警告' },
                  { event: '*', when: '订阅全部事件', payload: '同具体事件', level: '—' },
                ]}
                rowKey="event"
                size="small"
                pagination={false}
                columns={[
                  { title: '事件', dataIndex: 'event', width: 140, render: (v: string) => <Text code style={{ fontSize: 11 }}>{v}</Text> },
                  { title: '触发时机', dataIndex: 'when' },
                  { title: '载荷字段', dataIndex: 'payload', width: 170, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
                  { title: '级别', dataIndex: 'level', width: 70 },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={11}>
            <Card title="投递记录" extra={<Text type="secondary" style={{ fontSize: 12 }}>来自站内通知</Text>} styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={deliveries.slice(0, 8)}
                rowKey="id"
                size="small"
                pagination={false}
                locale={{ emptyText: '暂无投递记录' }}
                columns={[
                  { title: '时间', dataIndex: 'ts', width: 150, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(v)}</Text> },
                  { title: '内容', dataIndex: 'title', ellipsis: true },
                  { title: '级别', dataIndex: 'level', width: 74, render: (v: string) => <Tag color={v === 'error' ? 'red' : v === 'warning' ? 'orange' : 'blue'}>{v}</Tag> },
                ]}
              />
            </Card>
          </Col>
        </Row>

        <Card title="签名校验示例" style={{ marginTop: 16 }} styles={{ body: { paddingTop: 8 } }}>
          <Tabs
            size="small"
            items={[
              {
                key: 'python',
                label: 'Python',
                children: (
                  <pre className="code-block" style={{ margin: 0 }}>{`import hmac, hashlib
sig = request.headers["X-Echo-Signature"]  # "sha256=..."
expect = "sha256=" + hmac.new(
    secret.encode(), request.body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(sig, expect)`}</pre>
                ),
              },
              {
                key: 'node',
                label: 'Node.js',
                children: (
                  <pre className="code-block" style={{ margin: 0 }}>{`const crypto = require("crypto");
const expect = "sha256=" + crypto
  .createHmac("sha256", secret)
  .update(rawBody)
  .digest("hex");
const ok = crypto.timingSafeEqual(
  Buffer.from(expect), Buffer.from(req.headers["x-echo-signature"]));`}</pre>
                ),
              },
              {
                key: 'go',
                label: 'Go',
                children: (
                  <pre className="code-block" style={{ margin: 0 }}>{`mac := hmac.New(sha256.New, []byte(secret))
mac.Write(body)
expect := "sha256=" + hex.EncodeToString(mac.Sum(nil))
ok := hmac.Equal([]byte(expect),
    []byte(r.Header.Get("X-Echo-Signature")))`}</pre>
                ),
              },
            ]}
          />
          <p className="section-note" style={{ marginBottom: 0 }}>
            校验时务必使用原始请求体字节，不要先反序列化再重新序列化，否则签名会不匹配。
          </p>
        </Card>
      </Spin>

      <Modal title="新建 Webhook" open={open} onCancel={() => setOpen(false)} onOk={create} okText="创建" cancelText="取消">
        <Form form={form} layout="vertical" initialValues={{ events: ['config.update', 'user.create', 'user.delete', 'security.alert'] }}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="例如：ops-slack" />
          </Form.Item>
          <Form.Item name="url" label="投递地址" rules={[{ required: true, message: '请输入 http(s) 地址' }, { pattern: /^https?:\/\//, message: '必须以 http:// 或 https:// 开头' }]}>
            <Input placeholder="https://hooks.slack.com/services/..." />
          </Form.Item>
          <Form.Item name="secret" label="签名密钥（可选）" extra="留空自动生成；接收端用它对请求体做 HMAC-SHA256。">
            <Input.Password placeholder="留空自动生成" />
          </Form.Item>
          <Form.Item name="events" label="订阅事件">
            <Checkbox.Group options={EVENTS} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

export default Integrations;

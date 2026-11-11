import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  message,
  Modal,
  Popconfirm,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Steps,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  ApartmentOutlined,
  DeleteOutlined,
  EditOutlined,
  ExperimentOutlined,
  PlusOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { IPProvider, deleteJSON, errorText, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const KIND_LABEL: Record<string, string> = {
  builtin: '内置驱动',
  http: '云端 API',
  command: '本地命令',
};

const KIND_COLOR: Record<string, string> = {
  builtin: 'default',
  http: 'geekblue',
  command: 'purple',
};

const chainStatus = (p: IPProvider) => {
  if (!p.enabled) return <Tag>已禁用</Tag>;
  if (p.gated) return <Tag color="purple">已拦截</Tag>;
  if (p.status === 'ok') return <Tag color="success">正常</Tag>;
  if (p.status === 'error') return <Tag color="error">错误</Tag>;
  if (p.status === 'empty') return <Tag color="warning">无结果</Tag>;
  return <Tag color="processing">待命</Tag>;
};

const IPChain: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [chain, setChain] = useState<IPProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<IPProvider | null>(null);
  const [saving, setSaving] = useState(false);
  const [testIP, setTestIP] = useState('8.8.8.8');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState('');
  const [form] = Form.useForm();

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      setChain((await getJSON<IPProvider[]>('/api/ipproviders', token)) || []);
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

  const stats = useMemo(() => {
    const enabled = chain.filter(p => p.enabled).length;
    const ok = chain.filter(p => p.enabled && p.status === 'ok' && !p.gated).length;
    const calls = chain.reduce((n, p) => n + p.calls, 0);
    const okCalls = chain.reduce((n, p) => n + p.successes, 0);
    const avg = chain.filter(p => p.calls > 0);
    const avgMs = avg.length ? avg.reduce((n, p) => n + p.avg_ms, 0) / avg.length : 0;
    return {
      total: chain.length,
      enabled,
      ok,
      rate: calls ? Math.round((okCalls / calls) * 100) : 0,
      avgMs: Math.round(avgMs),
    };
  }, [chain]);

  const ordered = useMemo(
    () => [...chain].filter(p => p.enabled).sort((a, b) => a.priority - b.priority),
    [chain],
  );

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ kind: 'http', priority: 10 });
    setModalOpen(true);
  };

  const openEdit = (p: IPProvider) => {
    if (p.builtin) return;
    setEditing(p);
    form.setFieldsValue({
      name: p.name,
      kind: p.kind,
      priority: p.priority,
      url: p.url || '',
      command: p.command || '',
      headers: p.headers && Object.keys(p.headers).length ? JSON.stringify(p.headers, null, 2) : '',
      mapping: p.mapping && Object.keys(p.mapping).length ? JSON.stringify(p.mapping, null, 2) : '',
      timeout_sec: p.timeout_sec,
    });
    setModalOpen(true);
  };

  const submit = async () => {
    let values: any;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    const kind = values.kind;
    const body: any = {
      name: (values.name || '').trim(),
      kind,
      enabled: editing ? editing.enabled : true,
      priority: values.priority ?? 10,
    };
    if (kind === 'builtin') {
      body.driver = values.driver || 'ipwhois';
    } else if (kind === 'http') {
      body.url = (values.url || '').trim();
      for (const [field, label, key] of [
        [values.headers, '请求头', 'headers'],
        [values.mapping, '字段映射', 'mapping'],
      ] as const) {
        if ((field || '').trim()) {
          try {
            const parsed = JSON.parse(field);
            if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
            body[key] = parsed;
          } catch {
            message.error(`${label}必须是 JSON 对象`);
            return;
          }
        }
      }
    } else if (kind === 'command') {
      body.command = (values.command || '').trim();
      if ((values.mapping || '').trim()) {
        try {
          body.mapping = JSON.parse(values.mapping);
        } catch {
          message.error('字段映射必须是 JSON 对象');
          return;
        }
      }
    }
    if (values.timeout_sec) body.timeout_sec = values.timeout_sec;

    setSaving(true);
    try {
      await postJSON('/api/ipproviders', token, body);
      message.success(editing ? 'Provider 已更新' : 'Provider 已加入查询链路');
      setModalOpen(false);
      await load(true);
    } catch (err) {
      message.error('保存失败：' + errorText(err));
    } finally {
      setSaving(false);
    }
  };

  const toggle = async (p: IPProvider, enabled: boolean) => {
    try {
      await postJSON('/api/ipproviders', token, { ...p, enabled });
      await load(true);
    } catch (err) {
      fail(err);
    }
  };

  const remove = async (p: IPProvider) => {
    try {
      await deleteJSON(`/api/ipproviders?name=${encodeURIComponent(p.name)}`, token);
      message.success('Provider 已删除');
      await load(true);
    } catch (err) {
      fail(err);
    }
  };

  const runTest = async () => {
    if (!testIP.trim()) {
      message.warning('请输入要测试的 IP');
      return;
    }
    setTesting(true);
    setTestResult('');
    try {
      const res = await postJSON<any>('/api/ipproviders/test', token, { ip: testIP.trim() });
      setTestResult(JSON.stringify(res, null, 2));
    } catch (err) {
      setTestResult('查询失败：' + errorText(err));
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <PageHeader
        title="IP 查询链路"
        description="按优先级从高到低查询，第一个返回可用数据的 Provider 胜出；失败自动降级到下一个，全程记录调用统计。"
        extra={
          <Space wrap>
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
            {canEdit && <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>添加 Provider</Button>}
          </Space>
        }
      />

      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：可以查看链路、状态与统计，不能修改。" />}

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="链路 Provider" value={stats.total} prefix={<ApartmentOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="已启用 / 正常" value={stats.enabled} suffix={`/ ${stats.ok}`} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="累计成功率"
              value={stats.rate}
              suffix="%"
              valueStyle={{ color: stats.rate >= 90 ? '#059669' : stats.rate >= 50 ? '#d97706' : '#f04438' }}
            />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="平均耗时" value={stats.avgMs} suffix="ms" /></Card>
        </Col>
      </Row>

      <Card title="查询顺序" style={{ marginBottom: 16 }} extra={<Text type="secondary" style={{ fontSize: 12 }}>优先级数字越小越先查询</Text>}>
        {ordered.length === 0 ? (
          <Text type="secondary">当前没有启用的 Provider，回显只会使用本地 CIDR 判定。</Text>
        ) : (
          <Steps
            size="small"
            current={-1}
            items={ordered.map(p => ({
              title: p.name,
              description: (
                <Space size={4} wrap>
                  <Tag color={KIND_COLOR[p.kind] || 'default'} style={{ marginInlineEnd: 0 }}>P{p.priority}</Tag>
                  <Tag color={p.gated ? 'purple' : p.status === 'ok' ? 'success' : p.status === 'error' ? 'error' : 'warning'} style={{ marginInlineEnd: 0 }}>
                    {p.gated ? '已拦截' : p.status || '待命'}
                  </Tag>
                </Space>
              ),
            }))}
          />
        )}
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={chain}
              rowKey="name"
              loading={loading}
              pagination={false}
              size="middle"
              scroll={{ x: 780 }}
              columns={[
                {
                  title: '名称',
                  dataIndex: 'name',
                  width: 148,
                  render: (v: string, r: IPProvider) => {
                    const source = r.url || r.command || r.driver || '内置驱动';
                    return (
                      <Tooltip
                        title={
                          <div style={{ lineHeight: 1.8 }}>
                            <div>来源：{source}</div>
                            <div>最近成功：{fmtTime(r.last_success)}</div>
                            {r.last_error && <div>最近错误：{r.last_error}</div>}
                          </div>
                        }
                      >
                        <Space size={6}>
                          <span style={{ fontWeight: 600 }}>{v}</span>
                          {r.builtin && <Tag style={{ marginInlineEnd: 0 }}>内置</Tag>}
                          {r.headers && Object.keys(r.headers).length > 0 && (
                            <Tag color="gold" style={{ marginInlineEnd: 0 }}>鉴权</Tag>
                          )}
                        </Space>
                      </Tooltip>
                    );
                  },
                },
                {
                  title: '类型',
                  dataIndex: 'kind',
                  width: 100,
                  render: (v: string) => (
                    <Tag color={KIND_COLOR[v] || 'default'} style={{ marginInlineEnd: 0 }}>
                      {KIND_LABEL[v] || v}
                    </Tag>
                  ),
                },
                { title: '优先级', dataIndex: 'priority', width: 68 },
                {
                  title: '启用',
                  dataIndex: 'enabled',
                  width: 62,
                  render: (v: boolean, r: IPProvider) => (
                    <Switch size="small" disabled={!canEdit} checked={v} onChange={c => toggle(r, c)} />
                  ),
                },
                {
                  title: '状态',
                  dataIndex: 'status',
                  width: 88,
                  render: (_: string, r: IPProvider) => (
                    <Tooltip title={`最近成功：${fmtTime(r.last_success)}`}>
                      <span>{chainStatus(r)}</span>
                    </Tooltip>
                  ),
                },
                {
                  title: '调用 / 成功 / 失败',
                  width: 124,
                  render: (_: unknown, r: IPProvider) => (
                    <Text className="mono">{r.calls} / {r.successes} / {r.failures}</Text>
                  ),
                },
                {
                  title: '平均耗时',
                  dataIndex: 'avg_ms',
                  width: 84,
                  render: (v: number, r: IPProvider) => (r.calls > 0 ? `${(v || 0).toFixed(0)} ms` : '—'),
                },
                ...(canEdit
                  ? [
                      {
                        title: '操作',
                        width: 92,
                        render: (_: unknown, r: IPProvider) => (
                          <Space size={2}>
                            {!r.builtin && (
                              <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(r)} />
                            )}
                            {!r.builtin && (
                              <Popconfirm title={`删除 Provider「${r.name}」？`} onConfirm={() => remove(r)}>
                                <Button size="small" type="text" danger icon={<DeleteOutlined />} />
                              </Popconfirm>
                            )}
                          </Space>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
          </Card>

          {chain.some(p => !!p.last_error) && (
            <Alert
              type="warning"
              showIcon
              style={{ marginTop: 12 }}
              message="部分 Provider 最近调用失败"
              description={chain.filter(p => p.last_error).map(p => `${p.name}: ${p.last_error}`).join('；')}
            />
          )}
        </Col>

        <Col xs={24} xl={8}>
          <Card title="链路测试" extra={<ExperimentOutlined style={{ color: '#6366f1' }} />}>
            <Paragraph type="secondary">
              绕过结果缓存，立即用当前链路查询一个 IP，并显示最终胜出的 Provider。
            </Paragraph>
            <Space.Compact style={{ width: '100%' }}>
              <Input
                value={testIP}
                onChange={e => setTestIP(e.target.value)}
                placeholder="例如 8.8.8.8"
                onPressEnter={runTest}
              />
              <Button type="primary" icon={<ThunderboltOutlined />} loading={testing} onClick={runTest}>
                测试
              </Button>
            </Space.Compact>
            {testResult && <pre className="code-block" style={{ marginTop: 14 }}>{testResult}</pre>}
          </Card>

          <Card title="链路说明" style={{ marginTop: 16 }}>
            <Paragraph type="secondary" style={{ marginBottom: 8 }}>
              响应若是归一化结构（country / city / asn / is_proxy 等）可省略映射；否则用点路径映射到这些字段。
            </Paragraph>
            <Paragraph type="secondary" style={{ marginBottom: 0 }}>
              命令的 stdout 必须是 JSON；请求头中的凭据在状态接口中一律显示为 <Text code>***</Text>。
            </Paragraph>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={14}>
          <Card title="归一化字段" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={[
                { field: 'ip', desc: '查询的原始 IP', required: '必填' },
                { field: 'country / country_code', desc: '国家名称与 ISO 代码', required: '推荐' },
                { field: 'region / city', desc: '省州与城市', required: '可选' },
                { field: 'asn / org / isp', desc: '自治系统与运营组织', required: '推荐' },
                { field: 'latitude / longitude', desc: '经纬度（数值）', required: '可选' },
                { field: 'timezone', desc: 'IANA 时区', required: '可选' },
                { field: 'is_proxy / connection_type', desc: '是否代理及连接类型', required: '推荐' },
              ]}
              rowKey="field"
              size="small"
              pagination={false}
              columns={[
                { title: '字段', dataIndex: 'field', width: 240, render: (v: string) => <span className="mono">{v}</span> },
                { title: '含义', dataIndex: 'desc' },
                { title: '建议', dataIndex: 'required', width: 84, render: (v: string) => <Tag>{v}</Tag> },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="接入示例" styles={{ body: { paddingTop: 8 } }}>
            <Tabs
              size="small"
              items={[
                {
                  key: 'http',
                  label: 'HTTP',
                  children: (
                    <pre className="code-block" style={{ margin: 0 }}>{`{
  "name": "my-api",
  "kind": "http",
  "priority": 1,
  "url": "https://ip.example.com/{ip}",
  "headers": {"Authorization": "Bearer …"},
  "mapping": {
    "country": "data.country",
    "city": "data.city",
    "asn": "data.asn",
    "is_proxy": "data.proxy"
  },
  "timeout_sec": 4
}`}</pre>
                  ),
                },
                {
                  key: 'command',
                  label: 'Command',
                  children: (
                    <pre className="code-block" style={{ margin: 0 }}>{`{
  "name": "local-mmdb",
  "kind": "command",
  "priority": 5,
  "command": "mmdb-lookup --ip {ip} --json",
  "mapping": {"country": "country", "asn": "asn"}
}`}</pre>
                  ),
                },
                {
                  key: 'builtin',
                  label: 'Builtin',
                  children: (
                    <pre className="code-block" style={{ margin: 0 }}>{`{
  "name": "ipwhois",
  "kind": "builtin",
  "driver": "ipwhois",
  "priority": 20
}`}</pre>
                  ),
                },
              ]}
            />
            <p className="section-note" style={{ marginBottom: 0 }}>
              点路径使用 <Text code>.</Text> 分隔；数组下标可写成 <Text code>data.0.country</Text>。映射值留空则沿用原字段名。
            </p>
          </Card>
        </Col>
      </Row>

      <Card title="链路策略与超时" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
        <Table
          dataSource={[
            { scene: '上游超时', behavior: '计入 failure，立即尝试下一 Provider', note: '默认 4 秒，可按 Provider 覆盖' },
            { scene: '限流 / 5xx', behavior: '计入 failure，降级到下一 Provider', note: '不会自动重试同一来源' },
            { scene: '返回空结果', behavior: '视为失败，继续降级', note: '避免空值污染最终字段' },
            { scene: '命中缓存', behavior: '直接返回，不触发链路', note: '缓存 TTL 在 IP 情报页配置' },
            { scene: '全部失败', behavior: '返回本地 CIDR 判定结果', note: 'geo_source=local，字段可为空' },
            { scene: '命令类超时', behavior: '终止子进程并记录错误', note: 'stdout 必须为合法 JSON' },
          ]}
          rowKey="scene"
          size="small"
          pagination={false}
          columns={[
            { title: '场景', dataIndex: 'scene', width: 150, render: (v: string) => <Tag color="blue">{v}</Tag> },
            { title: '行为', dataIndex: 'behavior' },
            { title: '说明', dataIndex: 'note', width: 260, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
          ]}
        />
        <p className="section-note" style={{ padding: '0 16px' }}>
          链路按优先级串行执行，任一环节的失败都不会影响回显主流程返回；统计值会随每次真实调用累积。
        </p>
      </Card>

      <Modal
        title={editing ? `编辑 Provider · ${editing.name}` : '添加 IP Provider'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={submit}
        confirmLoading={saving}
        okText="保存并加入链路"
        width={680}
        destroyOnClose
      >
        <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
          <Space size={12} style={{ display: 'flex' }}>
            <Form.Item name="name" label="名称（唯一）" rules={[{ required: true, message: '请填写名称' }]} style={{ flex: 1 }}>
              <Input disabled={!!editing} placeholder="例如 cloud-api" />
            </Form.Item>
            <Form.Item name="kind" label="类型" style={{ width: 170 }}>
              <Select
                disabled={!!editing}
                options={[
                  { value: 'http', label: '云端 API' },
                  { value: 'command', label: '本地命令' },
                  { value: 'builtin', label: '内置驱动' },
                ]}
              />
            </Form.Item>
            <Form.Item name="priority" label="优先级" style={{ width: 130 }}>
              <InputNumber min={-100} max={10000} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.kind !== cur.kind}>
            {({ getFieldValue }) => {
              const kind = getFieldValue('kind');
              if (kind === 'builtin') {
                return (
                  <Form.Item name="driver" label="内置驱动" rules={[{ required: true }]}>
                    <Select
                      options={[
                        { value: 'ipwhois', label: 'ipwho.is' },
                        { value: 'ipapi', label: 'ip-api.com' },
                        { value: 'ipinfo', label: 'ipinfo.io' },
                      ]}
                    />
                  </Form.Item>
                );
              }
              if (kind === 'command') {
                return (
                  <>
                    <Form.Item name="command" label="命令（{ip} 会被替换，stdout 必须是 JSON）" rules={[{ required: true, message: '请填写命令' }]}>
                      <Input.TextArea rows={3} className="mono" placeholder='curl -s "https://api.example.com/{ip}"' />
                    </Form.Item>
                    <Form.Item name="mapping" label="字段映射 JSON（可选）">
                      <Input.TextArea rows={3} className="mono" placeholder='{"country":"data.country","asn":"data.asn"}' />
                    </Form.Item>
                  </>
                );
              }
              return (
                <>
                  <Form.Item name="url" label="URL 模板" rules={[{ required: true, message: '请填写 URL' }]}>
                    <Input placeholder="https://api.example.com/{ip} 或 {ip_raw}" />
                  </Form.Item>
                  <Form.Item name="headers" label="请求头 JSON（可选）">
                    <Input.TextArea rows={3} className="mono" placeholder='{"Authorization":"Bearer xxx"}；值填 "***" 表示保留原值' />
                  </Form.Item>
                  <Form.Item name="mapping" label="字段映射 JSON（可选）">
                    <Input.TextArea rows={3} className="mono" placeholder='{"country":"data.country","is_proxy":"data.proxy"}' />
                  </Form.Item>
                </>
              );
            }}
          </Form.Item>

          <Form.Item name="timeout_sec" label="单次查询超时（秒，默认 4）" style={{ width: 220 }}>
            <InputNumber min={1} max={60} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

export default IPChain;

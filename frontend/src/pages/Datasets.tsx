import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
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
  CloudSyncOutlined,
  DatabaseOutlined,
  DeleteOutlined,
  EditOutlined,
  FileSyncOutlined,
  PlusOutlined,
  ReloadOutlined,
  SyncOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Dataset, Provider, deleteJSON, errorText, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const KIND_LABEL: Record<string, string> = {
  embedded: '内置',
  file: '本地文件',
  remote: '云端 / 远程',
  command: '命令生成',
};

const KIND_COLOR: Record<string, string> = {
  embedded: 'default',
  file: 'blue',
  remote: 'geekblue',
  command: 'purple',
};

const DATASET_FIELDS: Record<string, { field: string; desc: string }[]> = {
  datacenter_cidr: [
    { field: 'ip.connection_type', desc: '命中时固定为 datacenter' },
    { field: 'ip.geo_source', desc: '标记为 local，与在线 Provider 区分' },
    { field: 'ip.org', desc: '若本地表带组织名则一并回填' },
  ],
  residential_proxy_cidr: [
    { field: 'ip.connection_type', desc: '命中时固定为 residential_proxy' },
    { field: 'ip.is_proxy', desc: '命中后用于爬虫 / 风控判定' },
    { field: 'ip.geo_source', desc: '标记为 local' },
  ],
  datacenter_orgs: [
    { field: 'ip.org', desc: '按 ASN 组织名匹配云厂商关键字' },
    { field: 'ip.connection_type', desc: '组织命中时判定为 datacenter' },
    { field: 'ip.geo_source', desc: '标记为 local' },
  ],
  ja4: [
    { field: 'client.name', desc: '根据 JA4 指纹匹配的客户端名称' },
    { field: 'client.family', desc: '浏览器 / CLI / 库等家族' },
    { field: 'client.confidence', desc: '指纹库中的置信度与观测数' },
  ],
  __default__: [
    { field: 'ip.connection_type', desc: '数据命中的判定结果' },
    { field: 'ip.geo_source', desc: '实际生效的 Provider 或 local' },
    { field: 'client.*', desc: '指纹类数据集用于客户端识别' },
  ],
};

const providerStatus = (p: Provider) => {
  if (!p.enabled) return <Tag>已禁用</Tag>;
  if (p.status === 'ok') return <Tag color="success">正常</Tag>;
  if (p.status === 'error') return <Tag color="error">错误</Tag>;
  if (p.status === 'empty') return <Tag color="warning">无数据</Tag>;
  return <Tag color="processing">{p.status || '待同步'}</Tag>;
};

const Datasets: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [active, setActive] = useState('');
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Provider | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const list = await getJSON<Dataset[]>('/api/datasets', token);
      setDatasets(list || []);
      setActive(prev => (prev && list.some(d => d.name === prev) ? prev : list[0]?.name || ''));
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

  const ds = datasets.find(d => d.name === active);
  const providers = ds?.providers || [];

  const stats = useMemo(() => {
    let providerCount = 0;
    let entries = 0;
    let failing = 0;
    datasets.forEach(d =>
      (d.providers || []).forEach(p => {
        providerCount += 1;
        entries += p.entries || 0;
        if (p.error) failing += 1;
      }),
    );
    return { datasets: datasets.length, providerCount, entries, failing };
  }, [datasets]);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ kind: 'file', priority: 10, refresh_min: 0 });
    setModalOpen(true);
  };

  const openEdit = (p: Provider) => {
    setEditing(p);
    form.setFieldsValue({
      name: p.name,
      kind: p.kind,
      priority: p.priority,
      path: p.path || '',
      url: p.url || '',
      command: p.command || '',
      headers: p.headers && Object.keys(p.headers).length ? JSON.stringify(p.headers, null, 2) : '',
      refresh_min: p.refresh_min || 0,
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
      enabled: true,
      priority: values.priority ?? 10,
    };
    if (kind === 'file') {
      body.path = (values.path || '').trim();
      body.refresh_min = values.refresh_min || 0;
    } else if (kind === 'remote') {
      body.url = (values.url || '').trim();
      body.refresh_min = values.refresh_min || 0;
      if ((values.headers || '').trim()) {
        try {
          const parsed = JSON.parse(values.headers);
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
          body.headers = parsed;
        } catch {
          message.error('请求头必须是 JSON 对象，如 {"Authorization":"Bearer xxx"}');
          return;
        }
      }
    } else if (kind === 'command') {
      body.command = (values.command || '').trim();
    }

    setSaving(true);
    try {
      await postJSON(`/api/datasets?dataset=${encodeURIComponent(active)}`, token, body);
      message.success(editing ? 'Provider 已更新' : 'Provider 已添加');
      setModalOpen(false);
      await load(true);
    } catch (err) {
      message.error('保存失败：' + errorText(err));
    } finally {
      setSaving(false);
    }
  };

  const syncOne = async (provider: string) => {
    try {
      await postJSON(`/api/datasets/sync?dataset=${encodeURIComponent(active)}&provider=${encodeURIComponent(provider)}`, token, {});
      message.info('已触发同步');
      setTimeout(() => load(true), 1200);
    } catch (err) {
      fail(err);
    }
  };

  const syncAll = async () => {
    try {
      await postJSON(`/api/datasets/sync?dataset=${encodeURIComponent(active)}`, token, {});
      message.info('已触发全部同步');
      setTimeout(() => load(true), 1200);
    } catch (err) {
      fail(err);
    }
  };

  const remove = async (provider: string) => {
    try {
      await deleteJSON(`/api/datasets?dataset=${encodeURIComponent(active)}&provider=${encodeURIComponent(provider)}`, token);
      message.success('Provider 已删除');
      await load(true);
    } catch (err) {
      fail(err);
    }
  };

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      render: (v: string, r: Provider) => (
        <Space size={6}>
          <span style={{ fontWeight: 600 }}>{v}</span>
          {r.builtin && <Tag style={{ marginInlineEnd: 0 }}>内置</Tag>}
        </Space>
      ),
    },
    {
      title: '类型',
      dataIndex: 'kind',
      width: 120,
      render: (v: string) => <Tag color={KIND_COLOR[v] || 'default'}>{KIND_LABEL[v] || v}</Tag>,
    },
    { title: '优先级', dataIndex: 'priority', width: 76 },
    { title: '状态', dataIndex: 'status', width: 92, render: (_: string, r: Provider) => providerStatus(r) },
    {
      title: '条目',
      dataIndex: 'entries',
      width: 90,
      render: (v: number) => (v || 0).toLocaleString(),
    },
    {
      title: '来源',
      ellipsis: true,
      render: (_: unknown, r: Provider) => {
        const source = r.source || r.url || r.path || r.command || '—';
        return (
          <Tooltip title={source}>
            <span className="mono" style={{ color: '#475569' }}>{source}</span>
            {r.headers && Object.keys(r.headers).length > 0 && <Tag style={{ marginLeft: 6 }}>鉴权</Tag>}
          </Tooltip>
        );
      },
    },
    {
      title: '最近同步',
      dataIndex: 'last_sync',
      width: 168,
      render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text>,
    },
    ...(canEdit
      ? [
          {
            title: '操作',
            width: 180,
            render: (_: unknown, r: Provider) => (
              <Space size={4}>
                {(r.kind === 'remote' || r.kind === 'command') && (
                  <Button size="small" type="text" icon={<SyncOutlined />} onClick={() => syncOne(r.name)}>同步</Button>
                )}
                {!r.builtin && (
                  <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
                )}
                {!r.builtin && (
                  <Popconfirm title={`删除 Provider「${r.name}」？`} onConfirm={() => remove(r.name)}>
                    <Button size="small" type="text" danger icon={<DeleteOutlined />} />
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]
      : []),
  ];

  const tabItems = datasets.map(d => ({
    key: d.name,
    label: (
      <Space size={6}>
        <DatabaseOutlined />
        {d.name}
        <Tag style={{ marginInlineEnd: 0 }}>{d.providers?.length || 0}</Tag>
      </Space>
    ),
    children: (
      <>
        <Paragraph type="secondary" style={{ marginTop: 4 }}>{d.description}</Paragraph>
        {d.providers?.some(p => p.error) && (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 12 }}
            message="部分 Provider 加载失败"
            description={d.providers.filter(p => p.error).map(p => `${p.name}: ${p.error}`).join('；')}
          />
        )}
        <Table
          dataSource={d.providers || []}
          rowKey="name"
          size="middle"
          pagination={false}
          scroll={{ x: 900 }}
          columns={columns as any}
        />

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={13}>
            <Card size="small" title="生效顺序">
              <Steps
                direction="vertical"
                size="small"
                current={-1}
                items={[...(d.providers || [])]
                  .sort((a, b) => a.priority - b.priority)
                  .map(p => ({
                    title: (
                      <Space size={6}>
                        <span>{p.name}</span>
                        <Tag color={KIND_COLOR[p.kind] || 'default'} style={{ marginInlineEnd: 0 }}>{KIND_LABEL[p.kind] || p.kind}</Tag>
                        {providerStatus(p)}
                      </Space>
                    ),
                    description: `优先级 ${p.priority} · ${(p.entries || 0).toLocaleString()} 条 · ${p.source || p.url || p.path || p.command || '内置'}`,
                  }))}
              />
            </Card>
          </Col>
          <Col xs={24} xl={11}>
            <Card size="small" title="判定字段">
              <Descriptions column={1} size="small" bordered>
                {(DATASET_FIELDS[d.name] || DATASET_FIELDS['__default__']).map(f => (
                  <Descriptions.Item key={f.field} label={<span className="mono">{f.field}</span>}>
                    {f.desc}
                  </Descriptions.Item>
                ))}
              </Descriptions>
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={10}>
            <Card size="small" title="数据生效路径">
              <Steps
                direction="vertical"
                size="small"
                current={-1}
                items={[
                  { title: '加载', description: '启动时按优先级读取全部启用 Provider。' },
                  { title: '合并', description: '同一键值按优先级覆盖，低优先级仅补缺。' },
                  { title: '查询', description: '请求进入时按最长前缀 / 精确键匹配。' },
                  { title: '回显', description: '命中结果写入 ip / client 字段并标记来源。' },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={14}>
            <Card size="small" title="常见问题" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={[
                  { q: '条目数为 0', a: '检查文件路径 / URL 是否可读，命令 stdout 是否为合法 JSON。' },
                  { q: '状态为错误', a: '展开告警查看错误信息；修正后可手动点击「同步」。' },
                  { q: '同步后不生效', a: '确认优先级顺序，未被更高优先级数据覆盖；必要时停用旧 Provider。' },
                  { q: '凭据显示 ***', a: '这是掩码，提交 *** 会保留原请求头；要更换请填入新值。' },
                ]}
                rowKey="q"
                size="small"
                pagination={false}
                columns={[
                  { title: '现象', dataIndex: 'q', width: 130, render: (v: string) => <Tag>{v}</Tag> },
                  { title: '处理方式', dataIndex: 'a' },
                ]}
              />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={13}>
            <Card size="small" title="Provider 配置字段" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={[
                  { field: 'name', desc: '数据集内唯一名称，内置项不可重名', required: '必填' },
                  { field: 'kind', desc: 'file / remote / command；创建后不可修改', required: '必填' },
                  { field: 'priority', desc: '数字越小越优先，同优先级按加载顺序', required: '必填' },
                  { field: 'path', desc: '本地文件、目录或 JSON / CSV', required: 'file' },
                  { field: 'url', desc: '远程数据集地址，支持自定义请求头', required: 'remote' },
                  { field: 'command', desc: '执行命令并读取 stdout 的 JSON', required: 'command' },
                  { field: 'refresh_min', desc: '自动刷新间隔，0 表示仅启动时加载', required: '可选' },
                  { field: 'headers', desc: '远程请求头；保存后返回 *** 掩码', required: '可选' },
                ]}
                rowKey="field"
                size="small"
                pagination={false}
                columns={[
                  { title: '字段', dataIndex: 'field', width: 130, render: (v: string) => <Text code>{v}</Text> },
                  { title: '含义', dataIndex: 'desc' },
                  { title: '要求', dataIndex: 'required', width: 70, render: (v: string) => <Tag>{v}</Tag> },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={11}>
            <Card size="small" title="数据格式要求">
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="CIDR 列表">每行一个 CIDR，可带组织名与备注</Descriptions.Item>
                <Descriptions.Item label="JSON">数组或对象，字段名需与判定字段一致</Descriptions.Item>
                <Descriptions.Item label="命令输出">stdout 必须是单个合法 JSON 文档</Descriptions.Item>
                <Descriptions.Item label="编码">UTF-8；CSV 首行作为表头</Descriptions.Item>
                <Descriptions.Item label="大小建议">单文件 &lt; 50 MB，超出请拆分或改用远程</Descriptions.Item>
              </Descriptions>
              <p className="section-note" style={{ marginBottom: 0 }}>
                加载失败不会阻塞服务启动，错误会记录在 Provider 状态与页面顶部告警中。
              </p>
            </Card>
          </Col>
        </Row>
      </>
    ),
  }));

  return (
    <>
      <PageHeader
        title="数据源"
        description="每个数据集由多个 Provider 按优先级叠加：内置数据兜底，本地文件、云端 URL 与命令输出都可以接入。"
        extra={
          <Space wrap>
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
            {canEdit && <Button icon={<CloudSyncOutlined />} onClick={syncAll}>同步当前数据集</Button>}
            {canEdit && <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>添加 Provider</Button>}
          </Space>
        }
      />

      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：可以查看数据源状态，不能新增或修改。" />}

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="数据集" value={stats.datasets} prefix={<DatabaseOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="Provider" value={stats.providerCount} prefix={<ApartmentOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="本地条目" value={stats.entries} prefix={<FileSyncOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="异常 Provider"
              value={stats.failing}
              prefix={<WarningOutlined />}
              valueStyle={{ color: stats.failing ? '#f04438' : '#059669' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        {datasets.map(d => {
          const list = d.providers || [];
          const entries = list.reduce((n, p) => n + (p.entries || 0), 0);
          const ok = list.filter(p => p.status === 'ok').length;
          const pct = list.length ? Math.round((ok / list.length) * 100) : 0;
          return (
            <Col xs={24} md={12} xl={8} key={d.name}>
              <Card
                hoverable
                onClick={() => setActive(d.name)}
                style={active === d.name ? { borderColor: '#6366f1', boxShadow: '0 0 0 2px rgba(99,102,241,.12)' } : undefined}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15 }}>{d.name}</div>
                    <Text type="secondary" style={{ fontSize: 12 }}>{list.length} 个 Provider · {entries.toLocaleString()} 条</Text>
                  </div>
                  <Tag color={active === d.name ? 'purple' : 'default'}>{active === d.name ? '当前' : '切换'}</Tag>
                </div>
                <Progress
                  percent={pct}
                  size="small"
                  strokeColor={pct === 100 ? '#12b76a' : pct >= 50 ? '#f79009' : '#f04438'}
                  style={{ marginTop: 12 }}
                  format={() => `${ok}/${list.length} 正常`}
                />
              </Card>
            </Col>
          );
        })}
      </Row>

      <Card styles={{ body: { paddingTop: 8 } }}>
        <Tabs activeKey={active} onChange={setActive} items={tabItems} />
      </Card>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={14}>
          <Card title="Provider 类型说明" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={[
                { kind: 'embedded', label: '内置', desc: '随二进制发布，无需配置，作为最后兜底。', refresh: '随版本更新' },
                { kind: 'file', label: '本地文件', desc: '读取 JSON / CSV / CIDR 目录，可设置监听间隔热加载。', refresh: '启动 + 可选轮询' },
                { kind: 'remote', label: '远程 URL', desc: '拉取云端数据集，支持自定义请求头鉴权。', refresh: '按 refresh_min' },
                { kind: 'command', label: '命令生成', desc: '执行本机命令并读取 stdout 的 JSON，适合对接内部管道。', refresh: '手动同步 / 定时' },
              ]}
              rowKey="kind"
              size="small"
              pagination={false}
              columns={[
                { title: '类型', dataIndex: 'label', width: 110, render: (v: string, r: any) => <Tag color={KIND_COLOR[r.kind]}>{v}</Tag> },
                { title: '数据来源', dataIndex: 'desc' },
                { title: '刷新方式', dataIndex: 'refresh', width: 140, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="接入步骤">
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                { title: '选择数据集', description: '在页签中切换到目标数据集，例如 datacenter_cidr。' },
                { title: '添加 Provider', description: '填写名称、类型与优先级；同名 Provider 唯一。' },
                { title: '同步并检查', description: '远程与命令类型可手动同步，状态变为「正常」且条目 > 0。' },
                { title: '回显验证', description: '在 /echo 响应中确认 connection_type 与 geo_source 已命中新数据。' },
              ]}
            />
            <Descriptions column={1} size="small" bordered style={{ marginTop: 12 }}>
              <Descriptions.Item label="覆盖顺序">优先级数字越小越先使用</Descriptions.Item>
              <Descriptions.Item label="删除内置">内置 Provider 不可删除，只能停用</Descriptions.Item>
              <Descriptions.Item label="敏感头">已保存的请求头返回 ***，提交 *** 保持原值</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Modal
        title={editing ? `编辑 Provider · ${editing.name}` : '添加 Provider'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={submit}
        confirmLoading={saving}
        okText="保存并加载"
        width={640}
        destroyOnClose
      >
        <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
          <Form.Item
            name="name"
            label="名称（唯一）"
            rules={[{ required: true, message: '请填写名称' }]}
          >
            <Input disabled={!!editing} placeholder="例如 my-ja4-lib" />
          </Form.Item>

          <Space size={12} style={{ display: 'flex' }}>
            <Form.Item name="kind" label="类型" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Select
                disabled={!!editing}
                options={[
                  { value: 'file', label: '本地文件 / 目录' },
                  { value: 'remote', label: '云端 / 远程 URL' },
                  { value: 'command', label: '命令生成' },
                ]}
              />
            </Form.Item>
            <Form.Item name="priority" label="优先级" style={{ width: 140 }}>
              <InputNumber min={-100} max={10000} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.kind !== cur.kind}>
            {({ getFieldValue }) => {
              const kind = getFieldValue('kind');
              if (kind === 'file') {
                return (
                  <>
                    <Form.Item name="path" label="文件或目录路径" rules={[{ required: true, message: '请填写路径' }]}>
                      <Input placeholder="/data/lib.json 或 /data/cidr-dir" />
                    </Form.Item>
                    <Form.Item name="refresh_min" label="监听间隔（分钟，0 表示仅启动时加载）">
                      <InputNumber min={0} style={{ width: 220 }} />
                    </Form.Item>
                  </>
                );
              }
              if (kind === 'remote') {
                return (
                  <>
                    <Form.Item name="url" label="URL" rules={[{ required: true, message: '请填写 URL' }]}>
                      <Input placeholder="https://cloud.example.com/lib.json（支持自定义协议）" />
                    </Form.Item>
                    <Form.Item name="headers" label="请求头 JSON（可选）">
                      <Input.TextArea
                        rows={3}
                        className="mono"
                        placeholder='{"Authorization":"Bearer xxx"}；值填 "***" 表示保留原值'
                      />
                    </Form.Item>
                    <Form.Item name="refresh_min" label="刷新间隔（分钟，0 表示不自动刷新）">
                      <InputNumber min={0} style={{ width: 220 }} />
                    </Form.Item>
                  </>
                );
              }
              if (kind === 'command') {
                return (
                  <Form.Item name="command" label="命令（stdout 必须是数据 JSON）" rules={[{ required: true, message: '请填写命令' }]}>
                    <Input.TextArea rows={3} className="mono" placeholder='cat /etc/my-lib.json | jq -c .' />
                  </Form.Item>
                );
              }
              return null;
            }}
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

export default Datasets;

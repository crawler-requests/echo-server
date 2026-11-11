import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Form,
  Input,
  InputNumber,
  message,
  Modal,
  Popconfirm,
  Progress,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
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
  ApiOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  CopyOutlined,
  DeleteOutlined,
  FireOutlined,
  KeyOutlined,
  LockOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { APIKey, AuditEntry, Config, MetricsSummary, downloadFile, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const randomToken = () => {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
};

const Security: React.FC = () => {
  const { token, canEdit, logout } = useSession();
  const fail = useApiError();
  const [cfg, setCfg] = useState<Config>({});
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [tab, setTab] = useState('overview');
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [traffic, setTraffic] = useState<MetricsSummary | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [newKey, setNewKey] = useState('');
  const [form] = Form.useForm();
  const [purgeDays, setPurgeDays] = useState(30);

  const load = async () => {
    setLoading(true);
    try {
      const [c, k, a, m] = await Promise.all([
        getJSON<Config>('/api/config', token),
        canEdit ? getJSON<APIKey[]>('/api/apikeys', token).catch(() => []) : Promise.resolve([]),
        getJSON<AuditEntry[]>('/api/audit?limit=20', token).catch(() => []),
        getJSON<MetricsSummary>('/api/metrics/summary?hours=24', token).catch(() => null),
      ]);
      setCfg(c || {});
      setKeys(k || []);
      setEvents(a || []);
      if (m) setTraffic(m);
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  const checks = useMemo(() => {
    const lineCount = (v?: string) =>
      (v || '')
        .split(/[\n,]/)
        .map(s => s.trim())
        .filter(Boolean).length;
    const tokenLen = cfg.api_token && cfg.api_token !== '***' ? cfg.api_token.length : 0;
    const activeKeys = keys.filter(k => k.enabled).length;
    const list = [
      { key: 'token', label: '回显接口要求凭据', ok: cfg.require_token === 'true', hint: '在「鉴权与密钥」中开启 require_token' },
      { key: 'secret', label: '共享 Token 足够长或存在命名 Key', ok: tokenLen >= 32 || activeKeys > 0, hint: '生成 32 位以上随机 Token，或创建命名 API Key' },
      { key: 'rate', label: '已配置每 IP 限流', ok: Number(cfg.rate_limit_per_min || 0) > 0, hint: '设置每分钟请求上限，防止暴力探测' },
      { key: 'body', label: '已限制请求体大小', ok: Number(cfg.body_limit_kb || 0) > 0, hint: '避免超大请求体耗尽内存' },
      { key: 'register', label: '自助注册已关闭', ok: cfg.allow_registration !== 'true', hint: '公网实例建议只由管理员创建账号' },
      { key: 'headers', label: '安全响应头已开启', ok: cfg.security_headers !== 'false', hint: '保持 Permissions-Policy 等头的默认开启' },
      { key: 'retention', label: '日志保留策略已设置', ok: Number(cfg.log_retention_days || 0) > 0, hint: '设置保留天数，避免数据库无限增长' },
      { key: 'ip', label: 'IP 允许 / 拒绝列表已配置', ok: lineCount(cfg.ip_allowlist) + lineCount(cfg.ip_denylist) > 0, hint: '按需限制来源网段（可选）' },
      { key: 'jwt', label: 'JWT 密钥来自环境变量', ok: cfg.jwt_secret_env === 'true', hint: '生产环境通过 ECHO_SERVER_JWT_SECRET 注入' },
    ];
    return list;
  }, [cfg, keys]);

  const passed = checks.filter(c => c.ok).length;
  const score = Math.round((passed / checks.length) * 100);
  const ipRules = useMemo(() => {
    const count = (v?: string) => (v || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean).length;
    return count(cfg.ip_allowlist) + count(cfg.ip_denylist);
  }, [cfg]);
  const activeKeys = keys.filter(k => k.enabled).length;
  const recentSecurity = events.filter(e => e.action.startsWith('security') || e.action.startsWith('apikey') || e.action.startsWith('system'));

  const overviewTab = (
    <>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="安全评分"
              value={score}
              suffix="/ 100"
              valueStyle={{ color: score >= 80 ? '#059669' : score >= 50 ? '#d97706' : '#f04438' }}
            />
            <Progress percent={score} showInfo={false} size="small" strokeColor={score >= 80 ? '#12b76a' : score >= 50 ? '#f79009' : '#f04438'} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="检查通过" value={passed} suffix={`/ ${checks.length}`} prefix={<SafetyCertificateOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="启用中的 Key" value={activeKeys} suffix={`/ ${keys.length}`} prefix={<KeyOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="24h 请求" value={traffic?.total ?? 0} prefix={<FireOutlined />} /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card title="安全检查清单" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={checks}
              rowKey="key"
              size="small"
              pagination={false}
              columns={[
                {
                  title: '状态',
                  dataIndex: 'ok',
                  width: 70,
                  render: (ok: boolean) =>
                    ok ? <CheckCircleFilled style={{ color: '#12b76a' }} /> : <CloseCircleFilled style={{ color: '#f04438' }} />,
                },
                { title: '检查项', dataIndex: 'label' },
                { title: '建议', dataIndex: 'hint', render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
                {
                  title: '结果',
                  dataIndex: 'ok',
                  width: 80,
                  render: (ok: boolean) => <Tag color={ok ? 'success' : 'error'}>{ok ? '通过' : '待处理'}</Tag>,
                },
              ]}
            />
          </Card>

          <Card title="最近安全与系统事件" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={recentSecurity}
              rowKey="id"
              size="small"
              pagination={false}
              locale={{ emptyText: '暂无安全相关审计记录' }}
              columns={[
                { title: '时间', dataIndex: 'ts', width: 170, render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text> },
                { title: '动作', dataIndex: 'action', width: 180, render: (v: string) => <Tag color={v.startsWith('security') ? 'red' : v.startsWith('apikey') ? 'gold' : 'orange'}>{v}</Tag> },
                { title: '对象', dataIndex: 'target', render: (v: string) => <span className="mono">{v || '—'}</span> },
                { title: '操作者', dataIndex: 'username', width: 110 },
              ]}
            />
          </Card>
        </Col>

        <Col xs={24} xl={10}>
          <Card title="暴露面概况">
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="回显鉴权">{cfg.require_token === 'true' ? <Tag color="green">已开启</Tag> : <Tag color="orange">未开启</Tag>}</Descriptions.Item>
              <Descriptions.Item label="限流">{Number(cfg.rate_limit_per_min || 0) > 0 ? `${cfg.rate_limit_per_min} 次 / 分钟 / IP` : <Text type="warning">未开启</Text>}</Descriptions.Item>
              <Descriptions.Item label="请求体上限">{Number(cfg.body_limit_kb || 0) > 0 ? `${cfg.body_limit_kb} KB` : '未限制'}</Descriptions.Item>
              <Descriptions.Item label="CORS 来源">{cfg.cors_origins ? <span className="mono">{cfg.cors_origins}</span> : '默认 *'}</Descriptions.Item>
              <Descriptions.Item label="IP 规则条目">{ipRules}</Descriptions.Item>
              <Descriptions.Item label="维护模式">{cfg.maintenance_mode === 'true' ? <Tag color="orange">开启</Tag> : <Tag color="green">关闭</Tag>}</Descriptions.Item>
              <Descriptions.Item label="24h 独立 IP">{traffic?.unique_ips ?? 0}</Descriptions.Item>
            </Descriptions>
          </Card>

          <Card title="待处理建议" style={{ marginTop: 16 }}>
            {checks.filter(c => !c.ok).length === 0 ? (
              <Alert type="success" showIcon message="全部检查通过" description="当前配置已达到内置安全基线，建议继续保持并定期轮换凭据。" />
            ) : (
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                {checks.filter(c => !c.ok).map(c => (
                  <div key={c.key} className="setting-tile">
                    <div>
                      <div className="s-title"><WarningOutlined style={{ color: '#f79009', marginRight: 6 }} />{c.label}</div>
                      <div className="s-desc">{c.hint}</div>
                    </div>
                  </div>
                ))}
              </Space>
            )}
          </Card>
        </Col>
      </Row>
    </>
  );

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async (patch: Record<string, string>, label: string) => {
    setSaving(true);
    try {
      await postJSON('/api/config', token, patch);
      message.success(label + '已保存');
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setSaving(false);
    }
  };

  const bool = (key: string) => cfg[key] === 'true';
  const num = (key: string, fallback = 0) => Number(cfg[key] || fallback) || fallback;

  const createKey = async () => {
    try {
      const values = await form.validateFields();
      const res = await postJSON<{ key: string }>('/api/apikeys', token, values);
      setCreateOpen(false);
      setNewKey(res.key);
      form.resetFields();
      await load();
    } catch (err) {
      if ((err as { errorFields?: unknown }).errorFields) return;
      fail(err);
    }
  };

  const toggleKey = async (k: APIKey, enabled: boolean) => {
    try {
      await fetch('/api/apikeys', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ id: k.id, enabled }),
      }).then(async res => {
        if (!res.ok) throw new Error(await res.text());
      });
      message.success(enabled ? 'Key 已启用' : 'Key 已停用');
      await load();
    } catch (err) {
      fail(err);
    }
  };

  const removeKey = async (k: APIKey) => {
    try {
      await fetch(`/api/apikeys?id=${k.id}`, {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + token },
      }).then(async res => {
        if (!res.ok) throw new Error(await res.text());
      });
      message.success('Key 已删除');
      await load();
    } catch (err) {
      fail(err);
    }
  };

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      message.success('已复制到剪贴板');
    } catch {
      message.warning('浏览器不允许自动复制，请手动选择');
    }
  };

  const rotateJWT = () => {
    Modal.confirm({
      title: '轮换会话签名密钥？',
      icon: <WarningOutlined style={{ color: '#f04438' }} />,
      content: '所有已登录的浏览器与 JWT 会立即失效，需要重新登录。API Key 与共享 Token 不受影响。',
      okText: '确认轮换',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await postJSON('/api/system/rotate-jwt', token, {});
          message.success('已轮换，正在退出当前会话…');
          setTimeout(logout, 900);
        } catch (err) {
          fail(err);
        }
      },
    });
  };

  const purge = (all: boolean) => {
    Modal.confirm({
      title: all ? '清空全部查询日志？' : `删除 ${purgeDays} 天前的查询日志？`,
      content: '该操作不可撤销。审计日志与账号数据不受影响。',
      okText: '确认清理',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          const res = await postJSON<{ deleted: number }>('/api/system/purge-logs', token, all ? { all: true } : { days: purgeDays });
          message.success(`已删除 ${res.deleted} 条记录`);
        } catch (err) {
          fail(err);
        }
      },
    });
  };

  const authTab = (
    <>
    <Row gutter={[16, 16]}>
      <Col xs={24} xl={14}>
        <Card title="回显接口鉴权">
          <div className="setting-tile" style={{ marginBottom: 18 }}>
            <div>
              <div className="s-title"><SafetyCertificateOutlined style={{ color: '#6366f1', marginRight: 8 }} />要求调用方携带凭据</div>
              <div className="s-desc">开启后，/echo 只接受 JWT、共享 API Token 或命名 API Key。</div>
            </div>
            <Switch
              disabled={!canEdit}
              checked={bool('require_token')}
              onChange={v => save({ require_token: v ? 'true' : 'false' }, '鉴权开关')}
            />
          </div>

          <Paragraph style={{ marginBottom: 6 }} type="secondary">共享 API Token（单一长期凭据）</Paragraph>
          <Space.Compact style={{ width: '100%', maxWidth: 640 }}>
            <Input.Password
              disabled={!canEdit}
              value={cfg.api_token || ''}
              placeholder="未设置时无法通过共享 Token 放行"
              onChange={e => setCfg(prev => ({ ...prev, api_token: e.target.value }))}
            />
            {canEdit && (
              <Button icon={<ThunderboltOutlined />} onClick={() => setCfg(prev => ({ ...prev, api_token: randomToken() }))}>随机生成</Button>
            )}
            {canEdit && !!cfg.api_token && cfg.api_token !== '***' && (
              <Button icon={<CopyOutlined />} onClick={() => copy(cfg.api_token)}>复制</Button>
            )}
            {canEdit && cfg.api_token !== '***' && (
              <Button
                type="primary"
                icon={<SaveOutlined />}
                loading={saving}
                onClick={() => save({ api_token: cfg.api_token || '' }, '共享 Token')}
              >
                保存
              </Button>
            )}
          </Space.Compact>
          <p className="section-note">
            请求头 <Text code>X-API-Token</Text> 或参数 <Text code>?token=</Text>。只读账号读到的值会掩码为 <Text code>***</Text>。
          </p>

          <Divider />
          <Paragraph type="secondary">
            命名 API Key 更适合多调用方场景：可以分别授权、单独停用，并保留最后使用时间。
          </Paragraph>
          <Space wrap>
            <Button type="primary" icon={<PlusOutlined />} disabled={!canEdit} onClick={() => setCreateOpen(true)}>创建 API Key</Button>
            <Tag color="blue">请求头 X-API-Key</Tag>
            <Tag>scope=viewer/admin</Tag>
            <Tag>支持过期时间</Tag>
          </Space>
        </Card>
      </Col>

      <Col xs={24} xl={10}>
        <Card title="API Key 列表" extra={<Button size="small" icon={<ReloadOutlined />} onClick={load}>刷新</Button>}>
          <Table
            dataSource={keys}
            rowKey="id"
            size="small"
            pagination={false}
            locale={{ emptyText: '尚未创建命名 Key' }}
            scroll={{ x: 430 }}
            columns={[
              {
                title: '名称 / 前缀',
                dataIndex: 'name',
                render: (_: string, k) => (
                  <div>
                    <div style={{ fontWeight: 600 }}><KeyOutlined /> {k.name}</div>
                    <div className="mono muted">{k.prefix}</div>
                  </div>
                ),
              },
              { title: '权限', dataIndex: 'scope', width: 86, render: (v: string) => <Tag color={v === 'admin' ? 'gold' : 'blue'}>{v}</Tag> },
              {
                title: '状态',
                dataIndex: 'enabled',
                width: 78,
                render: (v: boolean, k) => <Switch size="small" checked={v} disabled={!canEdit} onChange={x => toggleKey(k, x)} />,
              },
              {
                title: '操作',
                width: 70,
                render: (_: unknown, k) => (
                  <Popconfirm title="删除这个 Key？" description="使用该 Key 的调用方会立即失去访问。" okText="删除" cancelText="取消" onConfirm={() => removeKey(k)}>
                    <Button type="text" danger size="small" icon={<DeleteOutlined />} disabled={!canEdit} />
                  </Popconfirm>
                ),
              },
            ]}
          />
          <p className="section-note">最后使用时间会异步刷新，便于识别闲置凭据。明文只在创建时显示一次。</p>
        </Card>
      </Col>
    </Row>

    <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
      <Col xs={24} xl={14}>
        <Card title="鉴权优先级与失败语义" styles={{ body: { padding: 0 } }}>
          <Table
            dataSource={[
              { order: 1, method: 'JWT（Authorization: Bearer）', success: '放行，识别为控制台账号', fail: '继续尝试下一种凭据' },
              { order: 2, method: '命名 API Key（X-API-Key）', success: '按 scope 放行', fail: '无效 / 停用 / 过期 → 继续' },
              { order: 3, method: '共享 Token（X-API-Token / ?token=）', success: '放行，按匿名级权限处理', fail: '全部失败 → 401' },
              { order: 4, method: '匿名（require_token=false）', success: '放行', fail: '403 / 401' },
            ]}
            rowKey="order"
            size="small"
            pagination={false}
            columns={[
              { title: '#', dataIndex: 'order', width: 46 },
              { title: '凭据', dataIndex: 'method', width: 300 },
              { title: '通过', dataIndex: 'success' },
              { title: '失败后', dataIndex: 'fail', width: 190, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
            ]}
          />
        </Card>
      </Col>
      <Col xs={24} xl={10}>
        <Card title="凭据轮换流程">
          <Steps
            direction="vertical"
            size="small"
            current={-1}
            items={[
              { title: '签发新 Key', description: '为每个调用方单独创建，选择最小 scope 与过期时间。' },
              { title: '灰度切换', description: '新旧 Key 并存，更新调用方配置并观察最后使用时间。' },
              { title: '停用旧 Key', description: '确认新 Key 有流量后关闭旧 Key，无需删除以保留记录。' },
              { title: '审计核对', description: '在审计日志确认 apikey.* 操作与操作者。' },
            ]}
          />
        </Card>
      </Col>
    </Row>

    <Card title="回显调用示例" style={{ marginTop: 16 }} styles={{ body: { paddingTop: 8 } }}>
      <Tabs
        size="small"
        items={[
          {
            key: 'jwt',
            label: 'JWT',
            children: (
              <pre className="code-block" style={{ margin: 0 }}>{`curl -H "Authorization: Bearer <jwt>" \\
  "${window.location.origin}/echo?format=json"`}</pre>
            ),
          },
          {
            key: 'key',
            label: 'API Key',
            children: (
              <pre className="code-block" style={{ margin: 0 }}>{`curl -H "X-API-Key: esk_xxx" \\
  "${window.location.origin}/echo?fields=ip.country,client.name"`}</pre>
            ),
          },
          {
            key: 'shared',
            label: '共享 Token',
            children: (
              <pre className="code-block" style={{ margin: 0 }}>{`# 请求头（推荐）
curl -H "X-API-Token: <token>" "${window.location.origin}/echo"

# 查询参数（会进入访问日志）
curl "${window.location.origin}/echo?token=<token>"`}</pre>
            ),
          },
          {
            key: 'anon',
            label: '匿名',
            children: (
              <pre className="code-block" style={{ margin: 0 }}>{`# 仅在 require_token=false 时可用
curl "${window.location.origin}/echo?format=text"`}</pre>
            ),
          },
        ]}
      />
      <p className="section-note" style={{ marginBottom: 0 }}>
        鉴权失败返回 401 且不区分「凭据不存在 / 已停用 / 已过期」，避免枚举探测。
      </p>
    </Card>
    </>
  );

  const networkTab = (
    <>
    <Row gutter={[16, 16]}>
      <Col xs={24} xl={12}>
        <Card title="IP 允许 / 拒绝列表">
          <Paragraph type="secondary">每行一个 IP 或 CIDR，也支持逗号分隔。拒绝优先；允许列表为空表示不限制。</Paragraph>
          <Form layout="vertical">
            <Form.Item label="允许列表（白名单）">
              <Input.TextArea
                rows={4}
                disabled={!canEdit}
                className="mono"
                placeholder={'192.168.1.0/24\n10.0.0.8'}
                value={cfg.ip_allowlist || ''}
                onChange={e => setCfg(prev => ({ ...prev, ip_allowlist: e.target.value }))}
              />
            </Form.Item>
            <Form.Item label="拒绝列表（黑名单）">
              <Input.TextArea
                rows={4}
                disabled={!canEdit}
                className="mono"
                placeholder={'203.0.113.0/24\n198.51.100.7'}
                value={cfg.ip_denylist || ''}
                onChange={e => setCfg(prev => ({ ...prev, ip_denylist: e.target.value }))}
              />
            </Form.Item>
          </Form>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            disabled={!canEdit}
            loading={saving}
            onClick={() => save({ ip_allowlist: cfg.ip_allowlist || '', ip_denylist: cfg.ip_denylist || '' }, 'IP 规则')}
          >
            保存 IP 规则
          </Button>
          <Alert
            style={{ marginTop: 16 }}
            type="info"
            showIcon
            message="规则只作用于回显流量"
            description="控制台与 /api 不受 IP 列表限制，避免误配置后无法登录修改。"
          />
        </Card>
      </Col>
      <Col xs={24} xl={12}>
        <Card title="限流与请求约束">
          <Form layout="vertical">
            <Form.Item label="每 IP 每分钟请求上限" extra="0 表示关闭限流。计数器按分钟滚动。">
              <InputNumber
                min={0}
                max={1000000}
                disabled={!canEdit}
                style={{ width: '100%' }}
                value={num('rate_limit_per_min')}
                onChange={v => setCfg(prev => ({ ...prev, rate_limit_per_min: String(v ?? 0) }))}
              />
            </Form.Item>
            <Form.Item label="请求体上限（KB）" extra="0 表示不限制；超过上限的请求会收到 413。">
              <InputNumber
                min={0}
                max={1048576}
                disabled={!canEdit}
                style={{ width: '100%' }}
                value={num('body_limit_kb')}
                onChange={v => setCfg(prev => ({ ...prev, body_limit_kb: String(v ?? 0) }))}
              />
            </Form.Item>
            <Form.Item label="CORS 允许来源" extra="逗号分隔；留空保持回显接口的 * 默认行为，填写 * 则显式允许全部。">
              <Input
                disabled={!canEdit}
                placeholder="https://console.example.com, https://app.example.com"
                value={cfg.cors_origins || ''}
                onChange={e => setCfg(prev => ({ ...prev, cors_origins: e.target.value }))}
              />
            </Form.Item>
            <div className="setting-tile" style={{ marginBottom: 16 }}>
              <div>
                <div className="s-title">附加安全响应头</div>
                <div className="s-desc">Permissions-Policy、X-XSS-Protection: 0、Cross-Origin-Opener-Policy。基础头始终开启。</div>
              </div>
              <Switch
                disabled={!canEdit}
                checked={cfg.security_headers !== 'false'}
                onChange={v => save({ security_headers: v ? 'true' : 'false' }, '安全响应头')}
              />
            </div>
          </Form>
          <Button
            type="primary"
            icon={<SaveOutlined />}
            disabled={!canEdit}
            loading={saving}
            onClick={() =>
              save(
                {
                  rate_limit_per_min: String(num('rate_limit_per_min')),
                  body_limit_kb: String(num('body_limit_kb')),
                  cors_origins: cfg.cors_origins || '',
                },
                '网络约束',
              )
            }
          >
            保存网络约束
          </Button>
        </Card>
      </Col>
    </Row>

    <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
      <Col xs={24} xl={13}>
        <Card title="规则解析预览">
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="允许条目">
              <Space wrap>
                {(cfg.ip_allowlist || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean).length === 0
                  ? <Text type="secondary">未配置（不限制来源）</Text>
                  : (cfg.ip_allowlist || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean).map(v => <Tag key={v} color="green">{v}</Tag>)}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="拒绝条目">
              <Space wrap>
                {(cfg.ip_denylist || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean).length === 0
                  ? <Text type="secondary">未配置</Text>
                  : (cfg.ip_denylist || '').split(/[\n,]/).map(s => s.trim()).filter(Boolean).map(v => <Tag key={v} color="red">{v}</Tag>)}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="匹配顺序">拒绝列表优先 → 允许列表 → 默认放行</Descriptions.Item>
            <Descriptions.Item label="作用范围">仅回显流量，控制台与 /api 不受影响</Descriptions.Item>
          </Descriptions>
          <p className="section-note">支持单个 IP 与 CIDR；IPv6 建议使用完整地址或 /64 前缀。</p>
        </Card>
      </Col>
      <Col xs={24} xl={11}>
        <Card title="限流与 CORS 行为">
          <Table
            dataSource={[
              { scene: '超过每分钟上限', result: '429 Too Many Requests', note: '按来源 IP 计数，60 秒滚动窗口' },
              { scene: '请求体超过上限', result: '413 Payload Too Large', note: `当前 ${num('body_limit_kb') || '未设置'} KB` },
              { scene: '来源不在白名单', result: '403 Forbidden', note: '白名单非空时生效' },
              { scene: '命中黑名单', result: '403 Forbidden', note: '优先级高于白名单' },
              { scene: '跨域预检', result: '204 + CORS 头', note: cfg.cors_origins ? '仅允许列出来源' : '默认 *' },
            ]}
            rowKey="scene"
            size="small"
            pagination={false}
            columns={[
              { title: '场景', dataIndex: 'scene' },
              { title: '响应', dataIndex: 'result', width: 150, render: (v: string) => <Tag color={v.startsWith('4') ? 'orange' : 'blue'}>{v}</Tag> },
              { title: '说明', dataIndex: 'note', width: 190, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v}</Text> },
            ]}
          />
        </Card>
      </Col>
    </Row>
    </>
  );

  const protectionTab = (
    <>
    <Row gutter={[16, 16]}>
      <Col xs={24} xl={12}>
        <Card title="维护模式">
          <div className="setting-tile" style={{ marginBottom: 16 }}>
            <div>
              <div className="s-title"><LockOutlined style={{ color: '#f79009', marginRight: 8 }} />暂停回显服务</div>
              <div className="s-desc">开启后未携带有效凭据的 echo 请求返回 503；控制台与 API 保持可用，方便随时恢复。</div>
            </div>
            <Switch
              disabled={!canEdit}
              checked={bool('maintenance_mode')}
              onChange={v => save({ maintenance_mode: v ? 'true' : 'false' }, '维护模式')}
            />
          </div>
          <Form layout="vertical">
            <Form.Item label="维护提示文案">
              <Input
                disabled={!canEdit}
                placeholder="例如：正在升级数据源，预计 10 分钟恢复"
                value={cfg.maintenance_message || ''}
                onChange={e => setCfg(prev => ({ ...prev, maintenance_message: e.target.value }))}
              />
            </Form.Item>
          </Form>
          <Button
            icon={<SaveOutlined />}
            disabled={!canEdit}
            loading={saving}
            onClick={() => save({ maintenance_message: cfg.maintenance_message || '' }, '维护提示')}
          >
            保存提示
          </Button>
          {bool('maintenance_mode') && <Alert style={{ marginTop: 16 }} type="warning" showIcon message="维护模式已开启" />}
        </Card>

        <Card title="日志保留" style={{ marginTop: 16 }}>
          <Form layout="vertical">
            <Form.Item label="保留天数" extra="0 表示永久保留；后台每 6 小时清理一次。">
              <InputNumber
                min={0}
                max={3650}
                disabled={!canEdit}
                style={{ width: '100%' }}
                value={num('log_retention_days')}
                onChange={v => setCfg(prev => ({ ...prev, log_retention_days: String(v ?? 0) }))}
              />
            </Form.Item>
          </Form>
          <Space wrap>
            <Button icon={<SaveOutlined />} disabled={!canEdit} loading={saving} onClick={() => save({ log_retention_days: String(num('log_retention_days')) }, '日志保留策略')}>
              保存保留策略
            </Button>
            <Button danger icon={<DeleteOutlined />} disabled={!canEdit} onClick={() => purge(false)}>清理过期日志</Button>
            <Button danger type="primary" ghost disabled={!canEdit} onClick={() => purge(true)}>清空全部日志</Button>
          </Space>
          <p className="section-note">当前按 {num('log_retention_days') || '不限制'} 天保留查询记录。</p>
        </Card>
      </Col>

      <Col xs={24} xl={12}>
        <Card title="会话安全">
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="JWT 有效期">12 小时</Descriptions.Item>
            <Descriptions.Item label="签名算法">HS256</Descriptions.Item>
            <Descriptions.Item label="密钥来源">{cfg.jwt_secret_env ? '环境变量 ECHO_SERVER_JWT_SECRET' : 'SQLite（可在此轮换）'}</Descriptions.Item>
            <Descriptions.Item label="账号校验">每次请求回查数据库，禁用/删除即时生效</Descriptions.Item>
          </Descriptions>
          <Divider />
          <Button danger icon={<WarningOutlined />} disabled={!canEdit} onClick={rotateJWT}>轮换签名密钥并退出所有会话</Button>
          <p className="section-note">轮换后 API Key、共享 Token 与回显服务不受影响，仅浏览器登录态失效。</p>
        </Card>

        <Card title="防护建议" style={{ marginTop: 16 }}>
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <div><Tag color="red">公网</Tag>务必开启 Token 鉴权、配置限流，并在前面加反向代理与 HTTPS 证书。</div>
            <div><Tag color="orange">误配置</Tag>IP 规则只作用于回显流量，因此永远不会把管理员锁在控制台之外。</div>
            <div><Tag color="blue">审计</Tag>配置变更、账号变更与密钥操作都会写入审计日志并生成通知。</div>
          </Space>
        </Card>
      </Col>
    </Row>

    <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
      <Col xs={24} xl={10}>
        <Card title="备份与恢复">
          <Paragraph type="secondary">
            备份通过 <Text code>VACUUM INTO</Text> 生成一致性快照，包含账号、配置、审计与日志。恢复时停服替换数据库文件即可。
          </Paragraph>
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <Button
              block
              icon={<SaveOutlined />}
              disabled={!canEdit}
              onClick={async () => {
                try {
                  await downloadFile('/api/system/backup', token, 'echo-server-backup.db');
                  message.success('备份已开始下载');
                } catch (err) {
                  fail(err);
                }
              }}
            >
              下载数据库快照
            </Button>
            <Button block icon={<KeyOutlined />} onClick={() => copy(`curl -H "Authorization: Bearer <jwt>" ${window.location.origin}/api/system/backup -o backup.db`)}>
              复制备份命令
            </Button>
          </Space>
          <Descriptions column={1} size="small" bordered style={{ marginTop: 12 }}>
            <Descriptions.Item label="包含内容">账号、配置、API Key、审计、查询日志</Descriptions.Item>
            <Descriptions.Item label="不包含">环境变量、TLS 证书与外部数据源文件</Descriptions.Item>
            <Descriptions.Item label="建议频率">配置变更后 / 每日一次</Descriptions.Item>
          </Descriptions>
        </Card>
      </Col>
      <Col xs={24} xl={14}>
        <Card title="最近系统维护记录" styles={{ body: { padding: 0 } }}>
          <Table
            dataSource={events.filter(e => e.action.startsWith('system') || e.action.startsWith('security'))}
            rowKey="id"
            size="small"
            pagination={false}
            locale={{ emptyText: '暂无系统维护记录' }}
            columns={[
              { title: '时间', dataIndex: 'ts', width: 170, render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text> },
              { title: '动作', dataIndex: 'action', width: 190, render: (v: string) => <Tag color={v.includes('rotate') ? 'red' : v.includes('purge') ? 'orange' : 'blue'}>{v}</Tag> },
              { title: '对象 / 详情', render: (_: unknown, e) => <span className="mono" style={{ fontSize: 12 }}>{e.target || e.detail || '—'}</span> },
              { title: '操作者', dataIndex: 'username', width: 110 },
            ]}
          />
          <p className="section-note" style={{ padding: '0 16px' }}>
            维护类操作会同时生成站内通知；完整历史可在「审计日志」按 system. 前缀筛选。
          </p>
        </Card>
      </Col>
    </Row>
    </>
  );

  return (
    <>
      <PageHeader
        title="安全与防护"
        description="命名 API Key、IP 白黑名单、限流、维护模式、会话轮换与日志保留，集中管理对外暴露面。"
        extra={<Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>}
      />
      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：可以查看策略，但不能修改。" />}
      <Spin spinning={loading}>
        <Card styles={{ body: { paddingTop: 8 } }}>
          <Tabs
            activeKey={tab}
            onChange={setTab}
            items={[
              { key: 'overview', label: <span><SafetyCertificateOutlined /> 安全概览</span>, children: overviewTab },
              { key: 'auth', label: <span><ApiOutlined /> 鉴权与密钥</span>, children: authTab },
              { key: 'network', label: <span><SafetyCertificateOutlined /> 网络防护</span>, children: networkTab },
              { key: 'protection', label: <span><LockOutlined /> 系统保护</span>, children: protectionTab },
            ]}
          />
        </Card>
      </Spin>

      <Modal
        title="创建 API Key"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={createKey}
        okText="创建"
        cancelText="取消"
      >
        <Form form={form} layout="vertical" initialValues={{ scope: 'viewer' }}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '给这个 Key 起个名字' }]}>
            <Input placeholder="例如：ci-runner / grafana" />
          </Form.Item>
          <Form.Item name="scope" label="权限">
            <Select options={[{ value: 'viewer', label: 'viewer — 只读' }, { value: 'admin', label: 'admin — 管理与写入' }]} />
          </Form.Item>
          <Form.Item name="expires_at" label="过期时间（可选，RFC3339）" extra="例如 2027-01-01T00:00:00Z；留空表示长期有效。">
            <Input placeholder="2027-01-01T00:00:00Z" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="API Key 已创建"
        open={!!newKey}
        onCancel={() => setNewKey('')}
        footer={[
          <Button key="copy" icon={<CopyOutlined />} onClick={() => copy(newKey)}>复制 Key</Button>,
          <Button key="ok" type="primary" onClick={() => setNewKey('')}>我已保存</Button>,
        ]}
      >
        <Alert type="warning" showIcon message="这是唯一一次显示明文" description="关闭后无法再次查看，只能重新创建。" style={{ marginBottom: 14 }} />
        <pre className="code-block" style={{ whiteSpace: 'break-all' }}>{newKey}</pre>
        <p className="section-note">调用示例：<Text code>curl -H "X-API-Key: {newKey.slice(0, 12)}…" {window.location.origin}/echo</Text></p>
      </Modal>
    </>
  );
};

export default Security;

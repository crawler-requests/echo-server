import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Input,
  message,
  Progress,
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
  CheckCircleFilled,
  CloseCircleFilled,
  CopyOutlined,
  KeyOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { APIKey, AuditEntry, Config, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const randomToken = () => {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
};

const AUTH_MATRIX = [
  { endpoint: '/echo', anon: '仅 require_token=false', jwt: '✓', shared: '✓', key: '✓' },
  { endpoint: '/api/*（读）', anon: '✗（setup/status 除外）', jwt: '✓', shared: '✗', key: 'viewer/admin' },
  { endpoint: '/api/*（写）', anon: '✗', jwt: 'admin', shared: '✗', key: 'admin' },
  { endpoint: '/ui/', anon: '登录页 / 初始化向导', jwt: '✓', shared: '✗', key: '✗' },
  { endpoint: '/metrics', anon: '✓', jwt: '✓', shared: '✗', key: '✗' },
  { endpoint: '/health', anon: '✓', jwt: '✓', shared: '✗', key: '✗' },
];

const Access: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [cfg, setCfg] = useState<Config>({});
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [codeTab, setCodeTab] = useState('curl');

  const load = async () => {
    setLoading(true);
    try {
      const [c, k, a] = await Promise.all([
        getJSON<Config>('/api/config', token),
        canEdit ? getJSON<APIKey[]>('/api/apikeys', token).catch(() => []) : Promise.resolve([]),
        getJSON<AuditEntry[]>('/api/audit?action=security.&limit=8', token).catch(() => []),
      ]);
      setCfg(c || {});
      setKeys(k || []);
      setEvents(a || []);
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

  const requireToken = cfg.require_token === 'true';
  const apiToken = cfg.api_token || '';
  const tokenVisible = apiToken && apiToken !== '***';

  const strength = useMemo(() => {
    if (!tokenVisible) return { score: 0, label: '未设置', color: '#94a3b8' };
    const len = apiToken.length;
    const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(apiToken)).length;
    const score = Math.min(100, Math.round((Math.min(len, 48) / 48) * 70 + (classes / 4) * 30));
    const label = score >= 85 ? '强度高' : score >= 60 ? '强度中' : '强度偏低';
    const color = score >= 85 ? '#12b76a' : score >= 60 ? '#f79009' : '#f04438';
    return { score, label, color };
  }, [apiToken, tokenVisible]);

  const enabledKeys = keys.filter(k => k.enabled);
  const activeChecks = [
    { label: requireToken, text: '回显接口要求 Token' },
    { label: tokenVisible && apiToken.length >= 32, text: '共享 Token 长度 ≥ 32' },
    { label: enabledKeys.length > 0, text: '已创建命名 API Key' },
    { label: cfg.allow_registration !== 'true', text: '自助注册已关闭' },
  ];
  const passed = activeChecks.filter(c => c.label).length;

  const save = async () => {
    setSaving(true);
    try {
      await postJSON('/api/config', token, {
        require_token: requireToken ? 'true' : 'false',
        api_token: apiToken === '***' ? '' : apiToken,
      });
      message.success('访问控制已保存');
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setSaving(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      message.success('已复制');
    } catch {
      message.warning('浏览器不允许自动复制，请手动选择文本');
    }
  };

  const baseURL = `${window.location.origin}`;
  const samples: Record<string, { lang: string; code: string }> = {
    curl: {
      lang: 'curl',
      code: `# 共享 Token
curl -H "X-API-Token: ${tokenVisible ? apiToken : '<token>'}" \\
  "${baseURL}/echo?format=json"

# 命名 API Key
curl -H "X-API-Key: esk_xxx" \\
  "${baseURL}/echo?fields=ip.country,client.name"`,
    },
    python: {
      lang: 'Python',
      code: `import requests

headers = {"X-API-Key": "esk_xxx"}
r = requests.get("${baseURL}/echo", headers=headers,
                 params={"format": "json"}, timeout=10)
print(r.json()["ip"]["country"])`,
    },
    node: {
      lang: 'Node.js',
      code: `const res = await fetch("${baseURL}/echo?format=json", {
  headers: { "X-API-Key": "esk_xxx" },
});
const data = await res.json();
console.log(data.client);`,
    },
    go: {
      lang: 'Go',
      code: `req, _ := http.NewRequest("GET", "${baseURL}/echo?format=json", nil)
req.Header.Set("X-API-Key", "esk_xxx")
resp, err := http.DefaultClient.Do(req)
if err != nil { log.Fatal(err) }
defer resp.Body.Close()`,
    },
  };

  return (
    <>
      <PageHeader
        title="访问控制"
        description="控制谁可以调用回显接口。控制台本身的账号体系始终生效，这里的开关只约束 /echo 等回显端点。"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>重新加载</Button>
            {canEdit && <Button type="primary" icon={<SaveOutlined />} onClick={save} loading={saving}>保存设置</Button>}
          </Space>
        }
      />

      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：Token 以 *** 显示，不能修改访问策略。" />}

      <Spin spinning={loading}>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={12} lg={6}>
            <Card className="stat-card">
              <Statistic
                title="回显鉴权"
                value={requireToken ? '已开启' : '未开启'}
                valueStyle={{ color: requireToken ? '#059669' : '#d97706', fontSize: 22 }}
              />
            </Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="启用中的命名 Key" value={enabledKeys.length} suffix={`/ ${keys.length}`} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card">
              <Statistic title="共享 Token 强度" value={strength.label} valueStyle={{ color: strength.color, fontSize: 22 }} />
            </Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="安全检查通过" value={passed} suffix={`/ ${activeChecks.length}`} /></Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]}>
          <Col xs={24} xl={15}>
            <Card title="回显接口鉴权">
              <div className="setting-tile" style={{ marginBottom: 18 }}>
                <div>
                  <div className="s-title">
                    <SafetyCertificateOutlined style={{ color: '#6366f1', marginRight: 8 }} />
                    要求调用方携带 Token
                  </div>
                  <div className="s-desc">
                    开启后，/echo 只接受控制台签发的 JWT、共享 API Token 或命名 API Key；关闭则任何能访问端口的人都可以调用。
                  </div>
                </div>
                <Switch
                  disabled={!canEdit}
                  checked={requireToken}
                  onChange={v => setCfg(prev => ({ ...prev, require_token: v ? 'true' : 'false' }))}
                />
              </div>

              <Paragraph style={{ marginBottom: 6 }} type="secondary">共享 API Token</Paragraph>
              <Space.Compact style={{ width: '100%', maxWidth: 640 }}>
                <Input.Password
                  disabled={!canEdit}
                  value={apiToken}
                  placeholder="未设置时无法通过 Token 放行，请先生成"
                  onChange={e => setCfg(prev => ({ ...prev, api_token: e.target.value }))}
                />
                {canEdit && (
                  <Button icon={<ThunderboltOutlined />} onClick={() => setCfg(prev => ({ ...prev, api_token: randomToken() }))}>
                    随机生成
                  </Button>
                )}
                {canEdit && tokenVisible && (
                  <Button icon={<CopyOutlined />} onClick={() => copy(apiToken)}>复制</Button>
                )}
              </Space.Compact>
              <Progress
                percent={strength.score}
                strokeColor={strength.color}
                size="small"
                style={{ maxWidth: 640, marginTop: 8 }}
                format={() => strength.label}
              />
              <p className="section-note">
                修改后立即生效；建议 32 位以上随机串。只读账号在配置接口中只会看到 <Text code>***</Text>。
              </p>

              {requireToken && !tokenVisible && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginTop: 6 }}
                  message="已开启鉴权但没有可用的共享 Token"
                  description="此时只有 JWT 或命名 API Key 能通过，匿名脚本调用会被拒绝。"
                />
              )}

              <Divider />

              <Row gutter={16}>
                <Col xs={24} md={12}>
                  <div className="setting-tile" style={{ display: 'block', height: '100%' }}>
                    <div>
                      <div className="s-title"><KeyOutlined style={{ marginRight: 6 }} />命名 API Key</div>
                      <div className="s-desc">按调用方分别签发、可设置 scope 与过期时间、可单独停用，适合 CI 与多租户场景。</div>
                      <Button size="small" style={{ marginTop: 8 }} onClick={() => { window.location.href = '/ui/security'; }}>前往密钥管理</Button>
                    </div>
                  </div>
                </Col>
                <Col xs={24} md={12}>
                  <div className="setting-tile" style={{ display: 'block', height: '100%' }}>
                    <div>
                      <div className="s-title"><ApiOutlined style={{ marginRight: 6 }} />JWT 登录态</div>
                      <div className="s-desc">控制台登录后自动携带，12 小时过期；账号禁用或删除后每次请求都会重新校验。</div>
                      <Tag color="blue" style={{ marginTop: 8 }}>Authorization: Bearer</Tag>
                    </div>
                  </div>
                </Col>
              </Row>
            </Card>

            <Card title="调用示例" style={{ marginTop: 16 }} styles={{ body: { paddingTop: 8 } }}>
              <Tabs
                activeKey={codeTab}
                onChange={setCodeTab}
                items={Object.entries(samples).map(([key, s]) => ({
                  key,
                  label: s.lang,
                  children: (
                    <>
                      <pre className="code-block" style={{ margin: 0 }}>{s.code}</pre>
                      <Button size="small" icon={<CopyOutlined />} style={{ marginTop: 10 }} onClick={() => copy(s.code)}>复制代码</Button>
                    </>
                  ),
                }))}
              />
            </Card>
          </Col>

          <Col xs={24} xl={9}>
            <Card title="鉴权方式对照">
              <Space direction="vertical" size={14} style={{ width: '100%' }}>
                <div>
                  <Tag color="blue">JWT</Tag>
                  <Paragraph type="secondary" style={{ margin: '6px 0 0' }}>
                    在控制台登录后获得，随 <Text code>Authorization: Bearer …</Text> 发送，12 小时后过期。
                  </Paragraph>
                </div>
                <div>
                  <Tag color="purple">Shared Token</Tag>
                  <Paragraph type="secondary" style={{ margin: '6px 0 0' }}>
                    单一长期凭据，适合脚本与内部集成；持有即拥有匿名回显权限。
                  </Paragraph>
                </div>
                <div>
                  <Tag color="gold">API Key</Tag>
                  <Paragraph type="secondary" style={{ margin: '6px 0 0' }}>
                    SHA-256 存储、明文只显示一次，scope 决定能否调用管理接口。
                  </Paragraph>
                </div>
                <div>
                  <Tag>匿名</Tag>
                  <Paragraph type="secondary" style={{ margin: '6px 0 0' }}>
                    仅在「要求 Token」关闭时可用；建议只在内网或调试期使用。
                  </Paragraph>
                </div>
              </Space>
            </Card>

            <Card title="安全检查" style={{ marginTop: 16 }}>
              {activeChecks.map(c => (
                <div className="provider-row" key={c.text}>
                  <Space size={8}>
                    {c.label ? <CheckCircleFilled style={{ color: '#12b76a' }} /> : <CloseCircleFilled style={{ color: '#f04438' }} />}
                    <span>{c.text}</span>
                  </Space>
                  <Tag color={c.label ? 'success' : 'error'}>{c.label ? '通过' : '待处理'}</Tag>
                </div>
              ))}
              <p className="section-note" style={{ marginBottom: 0 }}>
                回显接口会把来源 IP 与请求头暴露给调用方，公网部署务必叠加反向代理与限流。
              </p>
            </Card>

            <Card title="最近安全事件" style={{ marginTop: 16 }} styles={{ body: { padding: '6px 0' } }}>
              {events.length === 0 ? (
                <div className="empty-pad muted" style={{ textAlign: 'center' }}>暂无安全审计事件</div>
              ) : (
                events.map(e => (
                  <div className="provider-row" key={e.id} style={{ padding: '8px 16px' }}>
                    <div>
                      <div className="provider-name">{e.action}</div>
                      <div className="provider-meta">{e.username} · {fmtTime(e.ts)}</div>
                    </div>
                    <Tag color={e.action.includes('rotate') ? 'red' : 'blue'}>{e.ip || '—'}</Tag>
                  </div>
                ))
              )}
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={14}>
            <Card title="端点鉴权矩阵" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={AUTH_MATRIX}
                rowKey="endpoint"
                size="small"
                pagination={false}
                scroll={{ x: 620 }}
                columns={[
                  { title: '端点', dataIndex: 'endpoint', render: (v: string) => <span className="mono">{v}</span> },
                  { title: '匿名', dataIndex: 'anon', width: 150, render: (v: string) => <Text type="secondary">{v}</Text> },
                  { title: 'JWT', dataIndex: 'jwt', width: 90, render: (v: string) => <Tag color={v.startsWith('✗') ? 'default' : 'blue'}>{v}</Tag> },
                  { title: '共享 Token', dataIndex: 'shared', width: 100, render: (v: string) => <Tag color={v.startsWith('✓') ? 'purple' : 'default'}>{v}</Tag> },
                  { title: 'API Key', dataIndex: 'key', width: 110, render: (v: string) => <Tag color={v.startsWith('✓') || v === 'viewer/admin' ? 'gold' : 'default'}>{v}</Tag> },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={10}>
            <Card title="模块说明">
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="鉴权范围">仅回显流量；控制台登录不受开关影响</Descriptions.Item>
                <Descriptions.Item label="优先级">JWT &gt; 命名 API Key &gt; 共享 Token</Descriptions.Item>
                <Descriptions.Item label="失效方式">停用账号 / 删除 Key / 关闭 require_token</Descriptions.Item>
                <Descriptions.Item label="推荐组合">require_token + 命名 Key + 反向代理限流</Descriptions.Item>
                <Descriptions.Item label="风险提示">query token 会进入访问日志与浏览器历史</Descriptions.Item>
              </Descriptions>
              <Alert
                style={{ marginTop: 12 }}
                type="warning"
                showIcon
                icon={<WarningOutlined />}
                message="登录与初始化接口目前没有内置限流"
                description="公网部署请在反向代理层增加 IP 限流与失败次数限制。"
              />
            </Card>
          </Col>
        </Row>
      </Spin>
    </>
  );
};

export default Access;

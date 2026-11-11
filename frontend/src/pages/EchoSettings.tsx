import React, { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Form,
  message,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  CodeOutlined,
  CopyOutlined,
  DesktopOutlined,
  EnvironmentOutlined,
  FileTextOutlined,
  GatewayOutlined,
  ReloadOutlined,
  SaveOutlined,
  ScanOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Config, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const TOGGLES = [
  {
    key: 'show_ja3',
    icon: <ScanOutlined />,
    title: 'JA3 / JA3Hash',
    desc: '在 tls 与 client_hello 中返回 TLS 指纹链。',
    path: 'tls.ja3 / client_hello.ja3',
    payload: '~180 B',
  },
  {
    key: 'show_ip',
    icon: <EnvironmentOutlined />,
    title: 'IP 地理位置与分类',
    desc: '返回 ASN、经纬度、国家城市以及数据中心 / 住宅代理判定。',
    path: 'ip',
    payload: '~320 B',
  },
  {
    key: 'show_raw',
    icon: <CodeOutlined />,
    title: '原始 ClientHello',
    desc: '返回 base64 / hex 形式的原始握手字节，便于离线分析。',
    path: 'client_hello.raw_*',
    payload: '~2.2 KB',
  },
  {
    key: 'show_body',
    icon: <FileTextOutlined />,
    title: '请求 Body',
    desc: '回显请求体内容；关闭后可避免日志里出现敏感数据。',
    path: 'body / body_length',
    payload: '请求体大小',
  },
  {
    key: 'show_client',
    icon: <DesktopOutlined />,
    title: '客户端识别',
    desc: '基于 JA4 指纹库与 User-Agent 推断客户端家族，并标注伪造迹象。',
    path: 'client',
    payload: '~260 B',
  },
  {
    key: 'show_ja4h',
    icon: <GatewayOutlined />,
    title: 'JA4H HTTP 指纹',
    desc: '返回 HTTP 方法、版本、Cookie 与请求头组合形成的指纹。',
    path: 'ja4h',
    payload: '~54 B',
  },
];

const CONTROLS = [
  {
    control: '响应格式',
    query: 'format=json|text',
    header: 'X-Echo-Format',
    sample: '/echo?format=text',
    note: '未指定时使用下方默认格式',
  },
  {
    control: '字段裁剪',
    query: 'fields=ip.country,ip.city',
    header: 'X-Echo-Fields',
    sample: '/echo?fields=ip.country,ip.latitude',
    note: '父级路径返回整个对象，未知路径忽略',
  },
  {
    control: '共享 Token',
    query: 'token=<token>',
    header: 'X-API-Token',
    sample: '/echo?token=***',
    note: '仅在「访问控制」开启鉴权时生效',
  },
  {
    control: '命名 Key',
    query: '（不支持）',
    header: 'X-API-Key',
    sample: 'curl -H "X-API-Key: esk_…"',
    note: '推荐脚本使用，可单独停用',
  },
];

const PRESETS = [
  {
    name: '最小地理探测',
    desc: '只返回国家、城市与连接类型，适合批量探测',
    cmd: '/echo?format=text&fields=ip.country,ip.city,ip.connection_type',
  },
  {
    name: '爬虫身份核验',
    desc: '返回客户端推断、是否伪造与置信度',
    cmd: '/echo?fields=client.name,client.family,client.spoofed,client.confidence',
  },
  {
    name: 'TLS 指纹采集',
    desc: '返回 JA3/JA4 链与 ALPN，不含原始字节',
    cmd: '/echo?fields=client_hello.ja4,client_hello.ja4_r,client_hello.alpn,tls.ja3_hash',
  },
];

const EchoSettings: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [cfg, setCfg] = useState<Config>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewFormat, setPreviewFormat] = useState<'json' | 'text'>('json');

  const load = async () => {
    setLoading(true);
    try {
      setCfg(await getJSON<Config>('/api/config', token));
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const on = (key: string) => cfg[key] !== 'false';
  const enabledCount = TOGGLES.filter(t => on(t.key)).length;

  const preview = useMemo(() => {
    const payload: Record<string, unknown> = {
      timestamp: '2026-11-12T02:30:00Z',
      method: 'GET',
      scheme: 'https',
      host: 'echo.example.com',
      remote_addr: '203.0.113.42:51234',
      path: '/echo',
      http_version: 'HTTP/1.1',
      headers: { 'User-Agent': ['curl/8.5.0'], Accept: ['*/*'] },
    };
    if (on('show_body')) {
      payload.body = '';
      payload.body_length = 0;
    }
    if (on('show_ja3')) {
      payload.tls = {
        tls_version: 'TLSv1.3',
        cipher_suite: 'TLS_AES_128_GCM_SHA256',
        server_name: 'echo.example.com',
        alpn: 'h2',
        ja3_hash: 'b32309a26951912be7dba376398abc3b',
        ja4: 't13d3112h2_e8f1e7e78f70_b26ce05bbdd6',
      };
      payload.client_hello = {
        sni: 'echo.example.com',
        alpn: ['h2', 'http/1.1'],
        ja3: '771,4866-4867-4865,0-11-10,29-23,0',
        ja3_hash: 'b32309a26951912be7dba376398abc3b',
        ja4: 't13d3112h2_e8f1e7e78f70_b26ce05bbdd6',
        ...(on('show_raw') ? { raw_base64: 'FgMB…（省略）', raw_hex: '160301…（省略）' } : {}),
      };
    } else if (on('show_raw')) {
      payload.client_hello = { raw_base64: 'FgMB…（省略）', raw_hex: '160301…（省略）' };
    }
    if (on('show_client')) {
      payload.client = {
        name: 'curl', family: 'cli', version: '8.5.0', confidence: 0.95,
        signal: 'user_agent', source: 'user_agent', spoofed: false,
        matches: ['JA4 exact match', 'User-Agent: curl/8.5.0'],
      };
    }
    if (on('show_ja4h')) {
      payload.ja4h = 'ge11nn020000_e5a56608905c_000000000000_000000000000';
    }
    if (on('show_ip')) {
      payload.ip = {
        ip: '203.0.113.42', asn: 'AS64500', org: 'Example Hosting LLC',
        country: 'United States', country_code: 'US', city: 'San Jose',
        latitude: 37.3394, longitude: -121.895, connection_type: 'datacenter',
        geo_source: 'ipwhois',
      };
    }
    if (previewFormat === 'json') return JSON.stringify(payload, null, 2);
    const lines: string[] = [];
    const walk = (prefix: string, value: unknown) => {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.entries(value as Record<string, unknown>).forEach(([k, v]) => walk(prefix ? `${prefix}.${k}` : k, v));
      } else {
        lines.push(`${prefix}=${Array.isArray(value) ? JSON.stringify(value) : String(value)}`);
      }
    };
    walk('', payload);
    return lines.join('\n');
  }, [cfg, previewFormat]);

  const save = async () => {
    setSaving(true);
    try {
      const payload: Config = { default_format: cfg.default_format || 'json' };
      TOGGLES.forEach(t => {
        payload[t.key] = on(t.key) ? 'true' : 'false';
      });
      await postJSON('/api/config', token, payload);
      setCfg(prev => ({ ...prev, ...payload }));
      message.success('回显设置已保存');
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
      message.warning('浏览器不允许自动复制');
    }
  };

  return (
    <>
      <PageHeader
        title="回显设置"
        description="决定 /echo 默认返回哪些内容。单次请求仍可用 query / header 进一步收窄，但不能越过这里的开关。"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>重新加载</Button>
            {canEdit && <Button type="primary" icon={<SaveOutlined />} onClick={save} loading={saving}>保存设置</Button>}
          </Space>
        }
      />

      {!canEdit && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="当前账号为只读"
          description="可以查看所有配置，但修改会由服务端拒绝。"
        />
      )}

      <Spin spinning={loading}>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="已开启字段" value={enabledCount} suffix={`/ ${TOGGLES.length}`} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="默认格式" value={(cfg.default_format || 'json').toUpperCase()} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="原始字节暴露" value={on('show_raw') ? '开启' : '关闭'} valueStyle={{ color: on('show_raw') ? '#d97706' : '#059669', fontSize: 24 }} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="请求体回显" value={on('show_body') ? '开启' : '关闭'} valueStyle={{ color: on('show_body') ? '#2563eb' : '#059669', fontSize: 24 }} /></Card>
          </Col>
        </Row>

        <Card title="响应字段" styles={{ body: { padding: 16 } }}>
          <Row gutter={[12, 12]}>
            {TOGGLES.map(t => (
              <Col xs={24} md={12} xl={8} key={t.key}>
                <div className="setting-tile">
                  <div>
                    <div className="s-title">
                      <Space size={8}>
                        <span style={{ color: '#6366f1' }}>{t.icon}</span>
                        {t.title}
                      </Space>
                    </div>
                    <div className="s-desc">{t.desc}</div>
                  </div>
                  <Switch
                    disabled={!canEdit}
                    checked={on(t.key)}
                    onChange={v => setCfg(prev => ({ ...prev, [t.key]: v ? 'true' : 'false' }))}
                  />
                </div>
              </Col>
            ))}
          </Row>
        </Card>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={15}>
            <Card title="响应字段矩阵" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={TOGGLES}
                rowKey="key"
                size="middle"
                pagination={false}
                scroll={{ x: 640 }}
                columns={[
                  {
                    title: '字段组', dataIndex: 'title',
                    render: (v: string, r) => <Space size={8}><span style={{ color: '#6366f1' }}>{r.icon}</span><span style={{ fontWeight: 600 }}>{v}</span></Space>,
                  },
                  { title: '配置键', dataIndex: 'key', width: 130, render: (v: string) => <Text code>{v}</Text> },
                  { title: '响应路径', dataIndex: 'path', width: 230, render: (v: string) => <span className="mono muted">{v}</span> },
                  { title: '体积', dataIndex: 'payload', width: 96, render: (v: string) => <Tag>{v}</Tag> },
                  {
                    title: '状态', dataIndex: 'key', width: 90,
                    render: (v: string) => (on(v) ? <Tag color="success">返回</Tag> : <Tag>省略</Tag>),
                  },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={9}>
            <Card title="默认格式">
              <Form layout="vertical">
                <Form.Item label="未指定 format 时返回" style={{ marginBottom: 10 }}>
                  <Select
                    disabled={!canEdit}
                    value={cfg.default_format || 'json'}
                    onChange={v => setCfg(prev => ({ ...prev, default_format: v }))}
                    options={[
                      { value: 'json', label: 'JSON · 结构化，便于程序解析' },
                      { value: 'text', label: '纯文本 · key=value，体积更小' },
                    ]}
                  />
                </Form.Item>
              </Form>
              <Divider style={{ margin: '8px 0 12px' }} />
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Text type="secondary">text 模式按点路径平铺：</Text>
                <pre className="code-block" style={{ margin: 0 }}>{`ip.country=United States
ip.connection_type=datacenter
tls.ja3_hash=b32309a2…`}</pre>
                <Text type="secondary">数组与数字保持紧凑 JSON；字符串原样输出。</Text>
              </Space>
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={14}>
            <Card
              title="响应预览"
              extra={
                <Segmented
                  size="small"
                  value={previewFormat}
                  onChange={v => setPreviewFormat(v as 'json' | 'text')}
                  options={[{ value: 'json', label: 'JSON' }, { value: 'text', label: 'Text' }]}
                />
              }
            >
              <pre className="code-block" style={{ maxHeight: 360, margin: 0 }}>{preview}</pre>
              <p className="section-note">示例数据仅用于展示字段开关效果，实际响应会包含完整请求头与时间戳。</p>
            </Card>
          </Col>
          <Col xs={24} xl={10}>
            <Card title="单次请求控制">
              <Table
                dataSource={CONTROLS}
                rowKey="control"
                size="small"
                pagination={false}
                columns={[
                  { title: '控制', dataIndex: 'control', width: 92, render: (v: string) => <strong>{v}</strong> },
                  {
                    title: '方式',
                    render: (_: unknown, r) => (
                      <div>
                        <div className="mono" style={{ fontSize: 12 }}>{r.query}</div>
                        <div className="mono muted" style={{ fontSize: 11 }}>{r.header}</div>
                      </div>
                    ),
                  },
                ]}
              />
              <p className="section-note">解析优先级：query 参数 &gt; 请求头 &gt; 管理端默认值。字段开关在序列化前生效，请求只能收窄、不能放宽。</p>
            </Card>
          </Col>
        </Row>

        <Card title="常用请求组合" style={{ marginTop: 16 }}>
          <Row gutter={[16, 16]}>
            {PRESETS.map(p => (
              <Col xs={24} md={8} key={p.name}>
                <div className="setting-tile" style={{ display: 'block' }}>
                  <div>
                    <div className="s-title"><ThunderboltOutlined style={{ color: '#6366f1', marginRight: 6 }} />{p.name}</div>
                    <div className="s-desc">{p.desc}</div>
                    <pre className="code-block" style={{ margin: '10px 0 0', whiteSpace: 'pre-wrap' }}>{p.cmd}</pre>
                    <Button size="small" icon={<CopyOutlined />} style={{ marginTop: 8 }} onClick={() => copy(`${window.location.origin}${p.cmd}`)}>
                      复制完整 URL
                    </Button>
                  </div>
                </div>
              </Col>
            ))}
          </Row>
          <Paragraph type="secondary" style={{ margin: '14px 0 0' }}>
            字段裁剪不会改变服务端采集行为：TLS 指纹与 IP 情报仍会计算，只是不写进响应，便于同一实例同时服务“全量分析”和“低带宽探测”两类调用方。
          </Paragraph>
        </Card>
      </Spin>
    </>
  );
};

export default EchoSettings;

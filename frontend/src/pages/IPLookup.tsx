import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Empty,
  Input,
  Row,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import {
  CompassOutlined,
  CopyOutlined,
  EnvironmentOutlined,
  GlobalOutlined,
  HistoryOutlined,
  SearchOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { errorText, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

interface IPInfo {
  ip: string;
  asn?: string;
  asn_name?: string;
  org?: string;
  isp?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  postal?: string;
  timezone?: string;
  utc_offset?: string;
  continent?: string;
  latitude?: number;
  longitude?: number;
  connection_type?: string;
  is_proxy?: boolean;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_hosting?: boolean;
  anycast?: boolean;
  geo_source?: string;
}

interface LookupResult {
  input: string;
  valid: boolean;
  error?: string;
  cached: boolean;
  // the Go struct embeds IPInfo, so its fields appear at the top level
  ip?: string;
  asn?: string;
  asn_name?: string;
  org?: string;
  isp?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  postal?: string;
  timezone?: string;
  utc_offset?: string;
  continent?: string;
  latitude?: number;
  longitude?: number;
  connection_type?: string;
  is_proxy?: boolean;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_hosting?: boolean;
  anycast?: boolean;
  geo_source?: string;
  [key: string]: unknown;
}

interface BatchResponse {
  count: number;
  answered: number;
  results: LookupResult[];
}

interface HistoryRow {
  ts: string;
  method: string;
  path: string;
  ip: string;
  connection_type: string;
  country: string;
}

const SAMPLE = `8.8.8.8
1.1.1.1
104.131.0.1`;

const CONN_META: Record<string, { color: string; label: string }> = {
  datacenter: { color: 'geekblue', label: '数据中心 / 云' },
  residential_proxy: { color: 'volcano', label: '住宅代理 / VPN' },
  unknown: { color: 'default', label: '未知' },
};

const splitIPs = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map(v => v.trim())
    .filter(Boolean);

const Copyable: React.FC<{ value?: string | number }> = ({ value }) => {
  if (value === undefined || value === null || value === '') return <Text type="secondary">—</Text>;
  return (
    <Space size={4}>
      <Text className="mono" copyable={{ text: String(value), icon: <CopyOutlined /> }}>
        {String(value)}
      </Text>
    </Space>
  );
};

const flag = (v?: boolean, yes = '是') =>
  v === undefined ? <Text type="secondary">—</Text> : v ? <Tag color="red">{yes}</Tag> : <Tag>否</Tag>;

const IPLookup: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  // Deep link from the log drawer: /lookup?ip=1.2.3.4
  const initialIP = useMemo(() => {
    const v = new URLSearchParams(window.location.search).get('ip');
    return v ? v.trim() : '';
  }, []);
  const [input, setInput] = useState(initialIP || '8.8.8.8');
  const [noCache, setNoCache] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [batch, setBatch] = useState<BatchResponse | null>(null);
  const [error, setError] = useState('');
  const [history, setHistory] = useState<HistoryRow[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const targets = useMemo(() => splitIPs(input), [input]);
  const isBatch = targets.length > 1;

  const run = async () => {
    if (!targets.length) {
      message.warning('请输入至少一个 IP 地址');
      return;
    }
    setLoading(true);
    setError('');
    setHistory(null);
    setHistoryOpen(false);
    try {
      if (isBatch) {
        const res = await postJSON<BatchResponse>('/api/ip/lookup', token, { ips: targets, nocache: noCache });
        setBatch(res);
        setResult(null);
      } else {
        const q = `/api/ip/lookup?ip=${encodeURIComponent(targets[0])}${noCache ? '&nocache=1' : ''}`;
        const res = await getJSON<LookupResult>(q, token);
        setResult(res);
        setBatch(null);
      }
    } catch (err) {
      setError(errorText(err));
      setResult(null);
      setBatch(null);
    } finally {
      setLoading(false);
    }
  };

  // A deep link with ?ip= runs as soon as the page is usable.
  useEffect(() => {
    if (!initialIP || !token) return;
    setInput(initialIP);
    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const loadHistory = async (ip: string) => {
    setHistoryLoading(true);
    setHistoryOpen(true);
    try {
      const res = await getJSON<{ ip: string; count: number; rows: HistoryRow[] }>(
        `/api/ip/history?ip=${encodeURIComponent(ip)}&limit=50`,
        token,
      );
      setHistory(res.rows || []);
    } catch (err) {
      fail(err);
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const active: IPInfo | null = result && result.valid ? (result as unknown as IPInfo) : null;
  const conn = active?.connection_type ? CONN_META[active.connection_type] || { color: 'default', label: active.connection_type } : null;
  const hasCoords = !!active && typeof active.latitude === 'number' && typeof active.longitude === 'number';

  return (
    <>
      <PageHeader
        title="IP 定位查询"
        description="直接指定 IP 查询地理位置、ASN 与连接类型，不依赖调用方自身的来源地址。支持单条、批量（最多 100 个）与历史回溯。"
        extra={
          <Space>
            <Switch checkedChildren="绕过缓存" unCheckedChildren="用缓存" checked={noCache} onChange={setNoCache} />
            <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={run}>
              {isBatch ? `查询 ${targets.length} 个` : '查询'}
            </Button>
          </Space>
        }
      />

      {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message="查询失败" description={error} />}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card
            title={<span><EnvironmentOutlined style={{ color: '#6366f1', marginRight: 8 }} />输入 IP</span>}
            extra={<Button size="small" type="link" onClick={() => setInput(SAMPLE)}>填入示例</Button>}
          >
            <Input.TextArea
              rows={6}
              value={input}
              onChange={e => setInput(e.target.value)}
              onPressEnter={e => {
                if (!e.shiftKey) {
                  e.preventDefault();
                  run();
                }
              }}
              placeholder="每行一个，或用逗号分隔：8.8.8.8, 1.1.1.1"
              style={{ fontFamily: 'SFMono-Regular, Consolas, monospace' }}
            />
            <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Text type="secondary">
                {targets.length ? `已识别 ${targets.length} 个地址` : '等待输入'}
                {targets.length > 1 ? ' · 批量模式' : ''}
              </Text>
              <Space>
                <Button icon={<CompassOutlined />} onClick={() => setInput('')}>清空</Button>
                <Button type="primary" icon={<ThunderboltOutlined />} loading={loading} onClick={run}>查询</Button>
              </Space>
            </div>
            <Divider />
            <Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
              命令行同样可用：<Text code>GET /api/ip/lookup?ip=8.8.8.8</Text>，批量用
              <Text code>POST /api/ip/lookup</Text> 传 <Text code>{'{"ips":[...]}'}</Text>。
              在线查询需在「IP 情报」页启用；关闭时仅返回本地 CIDR 判定。
            </Paragraph>
          </Card>

          <Card title="查询统计" style={{ marginTop: 16 }}>
            <Row gutter={12}>
              <Col span={8}><Statistic title="本次地址" value={targets.length} /></Col>
              <Col span={8}>
                <Statistic
                  title="已应答"
                  value={batch ? batch.answered : (active && active.geo_source && active.geo_source !== 'local') ? 1 : result ? 0 : 0}
                  suffix={isBatch && batch ? ` / ${batch.count}` : ''}
                />
              </Col>
              <Col span={8}>
                <Statistic title="缓存" value={result?.cached ? '命中' : noCache ? '绕过' : '未命中'} valueStyle={{ fontSize: 18 }} />
              </Col>
            </Row>
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          {isBatch ? (
            <Card title="批量结果" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={(batch?.results || []).map((r, i) => ({ ...r, key: i }))}
                rowKey="key"
                size="small"
                pagination={(batch?.results?.length || 0) > 12 ? { pageSize: 12, showSizeChanger: false } : false}
                locale={{ emptyText: loading ? '查询中…' : '输入多个地址后点击查询' }}
                scroll={{ x: 760 }}
                columns={[
                  {
                    title: '输入',
                    dataIndex: 'input',
                    width: 150,
                    render: (v: string) => <span className="mono">{v}</span>,
                  },
                  {
                    title: '国家 / 地区',
                    width: 170,
                    render: (_: unknown, r: LookupResult) =>
                      r.country ? (
                        <span>
                          {r.country_code && <Tag color="blue">{r.country_code}</Tag>}
                          {r.country}
                        </span>
                      ) : <Text type="secondary">—</Text>,
                  },
                  {
                    title: '省 / 城市',
                    width: 160,
                    render: (_: unknown, r: LookupResult) => (
                      <span>{[r.region, r.city].filter(Boolean).join(' / ') || <Text type="secondary">—</Text>}</span>
                    ),
                  },
                  { title: 'ASN', width: 110, render: (_: unknown, r: LookupResult) => <span className="mono">{r.asn || '—'}</span> },
                  {
                    title: '连接类型',
                    width: 120,
                    render: (_: unknown, r: LookupResult) => {
                      const m = CONN_META[r.connection_type || 'unknown'] || { color: 'default', label: r.connection_type };
                      return <Tag color={m.color}>{m.label}</Tag>;
                    },
                  },
                  {
                    title: '来源 / 说明',
                    render: (_: unknown, r: LookupResult) => (
                      <Space direction="vertical" size={0}>
                        <Text className="mono" style={{ fontSize: 11 }}>{r.geo_source || '—'}</Text>
                        {r.error && <Text type="secondary" style={{ fontSize: 11 }}>{r.error}</Text>}
                      </Space>
                    ),
                  },
                ]}
              />
            </Card>
          ) : active ? (
            <Card
              title={<span><GlobalOutlined style={{ color: '#6366f1', marginRight: 8 }} />{active.ip}</span>}
              extra={
                <Space>
                  {result?.cached && <Tag color="cyan">缓存命中</Tag>}
                  {conn && <Tag color={conn.color}>{conn.label}</Tag>}
                  {active.geo_source && <Tag>来源 {active.geo_source}</Tag>}
                  <Button size="small" icon={<HistoryOutlined />} onClick={() => loadHistory(active.ip)}>历史</Button>
                </Space>
              }
            >
              {result?.error && (
                <Alert
                  type={result.error.includes('disabled') ? 'warning' : 'info'}
                  showIcon
                  style={{ marginBottom: 16 }}
                  message={result.error}
                  description="结果来自本地 CIDR 表与组织名启发式；如需完整地理信息请启用在线查询。"
                />
              )}
              {active.anycast && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 16 }}
                  message="Anycast 地址"
                  description="该地址被多家边缘节点共享，城市与坐标没有定位意义，只应参考国家与 ASN。"
                />
              )}

              <Descriptions column={{ xs: 1, sm: 2 }} size="small" bordered>
                <Descriptions.Item label="IP"><Copyable value={active.ip} /></Descriptions.Item>
                <Descriptions.Item label="ASN / 组织"><Copyable value={[active.asn, active.org].filter(Boolean).join(' · ')} /></Descriptions.Item>
                <Descriptions.Item label="运营商">{active.isp || '—'}</Descriptions.Item>
                <Descriptions.Item label="ASN 名称">{active.asn_name || '—'}</Descriptions.Item>
                <Descriptions.Item label="国家">
                  {active.country ? (
                    <span>{active.country_code && <Tag color="blue">{active.country_code}</Tag>}{active.country}</span>
                  ) : '—'}
                </Descriptions.Item>
                <Descriptions.Item label="大洲">{active.continent || '—'}</Descriptions.Item>
                <Descriptions.Item label="省 / 州">{active.region || '—'}</Descriptions.Item>
                <Descriptions.Item label="城市">{active.city || '—'}</Descriptions.Item>
                <Descriptions.Item label="邮编">{active.postal || '—'}</Descriptions.Item>
                <Descriptions.Item label="时区">
                  {[active.timezone, active.utc_offset].filter(Boolean).join(' · ') || '—'}
                </Descriptions.Item>
                <Descriptions.Item label="坐标">
                  {hasCoords ? (
                    <Space size={6} wrap>
                      <Text className="mono">{active.latitude?.toFixed(4)}, {active.longitude?.toFixed(4)}</Text>
                      <Button
                        size="small"
                        type="link"
                        style={{ paddingInline: 4 }}
                        onClick={() =>
                          window.open(
                            `https://www.openstreetmap.org/?mlat=${active.latitude}&mlon=${active.longitude}#map=12/${active.latitude}/${active.longitude}`,
                            '_blank',
                            'noopener,noreferrer',
                          )
                        }
                      >
                        地图
                      </Button>
                    </Space>
                  ) : <Text type="secondary">—</Text>}
                </Descriptions.Item>
                <Descriptions.Item label="连接类型">
                  {conn ? <Tag color={conn.color}>{conn.label}</Tag> : '—'}
                </Descriptions.Item>
                <Descriptions.Item label="隐私标签">
                  <Space size={4} wrap>
                    <Tooltip title="代理">{flag(active.is_proxy, '代理')}</Tooltip>
                    <Tooltip title="VPN">{flag(active.is_vpn, 'VPN')}</Tooltip>
                    <Tooltip title="Tor">{flag(active.is_tor, 'Tor')}</Tooltip>
                    <Tooltip title="托管机房">{flag(active.is_hosting, '机房')}</Tooltip>
                  </Space>
                </Descriptions.Item>
                <Descriptions.Item label="Anycast">{flag(active.anycast, '是')}</Descriptions.Item>
              </Descriptions>

              {hasCoords && !active.anycast && (
                <div style={{ marginTop: 16 }}>
                  <iframe
                    title={`OSM ${active.ip}`}
                    width="100%"
                    height={260}
                    loading="lazy"
                    style={{ border: '1px solid #eef2f7', borderRadius: 12 }}
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${active.longitude! - 0.15}%2C${active.latitude! - 0.1}%2C${active.longitude! + 0.15}%2C${active.latitude! + 0.1}&layer=mapnik&marker=${active.latitude}%2C${active.longitude}`}
                  />
                  <p className="section-note" style={{ marginBottom: 0 }}>
                    地图位置是城市级近似坐标，不代表街道级位置；Anycast、VPN、移动网关地址尤其不准确。
                  </p>
                </div>
              )}
            </Card>
          ) : result ? (
            <Card>
              <Empty description={result.error || '没有拿到可用结果'}>
                <Space>
                  <Button onClick={() => { setNoCache(true); run(); }}>绕过缓存重试</Button>
                  <Button type="primary" onClick={run}>再次查询</Button>
                </Space>
              </Empty>
            </Card>
          ) : (
            <Card>
              <Empty description={loading ? '查询中…' : '输入一个 IP 后点击查询'}>
                <p className="section-note" style={{ marginBottom: 0 }}>
                  常用地址：8.8.8.8（Google DNS）、1.1.1.1（Cloudflare）、104.131.0.1（DigitalOcean）。
                </p>
              </Empty>
            </Card>
          )}

          {historyOpen && (
            <Card
              title={<span><HistoryOutlined style={{ color: '#6366f1', marginRight: 8 }} />该 IP 的回显请求历史</span>}
              style={{ marginTop: 16 }}
              extra={<Text type="secondary" style={{ fontSize: 12 }}>来自查询日志，最多 50 条</Text>}
              styles={{ body: { padding: 0 } }}
            >
              <Table
                dataSource={(history || []).map((r, i) => ({ ...r, key: i }))}
                rowKey="key"
                size="small"
                loading={historyLoading}
                pagination={(history?.length || 0) > 10 ? { pageSize: 10, showSizeChanger: false } : false}
                locale={{ emptyText: '该 IP 没有回显记录' }}
                columns={[
                  { title: '时间', dataIndex: 'ts', width: 190, render: (v: string) => <Text type="secondary">{v}</Text> },
                  { title: '方法', dataIndex: 'method', width: 80 },
                  { title: '路径', dataIndex: 'path', render: (v: string) => <span className="mono">{v}</span> },
                  { title: '连接类型', dataIndex: 'connection_type', width: 130 },
                  { title: '国家', dataIndex: 'country', width: 100 },
                ]}
              />
            </Card>
          )}
        </Col>
      </Row>
    </>
  );
};

export default IPLookup;

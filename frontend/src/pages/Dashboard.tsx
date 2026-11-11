import React, { useEffect, useState } from 'react';
import { Button, Card, Col, Empty, Row, Space, Spin, Table, Tag, Typography } from 'antd';
import {
  ApiOutlined,
  ArrowRightOutlined,
  AuditOutlined,
  BellOutlined,
  CheckCircleFilled,
  ClockCircleOutlined,
  CloudServerOutlined,
  DatabaseOutlined,
  GlobalOutlined,
  HistoryOutlined,
  LineChartOutlined,
  PartitionOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ScanOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  ToolOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import {
  Dataset,
  IPProvider,
  MetricsSummary,
  NotificationItem,
  QueryLog,
  Stats,
  fmtTime,
  getJSON,
  shortTime,
} from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';
import MiniChart from '../components/MiniChart';

const { Text } = Typography;

const statusTag = (status: string, enabled = true) => {
  if (!enabled) return <Tag>已禁用</Tag>;
  if (status === 'ok') return <Tag color="success">正常</Tag>;
  if (status === 'error') return <Tag color="error">异常</Tag>;
  if (status === 'empty') return <Tag color="warning">无数据</Tag>;
  return <Tag color="processing">待同步</Tag>;
};

const Dashboard: React.FC = () => {
  const { token, me, canEdit } = useSession();
  const fail = useApiError();
  const navigate = useNavigate();
  const [stats, setStats] = useState<Stats | null>(null);
  const [logs, setLogs] = useState<QueryLog[]>([]);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [chain, setChain] = useState<IPProvider[]>([]);
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [notices, setNotices] = useState<NotificationItem[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [s, l, d, p, m, n] = await Promise.all([
        getJSON<Stats>('/api/stats', token),
        getJSON<QueryLog[]>('/api/logs?limit=8', token),
        getJSON<Dataset[]>('/api/datasets', token),
        getJSON<IPProvider[]>('/api/ipproviders', token),
        getJSON<MetricsSummary>('/api/metrics/summary?hours=24', token).catch(() => null),
        getJSON<{ items: NotificationItem[]; unread: number }>('/api/notifications?limit=4', token).catch(() => ({ items: [], unread: 0 })),
      ]);
      setStats(s);
      setLogs(l || []);
      setDatasets(d || []);
      setChain(p || []);
      setMetrics(m);
      setNotices(n.items || []);
      setUnread(n.unread || 0);
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

  const providers = datasets.flatMap(d => d.providers || []);
  const enabledProviders = providers.filter(p => p.enabled);
  const healthyProviders = enabledProviders.filter(p => p.status === 'ok');
  const activeChain = chain.filter(p => p.enabled);

  const quick = [
    {
      icon: <ApiOutlined />,
      title: '回显设置',
      desc: '调整字段暴露与默认响应格式',
      path: '/echo',
    },
    {
      icon: <GlobalOutlined />,
      title: 'IP 情报',
      desc: '在线数据源、Token 与缓存策略',
      path: '/ip',
    },
    {
      icon: <PartitionOutlined />,
      title: '查询链路',
      desc: '串联云端 API 与本地命令',
      path: '/chain',
    },
    canEdit
      ? { icon: <TeamOutlined />, title: '用户管理', desc: '账号、角色与注册策略', path: '/users' }
      : { icon: <HistoryOutlined />, title: '查询日志', desc: '查看最近的请求记录', path: '/logs' },
    { icon: <LineChartOutlined />, title: '监控分析', desc: '趋势、来源分布与系统资源', path: '/monitor' },
    { icon: <ScanOutlined />, title: 'JA4 指纹', desc: '按指纹或客户端检索', path: '/fingerprints' },
    { icon: <SafetyCertificateOutlined />, title: '安全与防护', desc: 'API Key、IP 规则与维护模式', path: '/security' },
    { icon: <ToolOutlined />, title: '工具箱', desc: 'CIDR、哈希、JWT 与 curl', path: '/tools' },
    { icon: <AuditOutlined />, title: '审计日志', desc: '谁在什么时候改了什么', path: '/audit' },
    { icon: <BellOutlined />, title: '通知中心', desc: '配置变更与投递异常', path: '/notifications' },
  ];

  return (
    <>
      <PageHeader
        title={`你好，${me.username}`}
        description="指纹、地理信息与数据源状态一目了然。"
        extra={
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
            刷新
          </Button>
        }
      />

      <Row gutter={[16, 16]}>
        <Col xs={12} sm={12} xl={6}>
          <Card className="stat-card">
            <div className="stat-top">
              <div>
                <div className="stat-label">今日请求</div>
                <div className="stat-value">{stats ? stats.queries_today.toLocaleString() : '—'}</div>
              </div>
              <div className="stat-icon sky"><ThunderboltOutlined /></div>
            </div>
            <div className="stat-foot">按 UTC 自然日统计</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} xl={6}>
          <Card className="stat-card">
            <div className="stat-top">
              <div>
                <div className="stat-label">累计请求</div>
                <div className="stat-value">{stats ? stats.queries_total.toLocaleString() : '—'}</div>
              </div>
              <div className="stat-icon"><HistoryOutlined /></div>
            </div>
            <div className="stat-foot">SQLite 中保存的查询记录</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} xl={6}>
          <Card className="stat-card">
            <div className="stat-top">
              <div>
                <div className="stat-label">账号数</div>
                <div className="stat-value">{stats ? stats.users.toLocaleString() : '—'}</div>
              </div>
              <div className="stat-icon green"><TeamOutlined /></div>
            </div>
            <div className="stat-foot">{canEdit ? '管理账号与自注册策略' : '只读账号'}</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} xl={6}>
          <Card className="stat-card">
            <div className="stat-top">
              <div>
                <div className="stat-label">IP 查询链路</div>
                <div className="stat-value">
                  {activeChain.length ? activeChain.filter(p => p.status === 'ok').length : '—'}
                  <span style={{ fontSize: 16, color: '#94a3b8', fontWeight: 500 }}>
                    {activeChain.length ? ` / ${activeChain.length}` : ''}
                  </span>
                </div>
              </div>
              <div className="stat-icon amber"><PartitionOutlined /></div>
            </div>
            <div className="stat-foot">正常 / 已启用 Provider</div>
          </Card>
        </Col>
      </Row>

      <Card style={{ marginTop: 16 }} styles={{ body: { padding: 18 } }}>
        <div className="quick-grid">
          {quick.map(item => (
            <div className="quick-tile" key={item.path} onClick={() => navigate(item.path)}>
              <div className="q-icon">{item.icon}</div>
              <div className="q-title">{item.title}</div>
              <div className="q-desc">{item.desc}</div>
            </div>
          ))}
        </div>
      </Card>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={15}>
          <Card
            title="24 小时请求趋势"
            extra={
              <Button type="link" size="small" onClick={() => navigate('/monitor')}>
                监控分析 <ArrowRightOutlined />
              </Button>
            }
          >
            {metrics?.by_hour?.length ? (
              <MiniChart
                data={metrics.by_hour.map(p => ({ label: p.hour.slice(11, 16), value: p.count }))}
                height={170}
              />
            ) : (
              <div className="empty-pad"><Empty description="暂无趋势数据" /></div>
            )}
            <Space size={12} wrap style={{ marginTop: 8 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>24 小时 {metrics?.total?.toLocaleString() || 0} 次请求</Text>
              <Text type="secondary" style={{ fontSize: 12 }}>独立 IP {metrics?.unique_ips?.toLocaleString() || 0}</Text>
              <Text type="secondary" style={{ fontSize: 12 }}>Top 来源 {metrics?.top_ips?.[0]?.label || '—'}</Text>
            </Space>
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card
            title={<Space><BellOutlined /> 最新通知 {unread > 0 && <Tag color="red">{unread} 未读</Tag>}</Space>}
            extra={<Button type="link" size="small" onClick={() => navigate('/notifications')}>全部</Button>}
          >
            {notices.length === 0 ? (
              <div className="empty-pad"><Empty description="暂无通知" /></div>
            ) : (
              notices.map(n => (
                <div className="provider-row" key={n.id}>
                  <div style={{ minWidth: 0 }}>
                    <div className="provider-name" style={{ display: 'block' }}>
                      <Tag color={n.level === 'warning' ? 'orange' : n.level === 'error' ? 'red' : 'blue'}>{n.level}</Tag>
                      <span>{n.title}</span>
                    </div>
                    <div className="provider-meta">{shortTime(n.ts)} · {n.source}</div>
                  </div>
                  {!n.read && <span className="status-dot" />}
                </div>
              ))
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={15}>
          <Card
            title="最近请求"
            extra={
              <Button type="link" size="small" onClick={() => navigate('/logs')}>
                查看全部 <ArrowRightOutlined />
              </Button>
            }
            styles={{ body: { padding: 0 } }}
          >
            {loading ? (
              <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>
            ) : logs.length === 0 ? (
              <div className="empty-pad"><Empty description="还没有请求记录" /></div>
            ) : (
              <Table
                dataSource={logs}
                rowKey={r => `${r.ts}-${r.ip}-${r.path}`}
                pagination={false}
                size="small"
                columns={[
                  {
                    title: '时间',
                    dataIndex: 'ts',
                    width: 100,
                    render: (v: string) => (
                      <Text type="secondary" style={{ whiteSpace: 'nowrap' }}>{shortTime(v)}</Text>
                    ),
                  },
                  {
                    title: '请求',
                    dataIndex: 'path',
                    render: (_: string, r) => (
                      <Space size={8}>
                        <Tag color={r.method === 'GET' ? 'blue' : 'purple'}>{r.method}</Tag>
                        <span className="mono">{r.path}</span>
                      </Space>
                    ),
                  },
                  { title: '来源 IP', dataIndex: 'ip', width: 140, render: (v: string) => <span className="mono">{v}</span> },
                  {
                    title: '类型',
                    dataIndex: 'connection_type',
                    width: 130,
                    responsive: ['sm'],
                    render: (v: string) => <Tag color={v === 'datacenter' ? 'orange' : v === 'residential_proxy' ? 'green' : 'default'}>{v || 'unknown'}</Tag>,
                  },
                ]}
              />
            )}
          </Card>
        </Col>

        <Col xs={24} xl={9}>
          <Card
            title="服务组件"
            extra={<Tag color={healthyProviders.length === enabledProviders.length ? 'success' : 'warning'}>{healthyProviders.length}/{enabledProviders.length} 正常</Tag>}
          >
            <Text strong>数据源</Text>
            <div style={{ marginTop: 6 }}>
              {providers.length === 0 ? (
                <Text type="secondary">暂无 Provider</Text>
              ) : (
                providers.slice(0, 5).map(p => (
                  <div className="provider-row" key={`${p.name}-${p.source || ''}`}>
                    <div>
                      <div className="provider-name">
                        {p.name}
                        {p.builtin && <Tag style={{ marginInlineEnd: 0 }}>内置</Tag>}
                      </div>
                      <div className="provider-meta">{p.entries.toLocaleString()} 条 · 优先级 {p.priority}</div>
                    </div>
                    {statusTag(p.status, p.enabled)}
                  </div>
                ))
              )}
            </div>

            <div style={{ height: 1, background: '#eef2f7', margin: '16px 0' }} />

            <Text strong>IP 查询链路</Text>
            <div style={{ marginTop: 6 }}>
              {chain.length === 0 ? (
                <Text type="secondary">暂无 Provider</Text>
              ) : (
                chain.slice(0, 5).map(p => (
                  <div className="provider-row" key={p.name}>
                    <div>
                      <div className="provider-name">
                        {p.name}
                        {p.builtin && <Tag style={{ marginInlineEnd: 0 }}>内置</Tag>}
                      </div>
                      <div className="provider-meta">
                        {p.calls} 次调用 · 成功率 {p.calls ? Math.round((p.successes / p.calls) * 100) : 0}%
                      </div>
                    </div>
                    {p.gated ? <Tag color="purple">已拦截</Tag> : statusTag(p.status, p.enabled)}
                  </div>
                ))
              )}
            </div>
          </Card>
        </Col>
      </Row>

      <Text type="secondary" style={{ display: 'block', marginTop: 16, fontSize: 12 }}>
        <CloudServerOutlined /> 控制台通过 HTTP 与 HTTPS 同时提供；TLS 指纹捕获仅在 HTTPS 连接上可用。
        {' '}最近刷新：{fmtTime(new Date().toISOString())}
      </Text>
    </>
  );
};

export default Dashboard;

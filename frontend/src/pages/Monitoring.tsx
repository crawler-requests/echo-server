import React, { useEffect, useMemo, useState } from 'react';
import { Button, Card, Col, Empty, Progress, Row, Segmented, Space, Spin, Statistic, Table, Tag, Typography } from 'antd';
import {
  ApiOutlined,
  CloudServerOutlined,
  DatabaseOutlined,
  GlobalOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Bucket, Dataset, IPProvider, MetricsSummary, SystemInfo, fmtBytes, fmtDuration, getJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';
import MiniChart from '../components/MiniChart';

const { Text } = Typography;

const CONN_LABEL: Record<string, string> = {
  datacenter: '数据中心',
  residential_proxy: '住宅代理',
  unknown: '未知',
};

const BucketList: React.FC<{ data: Bucket[]; empty: string; color?: string }> = ({ data, empty, color = '#5b5bd6' }) => {
  if (!data.length) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} />;
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <Space direction="vertical" size={10} style={{ width: '100%' }}>
      {data.map(d => (
        <div key={d.label}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12 }}>
            <Text ellipsis style={{ maxWidth: 220 }} className={d.label.includes('.') || d.label.includes(':') ? 'mono' : undefined}>{d.label}</Text>
            <Text type="secondary">{d.count.toLocaleString()}</Text>
          </div>
          <Progress percent={Math.round((d.count / max) * 100)} showInfo={false} size="small" strokeColor={color} />
        </div>
      ))}
    </Space>
  );
};

const Monitoring: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<MetricsSummary | null>(null);
  const [sys, setSys] = useState<SystemInfo | null>(null);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [chain, setChain] = useState<IPProvider[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async (h = hours) => {
    setLoading(true);
    try {
      const [m, s, d, p] = await Promise.all([
        getJSON<MetricsSummary>(`/api/metrics/summary?hours=${h}`, token),
        getJSON<SystemInfo>('/api/system', token),
        getJSON<Dataset[]>('/api/datasets', token),
        getJSON<IPProvider[]>('/api/ipproviders', token),
      ]);
      setSummary(m);
      setSys(s);
      setDatasets(d || []);
      setChain(p || []);
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

  const chart = useMemo(
    () =>
      (summary?.by_hour || []).map(p => ({
        label: p.hour.slice(11, 16),
        value: p.count,
      })),
    [summary],
  );

  const providers = datasets.flatMap(d => (d.providers || []).map(p => ({ ...p, dataset: d.name })));
  const enabled = providers.filter(p => p.enabled);
  const healthy = enabled.filter(p => p.status === 'ok');
  const unhealthy = enabled.filter(p => p.status !== 'ok');
  const avgPerHour = summary && summary.hours ? Math.round((summary.total / summary.hours) * 10) / 10 : 0;
  const peak = chart.reduce((m, p) => Math.max(m, p.value), 0);
  const successRate = (() => {
    const calls = chain.reduce((n, p) => n + p.calls, 0);
    const ok = chain.reduce((n, p) => n + p.successes, 0);
    return calls ? Math.round((ok / calls) * 1000) / 10 : 100;
  })();

  return (
    <>
      <PageHeader
        title="监控分析"
        description="请求趋势、来源分布、系统资源与数据源健康度的统一视图。"
        extra={
          <Space>
            <Segmented
              value={hours}
              onChange={v => {
                const h = Number(v);
                setHours(h);
                load(h);
              }}
              options={[
                { value: 6, label: '6 小时' },
                { value: 24, label: '24 小时' },
                { value: 168, label: '7 天' },
              ]}
            />
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
          </Space>
        }
      />

      <Spin spinning={loading}>
        <Row gutter={[16, 16]}>
          <Col xs={12} xl={6}>
            <Card className="stat-card"><Statistic title={<Space size={6}><ThunderboltOutlined /> 区间请求</Space>} value={summary?.total || 0} /></Card>
          </Col>
          <Col xs={12} xl={6}>
            <Card className="stat-card"><Statistic title={<Space size={6}><GlobalOutlined /> 独立来源 IP</Space>} value={summary?.unique_ips || 0} /></Card>
          </Col>
          <Col xs={12} xl={6}>
            <Card className="stat-card"><Statistic title="平均每小时" value={avgPerHour} suffix={<Text type="secondary" style={{ fontSize: 12 }}>次</Text>} /></Card>
          </Col>
          <Col xs={12} xl={6}>
            <Card className="stat-card">
              <Statistic
                title={<Space size={6}><ApiOutlined /> IP 链路成功率</Space>}
                value={successRate}
                suffix="%"
                valueStyle={{ color: successRate >= 90 ? '#059669' : '#d97706' }}
              />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={16}>
            <Card title="请求趋势" extra={<Tag color="blue">峰值 {peak.toLocaleString()} 次 / 小时</Tag>}>
              {chart.length ? <MiniChart data={chart} /> : <Empty description="暂无趋势数据" />}
              <p className="section-note">按 UTC 小时聚合，数据来自 SQLite 的 query_log。可在日志页导出原始记录。</p>
            </Card>
          </Col>
          <Col xs={24} xl={8}>
            <Card title="系统资源">
              {sys ? (
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  <div>
                    <Text type="secondary">进程运行时间</Text>
                    <div style={{ fontSize: 20, fontWeight: 700 }}>{fmtDuration(sys.uptime_seconds)}</div>
                  </div>
                  <div>
                    <Text type="secondary">Go 协程</Text>
                    <div style={{ fontSize: 20, fontWeight: 700 }}>{sys.goroutines.toLocaleString()}</div>
                  </div>
                  <div>
                    <Text type="secondary">内存占用</Text>
                    <div style={{ fontSize: 20, fontWeight: 700 }}>{fmtBytes(sys.memory_alloc)} <Text type="secondary" style={{ fontSize: 12 }}>/ {fmtBytes(sys.memory_sys)}</Text></div>
                  </div>
                  <div>
                    <Text type="secondary">数据库大小</Text>
                    <div style={{ fontSize: 20, fontWeight: 700 }}>{fmtBytes(sys.db_size)}</div>
                  </div>
                  <Space wrap>
                    <Tag>{sys.version}</Tag>
                    <Tag>{sys.go_version}</Tag>
                    <Tag>{sys.os}/{sys.arch}</Tag>
                    <Tag>{sys.cpus} vCPU</Tag>
                  </Space>
                </Space>
              ) : (
                <Empty />
              )}
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} md={12} xl={6}>
            <Card title="Top 来源 IP"><BucketList data={summary?.top_ips || []} empty="暂无来源数据" /></Card>
          </Col>
          <Col xs={24} md={12} xl={6}>
            <Card title="Top 国家/地区"><BucketList data={summary?.top_countries || []} empty="暂无地理数据" color="#12b76a" /></Card>
          </Col>
          <Col xs={24} md={12} xl={6}>
            <Card title="请求方法"><BucketList data={summary?.top_methods || []} empty="暂无方法数据" color="#2563eb" /></Card>
          </Col>
          <Col xs={24} md={12} xl={6}>
            <Card title="连接类型">
              <BucketList
                data={(summary?.by_connection || []).map(b => ({ ...b, label: CONN_LABEL[b.label] || b.label }))}
                empty="暂无连接分类"
                color="#f79009"
              />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={14}>
            <Card
              title="数据源健康"
              extra={<Tag color={healthy.length === enabled.length ? 'success' : 'warning'}>{healthy.length}/{enabled.length} 正常</Tag>}
              styles={{ body: { padding: 0 } }}
            >
              <Table
                dataSource={providers}
                rowKey={p => `${p.dataset}-${p.name}-${p.source || ''}`}
                size="small"
                pagination={false}
                scroll={{ x: 560 }}
                columns={[
                  { title: '数据集', dataIndex: 'dataset', width: 110, render: (v: string) => <Tag>{v}</Tag> },
                  { title: 'Provider', dataIndex: 'name', render: (v: string) => <strong>{v}</strong> },
                  { title: '条目', dataIndex: 'entries', width: 100, render: (v: number) => v?.toLocaleString?.() ?? v },
                  { title: '优先级', dataIndex: 'priority', width: 76 },
                  {
                    title: '状态',
                    dataIndex: 'status',
                    width: 90,
                    render: (v: string, p) => <Tag color={!p.enabled ? 'default' : v === 'ok' ? 'success' : v === 'empty' ? 'warning' : 'error'}>{!p.enabled ? '停用' : v}</Tag>,
                  },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={10}>
            <Card title="运维入口">
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <div className="setting-tile">
                  <div>
                    <div className="s-title">Prometheus 指标</div>
                    <div className="s-desc mono">GET /metrics</div>
                  </div>
                  <Button size="small" href="/metrics" target="_blank">打开</Button>
                </div>
                <div className="setting-tile">
                  <div>
                    <div className="s-title">OpenAPI 文档</div>
                    <div className="s-desc mono">GET /api/openapi.json</div>
                  </div>
                  <Button size="small" href="/api/openapi.json" target="_blank">打开</Button>
                </div>
                <div className="setting-tile">
                  <div>
                    <div className="s-title">异常数据源</div>
                    <div className="s-desc">{unhealthy.length ? unhealthy.map(p => p.name).join('、') : '全部正常，无需处理'}</div>
                  </div>
                  {unhealthy.length ? <WarningOutlined style={{ color: '#f04438', fontSize: 18 }} /> : <CloudServerOutlined style={{ color: '#059669', fontSize: 18 }} />}
                </div>
                <div className="setting-tile">
                  <div>
                    <div className="s-title">查询记录存储</div>
                    <div className="s-desc">{sys ? fmtBytes(sys.db_size) : '—'} · {sys?.db_path || ''}</div>
                  </div>
                  <DatabaseOutlined style={{ color: '#5b5bd6', fontSize: 18 }} />
                </div>
              </Space>
            </Card>
          </Col>
        </Row>
      </Spin>
    </>
  );
};

export default Monitoring;

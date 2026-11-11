import React, { useEffect, useState } from 'react';
import { Button, Card, Col, Empty, Input, Progress, Row, Space, Spin, Statistic, Table, Tag, Typography } from 'antd';
import { ScanOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { JA4Hit, JA4StatProvider, getJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text } = Typography;

const Fingerprints: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  const [q, setQ] = useState('');
  const [items, setItems] = useState<JA4Hit[]>([]);
  const [providers, setProviders] = useState<JA4StatProvider[]>([]);
  const [entries, setEntries] = useState(0);
  const [observations, setObservations] = useState(0);
  const [loading, setLoading] = useState(true);

  const load = async (query = q) => {
    setLoading(true);
    try {
      const [stats, search] = await Promise.all([
        getJSON<{ providers: JA4StatProvider[]; total_entries: number; total_observations: number }>('/api/ja4/stats', token),
        getJSON<{ items: JA4Hit[] }>(`/api/ja4/search?q=${encodeURIComponent(query)}&limit=80`, token),
      ]);
      setProviders(stats.providers || []);
      setEntries(stats.total_entries || 0);
      setObservations(stats.total_observations || 0);
      setItems(search.items || []);
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <PageHeader
        title="JA4 指纹库"
        description="跨所有已加载指纹库搜索 JA4、客户端名称或家族。观测数越多、候选越集中，判断越可靠。"
        extra={<Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>}
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="指纹条目" value={entries} prefix={<ScanOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="累计观测" value={observations} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="已加载 Provider" value={providers.length} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="当前结果" value={items.length} suffix={<Text type="secondary" style={{ fontSize: 12 }}>条</Text>} />
          </Card>
        </Col>
      </Row>

      <Card styles={{ body: { paddingTop: 16 } }}>
        <Space.Compact style={{ width: '100%', maxWidth: 640, marginBottom: 14 }}>
          <Input
            allowClear
            prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
            placeholder="JA4 前缀（如 t13d1516h2_8daaf6152771）或客户端名称（Chrome / curl / Go）"
            value={q}
            onChange={e => setQ(e.target.value)}
            onPressEnter={() => load(q)}
          />
          <Button type="primary" onClick={() => load(q)} loading={loading}>搜索</Button>
        </Space.Compact>

        <Spin spinning={loading}>
          <Table
            dataSource={items}
            rowKey={r => `${r.provider}-${r.ja4}`}
            size="middle"
            scroll={{ x: 900 }}
            pagination={{ pageSize: 15, showTotal: n => `共 ${n} 条` }}
            locale={{ emptyText: <Empty description="没有匹配的指纹" /> }}
            expandable={{
              expandedRowRender: r => (
                <Space direction="vertical" size={6} style={{ padding: '4px 8px' }}>
                  <Text strong>候选客户端</Text>
                  {r.clients.length === 0 ? <Text type="secondary">没有可命名的客户端证据</Text> : r.clients.map(c => (
                    <div key={c.name} style={{ display: 'flex', alignItems: 'center', gap: 10, maxWidth: 520 }}>
                      <Tag color="blue">{c.name}</Tag>
                      <Progress percent={Math.round(c.share * 100)} size="small" style={{ flex: 1 }} />
                      <Text type="secondary" style={{ fontSize: 12 }}>{(c.share * 100).toFixed(1)}%</Text>
                    </div>
                  ))}
                </Space>
              ),
            }}
            columns={[
              {
                title: 'JA4 指纹',
                dataIndex: 'ja4',
                render: (v: string, r) => (
                  <div>
                    <div className="mono" style={{ fontWeight: 600 }}>{v}</div>
                    <div className="muted" style={{ fontSize: 11 }}>{r.provider}</div>
                  </div>
                ),
              },
              {
                title: '识别结果',
                width: 190,
                render: (_: unknown, r) => (
                  <div>
                    <Space size={6}>
                      <Tag color={r.verified ? 'success' : 'blue'}>{r.name || '未识别'}</Tag>
                      {r.verified && <Text type="secondary" style={{ fontSize: 11 }}>已验证</Text>}
                    </Space>
                    <div className="muted" style={{ fontSize: 11 }}>{r.family}{r.version ? ' · ' + r.version : ''}</div>
                  </div>
                ),
              },
              {
                title: '置信度',
                dataIndex: 'confidence',
                width: 160,
                render: (v: number) => <Progress percent={Math.round(v * 100)} size="small" strokeColor={(v || 0) >= 0.8 ? '#12b76a' : (v || 0) >= 0.55 ? '#5b5bd6' : '#f79009'} />,
              },
              {
                title: '观测数',
                dataIndex: 'observations',
                width: 100,
                sorter: (a, b) => a.observations - b.observations,
                render: (v: number) => v.toLocaleString(),
              },
              {
                title: '候选',
                width: 120,
                render: (_: unknown, r) => <Text type="secondary">{r.clients.length} 个</Text>,
              },
            ]}
          />
        </Spin>
        <p className="section-note">搜索为空时按观测数返回高频指纹；JA4 前缀匹配用于识别同加密套件的新版本客户端。</p>
      </Card>

      <Card title="指纹库来源" style={{ marginTop: 16 }}>
        {providers.length === 0 ? (
          <Empty description="没有已加载的指纹库" />
        ) : (
          <Table
            dataSource={providers}
            rowKey={p => p.name}
            size="small"
            pagination={false}
            columns={[
              { title: 'Provider', dataIndex: 'name', render: (v: string) => <Tag color="purple">{v}</Tag> },
              { title: '条目', dataIndex: 'entries', render: (v: number) => v.toLocaleString() },
              { title: '观测', dataIndex: 'observations', render: (v: number) => v.toLocaleString() },
              { title: '来源', dataIndex: 'source', ellipsis: true },
              { title: '导出时间', dataIndex: 'exported', width: 160 },
            ]}
          />
        )}
        <p className="section-note">自定义指纹库在「数据源」页面配置，优先级高于内置快照。</p>
      </Card>
    </>
  );
};

export default Fingerprints;

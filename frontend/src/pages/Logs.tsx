import React, { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Input,
  message,
  Modal,
  Popconfirm,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CloudDownloadOutlined,
  CloudServerOutlined,
  DeleteOutlined,
  GlobalOutlined,
  HistoryOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SaveOutlined,
  SearchOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { MetricsSummary, QueryLog, SavedView, downloadFile, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const CONN_LABEL: Record<string, string> = {
  datacenter: '数据中心',
  residential_proxy: '住宅代理',
  unknown: '未知',
};

const CONN_COLOR: Record<string, string> = {
  datacenter: 'orange',
  residential_proxy: 'green',
  unknown: 'default',
};

const METHOD_COLOR: Record<string, string> = {
  GET: 'blue', POST: 'green', PUT: 'gold', DELETE: 'red', PATCH: 'purple', HEAD: 'default', OPTIONS: 'default',
};

interface Filters {
  q: string;
  method: string;
  country: string;
  type: string;
  days: number;
}

const EMPTY: Filters = { q: '', method: '', country: '', type: '', days: 0 };

const Logs: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [logs, setLogs] = useState<QueryLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [auto, setAuto] = useState(true);
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [pageSize, setPageSize] = useState(20);
  const [selected, setSelected] = useState<QueryLog | null>(null);
  const [views, setViews] = useState<SavedView[]>([]);
  const [summary24, setSummary24] = useState<MetricsSummary | null>(null);
  const [replay, setReplay] = useState<{ method: string; path: string; body: string } | null>(null);
  const [replayResult, setReplayResult] = useState('');

  const qs = (f: Filters, limit = 1000) => {
    const p = new URLSearchParams({ limit: String(limit) });
    if (f.q.trim()) p.set('q', f.q.trim());
    if (f.method) p.set('method', f.method);
    if (f.country.trim()) p.set('country', f.country.trim());
    if (f.type) p.set('type', f.type);
    if (f.days > 0) p.set('days', String(f.days));
    return p.toString();
  };

  const load = async (silent = false, f = filters) => {
    if (!silent) setLoading(true);
    try {
      const [rows, agg] = await Promise.all([
        getJSON<QueryLog[]>('/api/logs?' + qs(f), token),
        getJSON<MetricsSummary>('/api/metrics/summary?hours=24', token).catch(() => null),
      ]);
      setLogs(rows || []);
      if (agg) setSummary24(agg);
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  const loadViews = async () => {
    try {
      setViews((await getJSON<SavedView[]>('/api/views?page=logs', token)) || []);
    } catch {
      /* views are optional */
    }
  };

  useEffect(() => {
    load();
    loadViews();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!auto) return;
    const timer = window.setInterval(() => load(true), 15000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, filters]);

  const summary = useMemo(() => {
    const ips = new Set(logs.map(l => l.ip));
    const dc = logs.filter(l => l.connection_type === 'datacenter').length;
    const rp = logs.filter(l => l.connection_type === 'residential_proxy').length;
    return { unique: ips.size, dc, rp };
  }, [logs]);

  const exportFile = async (ext: 'csv' | 'json') => {
    try {
      await downloadFile(`/api/export/logs.${ext}?${qs(filters, 10000)}`, token, `query-logs.${ext}`);
      message.success('开始下载');
    } catch (err) {
      fail(err);
    }
  };

  const saveView = () => {
    let name = '';
    Modal.confirm({
      title: '保存当前筛选',
      content: <Input placeholder="视图名称，例如：数据中心异常" onChange={e => { name = e.target.value; }} />,
      okText: '保存',
      cancelText: '取消',
      onOk: async () => {
        if (!name.trim()) {
          message.warning('请输入名称');
          return Promise.reject();
        }
        try {
          await postJSON('/api/views', token, { name: name.trim(), page: 'logs', filters: JSON.stringify(filters) });
          message.success('视图已保存');
          await loadViews();
        } catch (err) {
          fail(err);
        }
      },
    });
  };

  const applyView = (id: number) => {
    const v = views.find(x => x.id === id);
    if (!v) return;
    try {
      const parsed = JSON.parse(v.filters || '{}') as Partial<Filters>;
      const next = { ...EMPTY, ...parsed };
      setFilters(next);
      load(false, next);
    } catch {
      message.error('视图内容损坏');
    }
  };

  const deleteView = async (id: number) => {
    try {
      const res = await fetch(`/api/views?id=${id}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + token } });
      if (!res.ok) throw new Error(await res.text());
      await loadViews();
    } catch (err) {
      fail(err);
    }
  };

  const doReplay = async () => {
    if (!replay) return;
    try {
      const res = await postJSON<{ status: number; body: string }>('/api/replay', token, replay);
      setReplayResult(`HTTP ${res.status}\n\n${res.body}`);
    } catch (err) {
      fail(err);
    }
  };

  return (
    <>
      <PageHeader
        title="查询日志"
        description="按路径、IP、国家与连接类型筛选回显请求，可导出、保存视图，并重放合成请求验证当前配置。"
        extra={
          <Space wrap>
            <Space size={6}><Text type="secondary">自动刷新</Text><Switch size="small" checked={auto} onChange={setAuto} /></Space>
            <Button icon={<CloudDownloadOutlined />} onClick={() => exportFile('csv')}>CSV</Button>
            <Button icon={<CloudDownloadOutlined />} onClick={() => exportFile('json')}>JSON</Button>
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card" styles={{ body: { padding: 18 } }}>
            <Statistic title={<Space size={6}><HistoryOutlined /> 记录数</Space>} value={logs.length} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card" styles={{ body: { padding: 18 } }}>
            <Statistic title={<Space size={6}><GlobalOutlined /> 独立 IP</Space>} value={summary.unique} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card" styles={{ body: { padding: 18 } }}>
            <Statistic title={<Space size={6}><CloudServerOutlined /> 数据中心</Space>} value={summary.dc} valueStyle={{ color: '#d97706' }} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card" styles={{ body: { padding: 18 } }}>
            <Statistic title={<Space size={6}><UserOutlined /> 住宅代理</Space>} value={summary.rp} valueStyle={{ color: '#059669' }} />
          </Card>
        </Col>
      </Row>

      <Card styles={{ body: { paddingTop: 16 } }}>
        <Space wrap style={{ marginBottom: 12 }}>
          <Text type="secondary" style={{ fontSize: 12 }}>快捷筛选：</Text>
          {[
            { label: '数据中心', next: { ...EMPTY, type: 'datacenter' } },
            { label: '住宅代理', next: { ...EMPTY, type: 'residential_proxy' } },
            { label: '仅 POST', next: { ...EMPTY, method: 'POST' } },
            { label: '最近 1 天', next: { ...EMPTY, days: 1 } },
            { label: '重置', next: { ...EMPTY } },
          ].map(p => (
            <Tag
              key={p.label}
              color="blue"
              style={{ cursor: 'pointer' }}
              onClick={() => { setFilters(p.next); load(false, p.next); }}
            >
              {p.label}
            </Tag>
          ))}
        </Space>
        <Space wrap style={{ marginBottom: 14 }}>
          <Input
            allowClear
            prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
            placeholder="路径 / IP / 国家"
            style={{ width: 220 }}
            value={filters.q}
            onChange={e => setFilters(f => ({ ...f, q: e.target.value }))}
            onPressEnter={() => load()}
          />
          <Select
            allowClear
            placeholder="方法"
            style={{ width: 110 }}
            value={filters.method || undefined}
            onChange={v => setFilters(f => ({ ...f, method: v || '' }))}
            options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(v => ({ value: v, label: v }))}
          />
          <Input
            allowClear
            placeholder="国家，例如 Japan"
            style={{ width: 150 }}
            value={filters.country}
            onChange={e => setFilters(f => ({ ...f, country: e.target.value }))}
            onPressEnter={() => load()}
          />
          <Segmented
            value={filters.type || 'all'}
            onChange={v => setFilters(f => ({ ...f, type: v === 'all' ? '' : String(v) }))}
            options={[
              { value: 'all', label: '全部' },
              { value: 'datacenter', label: '数据中心' },
              { value: 'residential_proxy', label: '住宅代理' },
              { value: 'unknown', label: '未知' },
            ]}
          />
          <Select
            value={filters.days}
            onChange={v => setFilters(f => ({ ...f, days: Number(v) }))}
            style={{ width: 130 }}
            options={[
              { value: 0, label: '不限时间' },
              { value: 1, label: '最近 1 天' },
              { value: 7, label: '最近 7 天' },
              { value: 30, label: '最近 30 天' },
            ]}
          />
          <Button type="primary" icon={<SearchOutlined />} onClick={() => load()} loading={loading}>应用筛选</Button>
          <Button icon={<SaveOutlined />} onClick={saveView}>保存视图</Button>
          {views.length > 0 && (
            <Select
              placeholder="已保存视图"
              style={{ width: 180 }}
              value={undefined}
              onChange={applyView}
              options={views.map(v => ({ value: v.id, label: v.name }))}
            />
          )}
          <Select
            value={pageSize}
            onChange={setPageSize}
            style={{ width: 118 }}
            options={[{ value: 20, label: '20 条 / 页' }, { value: 50, label: '50 条 / 页' }, { value: 100, label: '100 条 / 页' }]}
          />
        </Space>

        {views.length > 0 && (
          <Space wrap style={{ marginBottom: 12 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>已保存视图：</Text>
            {views.map(v => (
              <Tag key={v.id} closable onClose={e => { e.preventDefault(); deleteView(v.id); }} onClick={() => applyView(v.id)} style={{ cursor: 'pointer' }}>
                {v.name}
              </Tag>
            ))}
          </Space>
        )}

        <Table
          dataSource={logs}
          loading={loading}
          rowKey={(_, index) => String(index)}
          size="middle"
          scroll={{ x: 820 }}
          onRow={r => ({ onClick: () => setSelected(r), style: { cursor: 'pointer' } })}
          pagination={{ pageSize, showSizeChanger: false, showTotal: n => `共 ${n} 条` }}
          columns={[
            {
              title: '时间', dataIndex: 'ts', width: 180,
              render: (v: string) => <Tooltip title={v}><Text type="secondary">{fmtTime(v)}</Text></Tooltip>,
            },
            { title: '方法', dataIndex: 'method', width: 88, render: (v: string) => <Tag color={METHOD_COLOR[v] || 'default'}>{v || '—'}</Tag> },
            { title: '路径', dataIndex: 'path', ellipsis: true, render: (v: string) => <span className="mono">{v || '—'}</span> },
            { title: '来源 IP', dataIndex: 'ip', width: 150, render: (v: string) => <span className="mono">{v || '—'}</span> },
            {
              title: '连接类型', dataIndex: 'connection_type', width: 118,
              render: (v: string) => {
                const key = v || 'unknown';
                return <Tag color={CONN_COLOR[key] || 'default'}>{CONN_LABEL[key] || key}</Tag>;
              },
            },
            { title: '国家', dataIndex: 'country', width: 90, render: (v: string) => (v ? <span>{v}</span> : <Text type="secondary">—</Text>) },
            {
              title: '操作', width: 70, fixed: 'right',
              render: (_: unknown, r) => (
                <Button
                  size="small"
                  type="text"
                  icon={<PlayCircleOutlined />}
                  disabled={!canEdit}
                  onClick={e => {
                    e.stopPropagation();
                    setReplay({ method: r.method || 'GET', path: r.path || '/', body: '' });
                    setReplayResult('');
                  }}
                />
              ),
            },
          ]}
        />
      </Card>

      <p className="section-note">列表最多拉取 1000 条匹配记录；自动刷新每 15 秒一次。点击行可查看详情。</p>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={13}>
          <Card title="日志字段" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={[
                { field: 'ts', desc: '请求进入服务端的时间（UTC 存储，页面本地化显示）' },
                { field: 'method', desc: 'HTTP 方法，重放时默认沿用' },
                { field: 'path', desc: '请求路径与查询串，不含主机名' },
                { field: 'ip', desc: '来源 IP；反向代理场景下取决于真实 IP 头配置' },
                { field: 'connection_type', desc: '本地 CIDR 或在线情报给出的数据中心 / 住宅代理判定' },
                { field: 'country', desc: '国家名称，离线模式下可能为空' },
              ]}
              rowKey="field"
              size="small"
              pagination={false}
              columns={[
                { title: '字段', dataIndex: 'field', width: 150, render: (v: string) => <Text code>{v}</Text> },
                { title: '说明', dataIndex: 'desc' },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={11}>
          <Card title="导出与保留">
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="CSV">适合表格分析，字段固定、逗号转义</Descriptions.Item>
              <Descriptions.Item label="JSON">保留原始结构，适合程序再处理</Descriptions.Item>
              <Descriptions.Item label="导出上限">单次最多 10000 条匹配记录</Descriptions.Item>
              <Descriptions.Item label="保留策略">由「安全与防护 → 系统保护」中的天数决定</Descriptions.Item>
              <Descriptions.Item label="清理方式">后台每 6 小时自动清理过期记录</Descriptions.Item>
              <Descriptions.Item label="请求内容">请求头与请求体不落库，重放时可手动补充</Descriptions.Item>
            </Descriptions>
            <p className="section-note" style={{ marginBottom: 0 }}>
              导出文件包含当前筛选条件；保存视图可以复用同一组筛选。
            </p>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={14}>
          <Card title="最近 24 小时趋势" extra={<Text type="secondary" style={{ fontSize: 12 }}>共 {summary24?.total ?? 0} 次 · {summary24?.unique_ips ?? 0} 个 IP</Text>}>
            {summary24?.by_hour?.length ? (
              <>
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 120 }}>
                  {summary24.by_hour.map((h, i) => {
                    const max = Math.max(...summary24.by_hour.map(x => x.count), 1);
                    const pct = Math.round((h.count / max) * 100);
                    return (
                      <Tooltip key={i} title={`${h.hour} · ${h.count} 次`}>
                        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', height: '100%' }}>
                          <div style={{ height: `${Math.max(pct, 2)}%`, background: 'linear-gradient(180deg,#818cf8,#5b5bd6)', borderRadius: 3 }} />
                        </div>
                      </Tooltip>
                    );
                  })}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>{summary24.by_hour[0]?.hour}</Text>
                  <Text type="secondary" style={{ fontSize: 11 }}>{summary24.by_hour[summary24.by_hour.length - 1]?.hour}</Text>
                </div>
              </>
            ) : (
              <div className="empty-pad muted" style={{ textAlign: 'center' }}>最近 24 小时还没有请求</div>
            )}
          </Card>
        </Col>
        <Col xs={24} xl={5}>
          <Card title="Top IP" styles={{ body: { padding: '6px 0' } }}>
            {(summary24?.top_ips || []).slice(0, 6).map(b => (
              <div className="provider-row" key={b.label} style={{ padding: '7px 16px' }}>
                <span className="mono" style={{ fontSize: 12 }}>{b.label}</span>
                <Text strong>{b.count}</Text>
              </div>
            ))}
            {!summary24?.top_ips?.length && <div className="empty-pad muted" style={{ textAlign: 'center' }}>暂无数据</div>}
          </Card>
        </Col>
        <Col xs={24} xl={5}>
          <Card title="Top 国家" styles={{ body: { padding: '6px 0' } }}>
            {(summary24?.top_countries || []).slice(0, 6).map(b => (
              <div className="provider-row" key={b.label} style={{ padding: '7px 16px' }}>
                <span style={{ fontSize: 12 }}>{b.label || '未知'}</span>
                <Text strong>{b.count}</Text>
              </div>
            ))}
            {!summary24?.top_countries?.length && <div className="empty-pad muted" style={{ textAlign: 'center' }}>暂无数据</div>}
          </Card>
        </Col>
      </Row>

      <Drawer title="请求详情" width={460} open={!!selected} onClose={() => setSelected(null)}>
        {selected && (
          <>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="时间">{fmtTime(selected.ts)}</Descriptions.Item>
              <Descriptions.Item label="方法">{selected.method}</Descriptions.Item>
              <Descriptions.Item label="路径"><span className="mono">{selected.path}</span></Descriptions.Item>
              <Descriptions.Item label="来源 IP"><span className="mono">{selected.ip}</span></Descriptions.Item>
              <Descriptions.Item label="连接类型">{CONN_LABEL[selected.connection_type] || selected.connection_type || '未知'}</Descriptions.Item>
              <Descriptions.Item label="国家">{selected.country || '—'}</Descriptions.Item>
            </Descriptions>
            {canEdit && (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                style={{ marginTop: 16 }}
                onClick={() => {
                  setReplay({ method: selected.method || 'GET', path: selected.path || '/', body: '' });
                  setReplayResult('');
                }}
              >
                重放这个请求
              </Button>
            )}
            <Paragraph type="secondary" style={{ marginTop: 16, fontSize: 12 }}>
              日志只保存时间、方法、路径、来源和分类；请求头与请求体未持久化，重放时可自行补充。
            </Paragraph>
          </>
        )}
      </Drawer>

      <Modal
        title="重放合成请求"
        open={!!replay}
        onCancel={() => setReplay(null)}
        width={720}
        footer={[
          <Button key="cancel" onClick={() => setReplay(null)}>关闭</Button>,
          <Button key="run" type="primary" icon={<PlayCircleOutlined />} onClick={doReplay}>执行重放</Button>,
        ]}
      >
        {replay && (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Space wrap>
              <Select
                value={replay.method}
                onChange={v => setReplay({ ...replay, method: v })}
                style={{ width: 110 }}
                options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(v => ({ value: v, label: v }))}
              />
              <Input style={{ width: 420 }} value={replay.path} onChange={e => setReplay({ ...replay, path: e.target.value })} className="mono" />
            </Space>
            <Input.TextArea rows={3} placeholder="请求体（可选）" value={replay.body} onChange={e => setReplay({ ...replay, body: e.target.value })} className="mono" />
            <pre className="code-block" style={{ maxHeight: 320 }}>{replayResult || '执行后会显示真实 echoHandler 的响应'}</pre>
            <Popconfirm title="清空全部匹配日志？" description="请先在筛选栏确认范围。" okText="清空" cancelText="取消" onConfirm={async () => {
              try {
                const res = await postJSON<{ deleted: number }>('/api/system/purge-logs', token, { all: true });
                message.success(`已删除 ${res.deleted} 条`);
                await load();
              } catch (err) {
                fail(err);
              }
            }}>
              <Button danger size="small" icon={<DeleteOutlined />}>清空全部查询日志</Button>
            </Popconfirm>
          </Space>
        )}
      </Modal>
    </>
  );
};

export default Logs;

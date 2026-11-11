import React, { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Input,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import {
  AuditOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SearchOutlined,
  SafetyOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { AuditEntry, downloadFile, fmtTime, getJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const ACTION_COLOR: Record<string, string> = {
  config: 'blue',
  user: 'purple',
  apikey: 'gold',
  webhook: 'cyan',
  security: 'red',
  system: 'orange',
};

const ACTION_LABEL: Record<string, string> = {
  config: '配置变更',
  user: '账号操作',
  apikey: 'API Key',
  webhook: 'Webhook',
  security: '安全动作',
  system: '系统维护',
};

const actionColor = (action: string) => ACTION_COLOR[action.split('.')[0]] || 'default';
const actionGroup = (action: string) => action.split('.')[0];

const Audit: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState('');
  const [username, setUsername] = useState('');
  const [limit, setLimit] = useState(200);
  const [selected, setSelected] = useState<AuditEntry | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams({ limit: String(limit) });
      if (action) qs.set('action', action);
      if (username.trim()) qs.set('username', username.trim());
      setRows((await getJSON<AuditEntry[]>('/api/audit?' + qs.toString(), token)) || []);
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
    const today = new Date().toDateString();
    const todayCount = rows.filter(r => new Date(r.ts).toDateString() === today).length;
    const actors = new Set(rows.map(r => r.username)).size;
    const groups = new Set(rows.map(r => actionGroup(r.action))).size;
    return { total: rows.length, today: todayCount, actors, groups };
  }, [rows]);

  const byAction = useMemo(() => {
    const map = new Map<string, number>();
    rows.forEach(r => {
      const g = actionGroup(r.action);
      map.set(g, (map.get(g) || 0) + 1);
    });
    return Array.from(map.entries())
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count);
  }, [rows]);

  const byActor = useMemo(() => {
    const map = new Map<string, { count: number; last: string }>();
    rows.forEach(r => {
      const cur = map.get(r.username) || { count: 0, last: '' };
      map.set(r.username, { count: cur.count + 1, last: r.ts > cur.last ? r.ts : cur.last });
    });
    return Array.from(map.entries())
      .map(([username, v]) => ({ username, ...v }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [rows]);

  const exportCSV = async () => {
    try {
      await downloadFile('/api/audit/export.csv?format=csv&limit=2000', token, 'audit-log.csv');
      message.success('审计日志已导出');
    } catch (err) {
      fail(err);
    }
  };

  const maxAction = Math.max(...byAction.map(a => a.count), 1);

  return (
    <>
      <PageHeader
        title="审计日志"
        description="记录配置变更、账号操作、密钥创建与安全动作。审计条目只追加，不作为回显查询统计的一部分。"
        extra={
          <Space>
            <Button icon={<DownloadOutlined />} onClick={exportCSV}>导出 CSV</Button>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="当前结果" value={stats.total} prefix={<AuditOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="今日操作" value={stats.today} prefix={<ThunderboltOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="操作者" value={stats.actors} prefix={<TeamOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="动作类别" value={stats.groups} prefix={<SafetyOutlined />} /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card styles={{ body: { paddingTop: 16 } }}>
            <Space wrap style={{ marginBottom: 14 }}>
              <Input
                allowClear
                prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                placeholder="按操作者过滤，例如 admin"
                style={{ width: 220 }}
                value={username}
                onChange={e => setUsername(e.target.value)}
                onPressEnter={load}
              />
              <Select
                value={action || undefined}
                allowClear
                placeholder="全部动作"
                style={{ width: 180 }}
                onChange={v => setAction(v || '')}
                options={Object.entries(ACTION_LABEL).map(([value, label]) => ({ value: value + '.', label }))}
              />
              <Select
                value={limit}
                onChange={setLimit}
                style={{ width: 130 }}
                options={[
                  { value: 100, label: '最近 100 条' },
                  { value: 200, label: '最近 200 条' },
                  { value: 500, label: '最近 500 条' },
                  { value: 2000, label: '最近 2000 条' },
                ]}
              />
              <Button type="primary" icon={<SearchOutlined />} onClick={load} loading={loading}>查询</Button>
            </Space>

            <Table
              dataSource={rows}
              rowKey="id"
              loading={loading}
              size="middle"
              scroll={{ x: 860 }}
              pagination={{ pageSize: 20, showTotal: n => `共 ${n} 条` }}
              onRow={r => ({ onClick: () => setSelected(r), style: { cursor: 'pointer' } })}
              columns={[
                {
                  title: '时间',
                  dataIndex: 'ts',
                  width: 180,
                  render: (v: string) => <Tooltip title={v}><Text type="secondary">{fmtTime(v)}</Text></Tooltip>,
                },
                {
                  title: '操作者',
                  dataIndex: 'username',
                  width: 130,
                  render: (v: string) => <Space size={4}><SafetyOutlined style={{ color: '#94a3b8' }} /><span>{v}</span></Space>,
                },
                {
                  title: '动作',
                  dataIndex: 'action',
                  width: 150,
                  render: (v: string) => <Tag color={actionColor(v)}>{v}</Tag>,
                },
                {
                  title: '对象',
                  dataIndex: 'target',
                  width: 200,
                  ellipsis: true,
                  render: (v: string) => <span className="mono">{v || '—'}</span>,
                },
                { title: '详情', dataIndex: 'detail', ellipsis: true, render: (v: string) => v || <Text type="secondary">—</Text> },
                { title: 'IP', dataIndex: 'ip', width: 150, render: (v: string) => <span className="mono">{v}</span> },
              ]}
            />
            <p className="section-note">操作筛选按前缀匹配（例如 config. 包含 config.update）。点击任意行查看完整详情。</p>
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card title="动作分布">
            {byAction.length === 0 ? (
              <div className="empty-pad muted" style={{ textAlign: 'center' }}>暂无数据</div>
            ) : (
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                {byAction.map(a => (
                  <div key={a.action}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                      <Text>{ACTION_LABEL[a.action] || a.action}</Text>
                      <Text type="secondary">{a.count}</Text>
                    </div>
                    <Progress
                      percent={Math.round((a.count / maxAction) * 100)}
                      showInfo={false}
                      size="small"
                      strokeColor={
                        a.action === 'security' ? '#f04438' : a.action === 'system' ? '#f79009' : a.action === 'user' ? '#7c3aed' : '#5b5bd6'
                      }
                    />
                  </div>
                ))}
              </Space>
            )}
          </Card>

          <Card title="操作者排行" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={byActor}
              rowKey="username"
              size="small"
              pagination={false}
              columns={[
                { title: '操作者', dataIndex: 'username' },
                { title: '操作数', dataIndex: 'count', width: 80 },
                { title: '最近活动', dataIndex: 'last', width: 160, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(v)}</Text> },
              ]}
            />
          </Card>

          <Card title="审计策略" style={{ marginTop: 16 }}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="写入时机">所有管理端写操作完成后</Descriptions.Item>
              <Descriptions.Item label="记录字段">时间、操作者、动作、对象、详情、来源 IP</Descriptions.Item>
              <Descriptions.Item label="保留策略">只追加，当前不自动清理</Descriptions.Item>
              <Descriptions.Item label="导出">CSV，最多 2000 条 / 次</Descriptions.Item>
              <Descriptions.Item label="关联通知">user.* / security.* / config.* / system.* 会生成站内通知</Descriptions.Item>
            </Descriptions>
            <p className="section-note" style={{ marginBottom: 0 }}>
              审计日志与查询日志分表存储，清空查询日志不会影响审计记录。
            </p>
          </Card>
        </Col>
      </Row>

      <Card title="动作字典" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
        <Table
          dataSource={[
            { action: 'config.update', where: '回显设置 / 访问控制 / 安全策略保存', level: '信息' },
            { action: 'user.create / update / delete', where: '用户管理创建、编辑、禁用、删除账号', level: '信息' },
            { action: 'apikey.create / update / delete', where: '安全页签签发、启停、删除命名 Key', level: '信息' },
            { action: 'security.rotate_jwt', where: '轮换会话签名密钥', level: '警告' },
            { action: 'system.backup / purge_logs', where: '下载备份、清理查询日志', level: '信息' },
            { action: 'webhook.create / update / delete', where: '集成页新增或修改 Webhook', level: '信息' },
            { action: 'webhook.delivery_failed', where: '异步投递失败（同时生成站内警告）', level: '警告' },
          ]}
          rowKey="action"
          size="small"
          pagination={false}
          columns={[
            { title: '动作前缀', dataIndex: 'action', width: 300, render: (v: string) => <Text code style={{ fontSize: 12 }}>{v}</Text> },
            { title: '触发位置', dataIndex: 'where' },
            { title: '通知级别', dataIndex: 'level', width: 100, render: (v: string) => <Tag color={v === '警告' ? 'orange' : 'blue'}>{v}</Tag> },
          ]}
        />
        <p className="section-note" style={{ padding: '0 16px' }}>
          筛选时使用前缀即可命中同组动作，例如 <Text code>user.</Text> 会包含 create / update / delete。
        </p>
      </Card>

      <Drawer title="审计详情" width={460} open={!!selected} onClose={() => setSelected(null)}>
        {selected && (
          <>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="时间">{fmtTime(selected.ts)}</Descriptions.Item>
              <Descriptions.Item label="操作者">{selected.username}</Descriptions.Item>
              <Descriptions.Item label="动作"><Tag color={actionColor(selected.action)}>{selected.action}</Tag></Descriptions.Item>
              <Descriptions.Item label="对象"><span className="mono">{selected.target || '—'}</span></Descriptions.Item>
              <Descriptions.Item label="来源 IP"><span className="mono">{selected.ip || '—'}</span></Descriptions.Item>
              <Descriptions.Item label="ID">#{selected.id}</Descriptions.Item>
            </Descriptions>
            <Paragraph strong style={{ marginTop: 16 }}>详情</Paragraph>
            <pre className="code-block" style={{ whiteSpace: 'pre-wrap' }}>{selected.detail || '（无补充说明）'}</pre>
          </>
        )}
      </Drawer>
    </>
  );
};

export default Audit;

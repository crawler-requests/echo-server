import React, { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  Col,
  Empty,
  Input,
  List,
  Popconfirm,
  Progress,
  Row,
  Segmented,
  Space,
  Spin,
  Statistic,
  Steps,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import {
  BellOutlined,
  CheckOutlined,
  DeleteOutlined,
  NotificationOutlined,
  ReloadOutlined,
  SearchOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { NotificationItem, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const LEVEL: Record<string, { color: string; label: string }> = {
  info: { color: 'blue', label: '信息' },
  warning: { color: 'orange', label: '警告' },
  error: { color: 'red', label: '错误' },
};

const RULES = [
  { action: 'config.*', trigger: '配置键被修改', level: '信息', source: 'config' },
  { action: 'user.*', trigger: '账号创建 / 更新 / 删除', level: '信息', source: 'user' },
  { action: 'security.*', trigger: 'JWT 轮换、鉴权开关等安全动作', level: '警告', source: 'security' },
  { action: 'system.*', trigger: '备份、清理日志、维护模式', level: '信息', source: 'system' },
  { action: 'webhook.delivery_failed', trigger: 'Webhook 投递失败', level: '警告', source: 'webhook' },
  { action: 'apikey.*', trigger: '命名 Key 创建 / 停用 / 删除', level: '信息', source: 'apikey' },
];

const Notifications: React.FC = () => {
  const { token } = useSession();
  const fail = useApiError();
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);
  const [auto, setAuto] = useState(true);
  const [onlyUnread, setOnlyUnread] = useState(false);
  const [level, setLevel] = useState('');
  const [q, setQ] = useState('');

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const qs = onlyUnread ? '?unread=1&limit=200' : '?limit=200';
      const res = await getJSON<{ items: NotificationItem[]; unread: number }>('/api/notifications' + qs, token);
      setItems(res.items || []);
      setUnread(res.unread || 0);
    } catch (err) {
      fail(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onlyUnread]);

  useEffect(() => {
    if (!auto) return;
    const t = window.setInterval(() => load(true), 30000);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, onlyUnread]);

  const filtered = useMemo(
    () =>
      items.filter(n => {
        if (level && n.level !== level) return false;
        const s = q.trim().toLowerCase();
        if (!s) return true;
        return [n.title, n.body, n.source].some(v => (v || '').toLowerCase().includes(s));
      }),
    [items, level, q],
  );

  const stats = useMemo(() => {
    const warn = items.filter(n => n.level === 'warning').length;
    const err = items.filter(n => n.level === 'error').length;
    const sources = new Set(items.map(n => n.source)).size;
    return { total: items.length, warn, err, sources };
  }, [items]);

  const bySource = useMemo(() => {
    const map = new Map<string, number>();
    items.forEach(n => map.set(n.source || 'unknown', (map.get(n.source || 'unknown') || 0) + 1));
    return Array.from(map.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [items]);

  const mark = async (id?: number) => {
    try {
      await postJSON('/api/notifications', token, id ? { id } : { all: true });
      message.success(id ? '已标记为已读' : '全部标记为已读');
      await load(true);
    } catch (err) {
      fail(err);
    }
  };

  const clear = async (all: boolean) => {
    try {
      const res = await fetch(`/api/notifications${all ? '?all=1' : ''}`, {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + token },
      });
      if (!res.ok) throw new Error(await res.text());
      message.success(all ? '通知已清空' : '已清理已读通知');
      await load();
    } catch (err) {
      fail(err);
    }
  };

  return (
    <>
      <PageHeader
        title="通知中心"
        description="配置变更、账号调整、安全操作与 Webhook 投递失败都会在这里留下记录。"
        extra={
          <Space>
            <Space size={6}><Text type="secondary">自动刷新</Text><Switch size="small" checked={auto} onChange={setAuto} /></Space>
            <Button icon={<CheckOutlined />} onClick={() => mark()} disabled={!unread}>全部已读</Button>
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="通知总数" value={stats.total} prefix={<BellOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="未读" value={unread} valueStyle={{ color: unread ? '#f04438' : '#059669' }} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="警告 / 错误" value={stats.warn + stats.err} valueStyle={{ color: stats.err ? '#f04438' : stats.warn ? '#d97706' : '#059669' }} />
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="事件来源" value={stats.sources} suffix="类" /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={17}>
          <Card
            title={<Space><NotificationOutlined /> 通知列表 <Badge count={unread} size="small" /></Space>}
            extra={
              <Space wrap>
                <Space size={6}><Text type="secondary">只看未读</Text><Switch size="small" checked={onlyUnread} onChange={setOnlyUnread} /></Space>
                <Popconfirm title="清理已读通知？" okText="清理" cancelText="取消" onConfirm={() => clear(false)}>
                  <Button size="small" icon={<DeleteOutlined />}>清理已读</Button>
                </Popconfirm>
                <Popconfirm title="清空全部通知？" description="该操作不可撤销。" okText="清空" cancelText="取消" onConfirm={() => clear(true)}>
                  <Button size="small" danger icon={<DeleteOutlined />}>清空</Button>
                </Popconfirm>
              </Space>
            }
            styles={{ body: { padding: items.length ? '8px 0' : 0 } }}
          >
            <Space wrap style={{ padding: '0 20px 12px' }} size={8}>
              <Input
                allowClear
                prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                placeholder="搜索标题 / 内容 / 来源"
                style={{ width: 240 }}
                value={q}
                onChange={e => setQ(e.target.value)}
              />
              <Segmented
                value={level || 'all'}
                onChange={v => setLevel(v === 'all' ? '' : String(v))}
                options={[
                  { value: 'all', label: '全部等级' },
                  { value: 'info', label: '信息' },
                  { value: 'warning', label: '警告' },
                  { value: 'error', label: '错误' },
                ]}
              />
              <Text type="secondary" style={{ fontSize: 12 }}>显示 {filtered.length} / {items.length} 条</Text>
            </Space>
            {loading ? (
              <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>
            ) : filtered.length === 0 ? (
              <div className="empty-pad"><Empty description={items.length ? '没有符合筛选条件的通知' : '暂无通知，一切安静'} /></div>
            ) : (
              <List
                dataSource={filtered}
                rowKey="id"
                pagination={filtered.length > 15 ? { pageSize: 15, size: 'small' } : false}
                renderItem={item => {
                  const lv = LEVEL[item.level] || LEVEL.info;
                  return (
                    <List.Item
                      style={{ padding: '14px 20px', background: item.read ? undefined : '#fbfcff' }}
                      actions={[
                        !item.read ? <Button key="read" type="link" size="small" onClick={() => mark(item.id)}>标记已读</Button> : <Text key="done" type="secondary" style={{ fontSize: 12 }}>已读</Text>,
                      ]}
                    >
                      <List.Item.Meta
                        avatar={<Badge dot={!item.read} offset={[-2, 2]}><Tag color={lv.color}>{lv.label}</Tag></Badge>}
                        title={
                          <Space size={8} wrap>
                            <Text strong={!item.read}>{item.title}</Text>
                            <Tag>{item.source}</Tag>
                            <Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(item.ts)}</Text>
                          </Space>
                        }
                        description={
                          <Paragraph type="secondary" style={{ margin: 0, fontSize: 13 }} ellipsis={{ rows: 2 }}>
                            {item.body || '（无补充说明）'}
                          </Paragraph>
                        }
                      />
                    </List.Item>
                  );
                }}
              />
            )}
          </Card>
          <p className="section-note">通知最多保留 500 条；列表按最新优先，自动刷新每 30 秒一次。</p>
        </Col>

        <Col xs={24} xl={7}>
          <Card title="来源分布">
            {bySource.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />
            ) : (
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                {bySource.map(s => {
                  const max = Math.max(...bySource.map(x => x.count), 1);
                  return (
                    <div key={s.label}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                        <Text>{s.label}</Text>
                        <Text type="secondary">{s.count}</Text>
                      </div>
                      <Progress percent={Math.round((s.count / max) * 100)} showInfo={false} size="small" strokeColor="#5b5bd6" />
                    </div>
                  );
                })}
              </Space>
            )}
          </Card>

          <Card title="触发规则" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={RULES}
              rowKey="action"
              size="small"
              pagination={false}
              columns={[
                { title: '事件', dataIndex: 'action', width: 150, render: (v: string) => <Text code style={{ fontSize: 11 }}>{v}</Text> },
                { title: '触发条件', dataIndex: 'trigger' },
              ]}
            />
          </Card>

          <Card title="告警渠道" style={{ marginTop: 16 }}>
            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              <div className="setting-tile">
                <div>
                  <div className="s-title">站内通知</div>
                  <div className="s-desc">顶部铃铛徽标 + 本页列表，始终开启。</div>
                </div>
                <Tag color="green">已启用</Tag>
              </div>
              <div className="setting-tile">
                <div>
                  <div className="s-title">Webhook</div>
                  <div className="s-desc">把同一事件推送到 Slack / Telegram / 自建系统。</div>
                </div>
                <Button size="small" onClick={() => { window.location.href = '/ui/integrations'; }}>配置</Button>
              </div>
              <div className="setting-tile">
                <div>
                  <div className="s-title">投递失败提醒</div>
                  <div className="s-desc">失败的 Webhook 会在这里生成一条警告。</div>
                </div>
                <WarningOutlined style={{ color: '#f79009', fontSize: 18 }} />
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={14}>
          <Card title="通知生命周期">
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                { title: '事件产生', description: '配置保存、账号变更、密钥操作、Webhook 投递失败或系统维护。' },
                { title: '写入站内', description: '按级别写入 notifications 表，并同步生成审计记录（如适用）。' },
                { title: '外部推送', description: '启用的 Webhook 按订阅事件异步投递，失败会反向生成警告通知。' },
                { title: '已读与清理', description: '可单条或全部标记已读；最多保留 500 条，超出后自动淘汰最旧记录。' },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title="级别约定" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={[
                { level: '信息', color: 'blue', desc: '常规变更，例如配置保存成功、账号创建。' },
                { level: '警告', color: 'orange', desc: '需要关注但不影响服务，例如 Webhook 投递失败。' },
                { level: '错误', color: 'red', desc: '影响功能的异常，例如数据源同步失败。' },
              ]}
              rowKey="level"
              size="small"
              pagination={false}
              columns={[
                { title: '级别', dataIndex: 'level', width: 80, render: (v: string, r: any) => <Tag color={r.color}>{v}</Tag> },
                { title: '使用场景', dataIndex: 'desc' },
              ]}
            />
            <p className="section-note" style={{ padding: '0 16px' }}>
              通知不替代审计日志：前者用于提醒，后者用于追溯，两者的保留策略相互独立。
            </p>
          </Card>
        </Col>
      </Row>
    </>
  );
};

export default Notifications;

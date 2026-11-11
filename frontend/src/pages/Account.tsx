import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Form,
  Input,
  message,
  Progress,
  Row,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  ClockCircleOutlined,
  HistoryOutlined,
  IdcardOutlined,
  KeyOutlined,
  LockOutlined,
  LoginOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { AuditEntry, errorText, fmtTime, getJSON, postJSON } from '../api';
import { useSession } from '../session';
import { useApiError } from '../hooks';
import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const decodeJWT = (token: string): Record<string, any> | null => {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(decodeURIComponent(escape(atob(padded))));
  } catch {
    return null;
  }
};

const passwordStrength = (pw: string) => {
  if (!pw) return { score: 0, label: '未输入', color: '#cbd5e1' };
  let score = Math.min(40, pw.length * 3);
  if (/[a-z]/.test(pw)) score += 10;
  if (/[A-Z]/.test(pw)) score += 12;
  if (/\d/.test(pw)) score += 12;
  if (/[^A-Za-z0-9]/.test(pw)) score += 16;
  if (pw.length >= 14) score += 10;
  score = Math.min(100, score);
  const label = score >= 80 ? '强' : score >= 55 ? '中' : '弱';
  const color = score >= 80 ? '#12b76a' : score >= 55 ? '#f79009' : '#f04438';
  return { score, label, color };
};

const Account: React.FC = () => {
  const { token, me, logout } = useSession();
  const navigate = useNavigate();
  const fail = useApiError();
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(true);
  const [now, setNow] = useState(Date.now());
  const [pw, setPw] = useState('');
  const isAdmin = me.role === 'admin';

  const claims = useMemo(() => decodeJWT(token), [token]);
  const exp = claims?.exp ? Number(claims.exp) * 1000 : 0;
  const iat = claims?.iat ? Number(claims.iat) * 1000 : 0;
  const remaining = exp ? Math.max(0, exp - now) : 0;
  const totalLife = exp && iat ? exp - iat : 12 * 3600 * 1000;
  const lifePct = totalLife ? Math.max(0, Math.min(100, Math.round((remaining / totalLife) * 100))) : 0;
  const hours = Math.floor(remaining / 3600000);
  const minutes = Math.floor((remaining % 3600000) / 60000);

  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const rows = await getJSON<AuditEntry[]>(
          `/api/audit?username=${encodeURIComponent(me.username)}&limit=8`,
          token,
        );
        setEvents(rows || []);
      } catch (err) {
        // A viewer may still read the audit log; only surface real failures.
        if (loadingEvents) fail(err);
      } finally {
        setLoadingEvents(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const strength = passwordStrength(pw);

  const submit = async () => {
    let values: any;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    setSaving(true);
    try {
      await postJSON('/api/me/password', token, {
        old_password: values.old_password,
        new_password: values.new_password,
      });
      message.success('密码已更新，下次登录请使用新密码');
      form.resetFields();
      setPw('');
    } catch (err) {
      message.error('修改失败：' + errorText(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <PageHeader
        title="我的账户"
        description="查看当前登录身份并轮换密码。账号由管理员创建，权限角色无法自行修改。"
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="角色" value={isAdmin ? '管理员' : '只读用户'} prefix={<SafetyCertificateOutlined />} valueStyle={{ fontSize: 22, color: isAdmin ? '#d97706' : '#2563eb' }} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="会话剩余" value={exp ? `${hours}h ${minutes}m` : '—'} prefix={<ClockCircleOutlined />} valueStyle={{ color: lifePct > 25 ? '#059669' : '#d97706', fontSize: 22 }} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="最近登录" value={me.last_login ? fmtTime(me.last_login) : '首次'} valueStyle={{ fontSize: 16 }} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="我的审计记录" value={events.length} suffix="条" prefix={<HistoryOutlined />} /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
              <Avatar
                size={64}
                style={{
                  background: isAdmin
                    ? 'linear-gradient(135deg,#f59e0b,#ef4444)'
                    : 'linear-gradient(135deg,#6366f1,#22d3ee)',
                  fontWeight: 700,
                  fontSize: 26,
                }}
              >
                {me.username.slice(0, 1).toUpperCase()}
              </Avatar>
              <div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{me.username}</div>
                <Space size={6} style={{ marginTop: 4 }}>
                  <Tag color={isAdmin ? 'gold' : 'blue'}>{isAdmin ? '管理员' : '只读用户'}</Tag>
                  {me.disabled ? <Tag color="red">已禁用</Tag> : <Tag color="green">正常</Tag>}
                </Space>
              </div>
            </div>

            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label={<Space size={6}><IdcardOutlined /> 账号 ID</Space>}>
                <span className="mono">{me.id}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<Space size={6}><UserOutlined /> 用户名</Space>}>
                {me.username}
              </Descriptions.Item>
              <Descriptions.Item label={<Space size={6}><SafetyCertificateOutlined /> 角色</Space>}>
                <span className="mono">{me.role}</span>
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">{fmtTime(me.created_at)}</Descriptions.Item>
              <Descriptions.Item label="最近登录">{fmtTime(me.last_login)}</Descriptions.Item>
            </Descriptions>

            <Divider />

            <Paragraph type="secondary" style={{ marginBottom: 12 }}>
              退出登录只会清除本机保存的令牌，不会影响其他设备。
            </Paragraph>
            <Button danger icon={<LockOutlined />} onClick={logout}>退出当前会话</Button>
          </Card>

          <Card title="令牌状态" style={{ marginTop: 16 }}>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="签发时间">{iat ? fmtTime(new Date(iat).toISOString()) : '—'}</Descriptions.Item>
              <Descriptions.Item label="过期时间">{exp ? fmtTime(new Date(exp).toISOString()) : '—'}</Descriptions.Item>
              <Descriptions.Item label="算法">{claims?.alg || 'HS256'}</Descriptions.Item>
              <Descriptions.Item label="主体">{String(claims?.sub ?? claims?.username ?? me.username)}</Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 10 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>有效期剩余</Text>
              <Progress percent={lifePct} strokeColor={lifePct > 25 ? '#12b76a' : '#f04438'} size="small" format={() => `${hours}h ${minutes}m`} />
            </div>
            <p className="section-note" style={{ marginBottom: 0 }}>
              JWT 为无状态令牌，服务端不保存会话；退出后如需立即作废，可修改密码或由管理员禁用账号。
            </p>
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card title={<Space size={8}><KeyOutlined style={{ color: '#6366f1' }} /> 修改密码</Space>}>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 18 }}
              message="需要验证当前密码"
              description="新密码至少 5 个字符，使用 PBKDF2-SHA256 加盐存储。修改后已签发的令牌在过期前仍然有效。"
            />
            <Form form={form} layout="vertical" style={{ maxWidth: 420 }} onValuesChange={v => { if ('new_password' in v) setPw(v.new_password || ''); }}>
              <Form.Item
                name="old_password"
                label="当前密码"
                rules={[{ required: true, message: '请输入当前密码' }]}
              >
                <Input.Password autoComplete="current-password" placeholder="验证身份" />
              </Form.Item>
              <Form.Item
                name="new_password"
                label="新密码"
                rules={[
                  { required: true, message: '请输入新密码' },
                  { min: 5, max: 128, message: '密码长度为 5-128 个字符' },
                ]}
              >
                <Input.Password autoComplete="new-password" placeholder="至少 5 个字符" />
              </Form.Item>
              <div style={{ marginTop: -12, marginBottom: 16, maxWidth: 420 }}>
                <Progress percent={strength.score} size="small" strokeColor={strength.color} format={() => strength.label} />
                <Text type="secondary" style={{ fontSize: 12 }}>
                  建议混合大小写、数字与符号，长度 14 位以上。
                </Text>
              </div>
              <Form.Item
                name="confirm"
                label="确认新密码"
                dependencies={['new_password']}
                rules={[
                  { required: true, message: '请再次输入新密码' },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue('new_password') === value) return Promise.resolve();
                      return Promise.reject(new Error('两次输入的新密码不一致'));
                    },
                  }),
                ]}
              >
                <Input.Password autoComplete="new-password" placeholder="再次输入" />
              </Form.Item>
              <Form.Item style={{ marginBottom: 0 }}>
                <Button type="primary" onClick={submit} loading={saving} icon={<KeyOutlined />}>
                  更新密码
                </Button>
              </Form.Item>
            </Form>
          </Card>

          <Card title="权限与快捷入口" style={{ marginTop: 16 }}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="回显接口">读取请求、指纹与 IP 情报</Descriptions.Item>
              <Descriptions.Item label="查询日志">查看与导出</Descriptions.Item>
              <Descriptions.Item label="配置修改">{isAdmin ? '允许' : '只读，不允许'}</Descriptions.Item>
              <Descriptions.Item label="账号与密钥">{isAdmin ? '允许' : '只读，不允许'}</Descriptions.Item>
              <Descriptions.Item label="系统维护">轮换密钥、清理日志、备份仅管理员可操作</Descriptions.Item>
            </Descriptions>
            <Space wrap style={{ marginTop: 16 }}>
              <Button onClick={() => navigate('/logs')}>查询日志</Button>
              <Button onClick={() => navigate('/docs')}>API 文档</Button>
              <Button onClick={() => navigate('/security')}>安全策略</Button>
            </Space>
            <Paragraph type="secondary" style={{ margin: '16px 0 0' }}>
              控制台账号只用于管理界面。<Text code>/echo</Text> 对外调用是否需要额外令牌，由
              <Text code>访问控制</Text> 页决定；两者互不影响。
            </Paragraph>
          </Card>
        </Col>
      </Row>

      <Card title={<Space><LoginOutlined /> 我的操作记录</Space>} style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
        <Table
          dataSource={events}
          rowKey="id"
          size="small"
          loading={loadingEvents}
          pagination={false}
          locale={{ emptyText: '还没有与该账号关联的审计记录' }}
          columns={[
            { title: '时间', dataIndex: 'ts', width: 180, render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text> },
            { title: '动作', dataIndex: 'action', width: 180, render: (v: string) => <Tag color={v.startsWith('security') ? 'red' : v.startsWith('user') ? 'purple' : 'blue'}>{v}</Tag> },
            { title: '对象', dataIndex: 'target', width: 220, render: (v: string) => <span className="mono">{v || '—'}</span> },
            { title: '详情', dataIndex: 'detail', ellipsis: true },
            { title: '来源 IP', dataIndex: 'ip', width: 160, render: (v: string) => <span className="mono">{v || '—'}</span> },
          ]}
        />
        <p className="section-note" style={{ padding: '0 16px' }}>
          只展示最近 8 条与当前账号相关的记录；完整审计日志在「审计日志」页。
        </p>
      </Card>
    </>
  );
};

export default Account;

import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  message,
  Modal,
  Popconfirm,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Steps,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  DeleteOutlined,
  EditOutlined,
  LockOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  TeamOutlined,
  UserAddOutlined,
  UserOutlined,
  UserSwitchOutlined,
} from '@ant-design/icons';
import { AuditEntry, Config, User, deleteJSON, errorText, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const roleTag = (role: string) =>
  role === 'admin' ? <Tag color="gold">管理员</Tag> : <Tag color="blue">只读用户</Tag>;

const PERMISSIONS = [
  { area: '查看仪表盘 / 监控 / 日志', admin: '✓', viewer: '✓' },
  { area: '查看配置与回显设置', admin: '✓', viewer: '✓' },
  { area: '查看请求头中的敏感值', admin: '✓', viewer: '*** 掩码' },
  { area: '修改配置 / 访问控制', admin: '✓', viewer: '✗' },
  { area: '创建 / 编辑 / 删除账号', admin: '✓', viewer: '✗' },
  { area: '签发 / 停用 API Key', admin: '✓', viewer: '✗' },
  { area: '导出日志 / 备份数据库', admin: '✓', viewer: '✓（只读导出）' },
  { area: '清空日志 / 维护模式', admin: '✓', viewer: '✗' },
];

const Users: React.FC = () => {
  const { token, me } = useSession();
  const fail = useApiError();
  const [users, setUsers] = useState<User[]>([]);
  const [events, setEvents] = useState<AuditEntry[]>([]);
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [loading, setLoading] = useState(true);
  const [regSaving, setRegSaving] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [saving, setSaving] = useState(false);
  const [q, setQ] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [form] = Form.useForm();

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [list, cfg, audit] = await Promise.all([
        getJSON<User[]>('/api/users', token),
        getJSON<Config>('/api/config', token),
        getJSON<AuditEntry[]>('/api/audit?action=user.&limit=10', token).catch(() => []),
      ]);
      setUsers(list || []);
      setAllowRegistration(cfg.allow_registration === 'true');
      setEvents(audit || []);
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

  const filtered = useMemo(
    () =>
      users.filter(u => {
        if (roleFilter && u.role !== roleFilter) return false;
        if (statusFilter === 'active' && u.disabled) return false;
        if (statusFilter === 'disabled' && !u.disabled) return false;
        const s = q.trim().toLowerCase();
        return !s || u.username.toLowerCase().includes(s);
      }),
    [users, q, roleFilter, statusFilter],
  );

  const stats = useMemo(() => {
    const admins = users.filter(u => u.role === 'admin').length;
    const disabled = users.filter(u => u.disabled).length;
    const active = users.length - disabled;
    return { total: users.length, admins, viewers: users.length - admins, disabled, active };
  }, [users]);

  const toggleRegistration = async (enabled: boolean) => {
    setRegSaving(true);
    try {
      await postJSON('/api/config', token, { allow_registration: enabled ? 'true' : 'false' });
      setAllowRegistration(enabled);
      message.success(enabled ? '已开放自助注册（新账号为只读）' : '已关闭自助注册');
    } catch (err) {
      fail(err);
    } finally {
      setRegSaving(false);
    }
  };

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ role: 'viewer', disabled: false });
    setModalOpen(true);
  };

  const openEdit = (u: User) => {
    setEditing(u);
    form.setFieldsValue({
      username: u.username,
      role: u.role,
      disabled: !!u.disabled,
      password: '',
    });
    setModalOpen(true);
  };

  const submit = async () => {
    let values: any;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    const body: any = {
      username: (values.username || '').trim(),
      role: values.role || 'viewer',
      disabled: !!values.disabled,
    };
    if (values.password) body.password = values.password;
    setSaving(true);
    try {
      await postJSON('/api/users', token, body);
      message.success(editing ? '账号已更新' : '账号已创建');
      setModalOpen(false);
      await load(true);
    } catch (err) {
      message.error('保存失败：' + errorText(err));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (u: User) => {
    try {
      await deleteJSON(`/api/users?username=${encodeURIComponent(u.username)}`, token);
      message.success('账号已删除');
      await load(true);
    } catch (err) {
      fail(err);
    }
  };

  return (
    <>
      <PageHeader
        title="用户管理"
        description="管理控制台账号与权限。管理员拥有全部写权限，只读用户只能查看，所有写操作由服务端拒绝。"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建账号</Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="账号总数" value={stats.total} prefix={<TeamOutlined />} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="管理员" value={stats.admins} prefix={<SafetyCertificateOutlined />} valueStyle={{ color: '#d97706' }} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card"><Statistic title="只读用户" value={stats.viewers} prefix={<UserOutlined />} valueStyle={{ color: '#2563eb' }} /></Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="stat-card">
            <Statistic title="启用 / 禁用" value={stats.active} suffix={`/ ${stats.disabled}`} prefix={<UserSwitchOutlined />} />
          </Card>
        </Col>
      </Row>

      <Card style={{ marginBottom: 16 }} styles={{ body: { padding: '16px 20px' } }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 20, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <div className="stat-icon green" style={{ width: 38, height: 38, fontSize: 17 }}><UserAddOutlined /></div>
            <div>
              <Space size={8}>
                <Text strong>允许访客自助注册</Text>
                <Tag color={allowRegistration ? 'green' : 'default'}>{allowRegistration ? '已开放' : '已关闭'}</Tag>
              </Space>
              <Paragraph type="secondary" style={{ margin: '2px 0 0', fontSize: 12 }}>
                关闭时只能由管理员在这里创建账号；开放后登录页出现注册入口，新账号固定为只读用户。
              </Paragraph>
            </div>
          </div>
          <Switch checked={allowRegistration} loading={regSaving} onChange={toggleRegistration} />
        </div>
      </Card>

      {users.length === 0 && !loading && (
        <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="当前没有账号，请至少保留一个启用的管理员。" />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card
            title={<Space><TeamOutlined /> 账号列表</Space>}
            styles={{ body: { paddingTop: 16 } }}
          >
            <Space wrap style={{ marginBottom: 14 }}>
              <Input
                allowClear
                prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                placeholder="搜索用户名"
                style={{ width: 220 }}
                value={q}
                onChange={e => setQ(e.target.value)}
              />
              <Select
                allowClear
                placeholder="全部角色"
                style={{ width: 150 }}
                value={roleFilter || undefined}
                onChange={v => setRoleFilter(v || '')}
                options={[
                  { value: 'admin', label: '管理员' },
                  { value: 'viewer', label: '只读用户' },
                ]}
              />
              <Select
                allowClear
                placeholder="全部状态"
                style={{ width: 150 }}
                value={statusFilter || undefined}
                onChange={v => setStatusFilter(v || '')}
                options={[
                  { value: 'active', label: '正常' },
                  { value: 'disabled', label: '已禁用' },
                ]}
              />
              <Text type="secondary" style={{ fontSize: 12 }}>显示 {filtered.length} / {users.length}</Text>
            </Space>

            <Table
              dataSource={filtered}
              rowKey="username"
              loading={loading}
              pagination={{ pageSize: 12, hideOnSinglePage: true }}
              scroll={{ x: 860 }}
              size="middle"
              columns={[
                {
                  title: '用户',
                  dataIndex: 'username',
                  render: (v: string, r: User) => (
                    <Space size={10}>
                      <Avatar size={32} style={{ background: r.role === 'admin' ? 'linear-gradient(135deg,#f59e0b,#ef4444)' : 'linear-gradient(135deg,#6366f1,#22d3ee)', fontWeight: 700 }}>
                        {v.slice(0, 1).toUpperCase()}
                      </Avatar>
                      <div>
                        <div style={{ fontWeight: 600 }}>
                          {v}
                          {v === me.username && <Tag style={{ marginLeft: 6 }}>当前</Tag>}
                        </div>
                        <Text type="secondary" style={{ fontSize: 11 }}>ID {r.id}</Text>
                      </div>
                    </Space>
                  ),
                },
                { title: '角色', dataIndex: 'role', width: 110, render: (v: string) => roleTag(v) },
                {
                  title: '状态',
                  dataIndex: 'disabled',
                  width: 92,
                  render: (v: boolean) => (v ? <Tag color="red">已禁用</Tag> : <Tag color="green">正常</Tag>),
                },
                { title: '创建时间', dataIndex: 'created_at', width: 172, render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text> },
                { title: '最近登录', dataIndex: 'last_login', width: 172, render: (v: string) => <Text type="secondary">{fmtTime(v)}</Text> },
                {
                  title: '操作',
                  width: 130,
                  render: (_: unknown, r: User) => (
                    <Space size={2}>
                      <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
                      <Popconfirm
                        title={`删除账号「${r.username}」？`}
                        description="该账号的登录令牌会立即失效。"
                        onConfirm={() => remove(r)}
                        disabled={r.username === me.username}
                      >
                        <Button
                          size="small"
                          type="text"
                          danger
                          icon={<DeleteOutlined />}
                          disabled={r.username === me.username}
                        />
                      </Popconfirm>
                    </Space>
                  ),
                },
              ]}
            />
            <p className="section-note">
              系统至少保留一个启用的管理员；管理员不能删除或禁用自己的账号。密码使用 PBKDF2-SHA256（21 万次迭代）加盐存储。
            </p>
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card title="角色权限矩阵" styles={{ body: { padding: 0 } }}>
            <Table
              dataSource={PERMISSIONS}
              rowKey="area"
              size="small"
              pagination={false}
              columns={[
                { title: '能力', dataIndex: 'area' },
                { title: '管理员', dataIndex: 'admin', width: 74, render: (v: string) => <Text style={{ color: v === '✓' ? '#12b76a' : '#f04438' }}>{v}</Text> },
                { title: '只读', dataIndex: 'viewer', width: 92, render: (v: string) => <Text style={{ color: v.startsWith('✓') ? '#12b76a' : v.startsWith('✗') ? '#f04438' : '#94a3b8', fontSize: 12 }}>{v}</Text> },
              ]}
            />
          </Card>

          <Card title="最近账号操作" style={{ marginTop: 16 }} styles={{ body: { padding: '6px 0' } }}>
            {events.length === 0 ? (
              <div className="empty-pad muted" style={{ textAlign: 'center' }}>暂无账号操作记录</div>
            ) : (
              events.map(e => (
                <div className="provider-row" key={e.id} style={{ padding: '8px 16px' }}>
                  <div>
                    <div className="provider-name">{e.action}</div>
                    <div className="provider-meta">{e.target || e.username} · {fmtTime(e.ts)}</div>
                  </div>
                  <Tag color={e.action.includes('delete') ? 'red' : e.action.includes('create') ? 'green' : 'blue'}>
                    {e.username}
                  </Tag>
                </div>
              ))
            )}
          </Card>

          <Card title="账号策略" style={{ marginTop: 16 }}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="密码"><Space size={6}><LockOutlined />PBKDF2-SHA256 · 21 万次迭代</Space></Descriptions.Item>
              <Descriptions.Item label="登录态">JWT HS256，12 小时过期</Descriptions.Item>
              <Descriptions.Item label="禁用效果">现有令牌立即失效，无法再登录</Descriptions.Item>
              <Descriptions.Item label="自助注册">默认关闭，开启后新账号为只读</Descriptions.Item>
              <Descriptions.Item label="最小管理员">至少保留一个启用状态的管理员</Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 12 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>启用比例</Text>
              <Progress
                percent={stats.total ? Math.round((stats.active / stats.total) * 100) : 0}
                strokeColor="#12b76a"
                size="small"
              />
            </div>
          </Card>
        </Col>
      </Row>

      <Card title="账号开通与初始化" style={{ marginTop: 16 }}>
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={14}>
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                { title: '首个管理员', description: '首次访问控制台时通过初始化向导创建，角色固定为管理员。' },
                { title: '关闭自助注册', description: '默认关闭；公网实例建议保持关闭，由管理员统一创建账号。' },
                { title: '分配只读账号', description: '为查看日志 / 监控的同事创建 viewer，敏感值自动掩码。' },
                { title: '定期复核', description: '在审计日志中按 user. 前缀检查创建、改密与删除记录。' },
              ]}
            />
          </Col>
          <Col xs={24} xl={10}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="初始密码">创建时必填，至少 5 个字符</Descriptions.Item>
              <Descriptions.Item label="重置密码">编辑账号时留空表示不修改</Descriptions.Item>
              <Descriptions.Item label="禁用与删除">禁用即时生效；删除后令牌立即失效</Descriptions.Item>
              <Descriptions.Item label="自我保护">不能删除或禁用当前登录账号</Descriptions.Item>
              <Descriptions.Item label="注册入口">仅 allow_registration=true 时登录页显示</Descriptions.Item>
            </Descriptions>
          </Col>
        </Row>
      </Card>

      <Modal
        title={editing ? `编辑账号 · ${editing.username}` : '新建账号'}
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={submit}
        confirmLoading={saving}
        okText={editing ? '保存修改' : '创建账号'}
        width={480}
        destroyOnClose
      >
        <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
          <Form.Item
            name="username"
            label="用户名"
            rules={[
              { required: true, message: '请填写用户名' },
              { min: 3, max: 32, message: '用户名长度为 3-32 个字符' },
              { pattern: /^[A-Za-z0-9._-]+$/, message: '只能使用字母、数字、点、下划线或短横线' },
            ]}
          >
            <Input disabled={!!editing} placeholder="3-32 位，字母 / 数字 / . _ -" />
          </Form.Item>
          <Form.Item
            name="password"
            label={editing ? '重置密码（留空则不修改）' : '初始密码'}
            rules={editing
              ? [{ min: 5, max: 128, message: '密码长度为 5-128 个字符' }]
              : [
                  { required: true, message: '请填写初始密码' },
                  { min: 5, max: 128, message: '密码长度为 5-128 个字符' },
                ]}
          >
            <Input.Password placeholder={editing ? '留空保持原密码' : '至少 5 个字符'} autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="role" label="角色">
            <Select
              options={[
                { value: 'viewer', label: '只读用户 · 仅查看控制台' },
                { value: 'admin', label: '管理员 · 全部权限' },
              ]}
            />
          </Form.Item>
          <Form.Item name="disabled" label="禁用账号" valuePropName="checked">
            <Switch disabled={editing?.username === me.username} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

export default Users;

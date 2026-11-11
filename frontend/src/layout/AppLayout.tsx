import React, { useEffect, useMemo, useState } from 'react';
import { Avatar, Badge, Button, Drawer, Dropdown, Grid, Input, Layout, Menu, Modal, Tag } from 'antd';
import type { MenuProps } from 'antd';
import {
  ApiOutlined,
  AuditOutlined,
  BellOutlined,
  BookOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  GlobalOutlined,
  HistoryOutlined,
  LineChartOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  PartitionOutlined,
  SafetyCertificateOutlined,
  ScanOutlined,
  SearchOutlined,
  SettingOutlined,
  TeamOutlined,
  ToolOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { User } from '../api';
import { SessionCtx } from '../session';

const { Header, Sider, Content } = Layout;

const PAGE_META: Record<string, { title: string; sub: string }> = {
  '/': { title: '概览', sub: '服务状态、趋势、通知与最近活动' },
  '/echo': { title: '回显设置', sub: '控制 /echo 响应中暴露的字段与默认格式' },
  '/ip': { title: 'IP 情报', sub: '地理位置、ASN 与代理类型的在线查询配置' },
  '/datasets': { title: '数据源', sub: 'JA4 指纹库、CIDR 表与关键词库的 Provider' },
  '/chain': { title: 'IP 查询链路', sub: '按优先级串联云端 API、本地命令与内置驱动' },
  '/fingerprints': { title: 'JA4 指纹库', sub: '跨 Provider 搜索指纹与客户端分布' },
  '/monitor': { title: '监控分析', sub: '请求趋势、来源分布与系统资源' },
  '/logs': { title: '查询日志', sub: '筛选、导出、保存视图与重放请求' },
  '/audit': { title: '审计日志', sub: '配置、账号与安全操作的变更记录' },
  '/notifications': { title: '通知中心', sub: '站内事件与 Webhook 投递异常' },
  '/users': { title: '用户管理', sub: '账号、角色、密码与自助注册策略' },
  '/access': { title: '访问控制', sub: '回显接口的鉴权方式与共享 API Token' },
  '/security': { title: '安全与防护', sub: 'API Key、IP 规则、限流与维护模式' },
  '/integrations': { title: '集成与 Webhook', sub: '事件订阅、签名投递与运维下载' },
  '/system': { title: '系统设置', sub: '站点标识、功能开关、运行时与导出' },
  '/docs': { title: 'API 文档', sub: '端点清单、鉴权方式与 OpenAPI' },
  '/tools': { title: '工具箱', sub: 'CIDR、哈希、JWT、curl 等本地工具' },
  '/account': { title: '我的账户', sub: '个人资料与密码安全' },
};

const MENU_ITEMS: { key: string; label: string; icon: React.ReactNode; admin?: boolean }[] = [
  { key: '/', label: '概览', icon: <DashboardOutlined /> },
  { key: '/echo', label: '回显设置', icon: <ApiOutlined /> },
  { key: '/ip', label: 'IP 情报', icon: <GlobalOutlined /> },
  { key: '/datasets', label: '数据源', icon: <DatabaseOutlined /> },
  { key: '/chain', label: 'IP 查询链路', icon: <PartitionOutlined /> },
  { key: '/fingerprints', label: 'JA4 指纹库', icon: <ScanOutlined /> },
  { key: '/monitor', label: '监控分析', icon: <LineChartOutlined /> },
  { key: '/logs', label: '查询日志', icon: <HistoryOutlined /> },
  { key: '/audit', label: '审计日志', icon: <AuditOutlined /> },
  { key: '/notifications', label: '通知中心', icon: <BellOutlined /> },
  { key: '/users', label: '用户管理', icon: <TeamOutlined />, admin: true },
  { key: '/access', label: '访问控制', icon: <SafetyCertificateOutlined /> },
  { key: '/security', label: '安全与防护', icon: <SafetyCertificateOutlined /> },
  { key: '/integrations', label: '集成与 Webhook', icon: <ApiOutlined />, admin: true },
  { key: '/system', label: '系统设置', icon: <SettingOutlined /> },
  { key: '/docs', label: 'API 文档', icon: <BookOutlined /> },
  { key: '/tools', label: '工具箱', icon: <ToolOutlined /> },
  { key: '/account', label: '我的账户', icon: <UserOutlined /> },
];

interface Props {
  token: string;
  me: User;
  onLogout: () => void;
}

const AppLayout: React.FC<Props> = ({ token, me, onLogout }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [siteName, setSiteName] = useState('Echo Server');
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState('');
  const screens = Grid.useBreakpoint();
  const mobile = !screens.lg;
  const navigate = useNavigate();
  const location = useLocation();
  const isAdmin = me.role === 'admin';

  // Unread badge; refreshed on navigation and every minute.
  useEffect(() => {
    let cancelled = false;
    const refresh = () =>
      fetch('/api/notifications?unread=1&limit=1', { headers: { Authorization: 'Bearer ' + token } })
        .then(res => (res.ok ? res.json() : null))
        .then((data: { unread?: number } | null) => {
          if (!cancelled && data) setUnread(data.unread || 0);
        })
        .catch(() => undefined);
    refresh();
    const timer = window.setInterval(refresh, 60000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [token, location.pathname]);

  // Operator-defined site name (falls back to the product name).
  useEffect(() => {
    fetch('/api/config', { headers: { Authorization: 'Bearer ' + token } })
      .then(res => (res.ok ? res.json() : null))
      .then((cfg: Record<string, string> | null) => {
        const name = cfg?.site_name?.trim();
        if (name) {
          setSiteName(name);
          document.title = name + ' · 控制台';
        }
      })
      .catch(() => undefined);
  }, [token]);

  // Ctrl/Cmd+K opens the command palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(v => !v);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const items: MenuProps['items'] = useMemo(
    () => [
      { key: '/', icon: <DashboardOutlined />, label: '概览' },
      { key: '/echo', icon: <ApiOutlined />, label: '回显设置' },
      { key: '/ip', icon: <GlobalOutlined />, label: 'IP 情报' },
      {
        type: 'group',
        label: '数据与链路',
        children: [
          { key: '/datasets', icon: <DatabaseOutlined />, label: '数据源' },
          { key: '/chain', icon: <PartitionOutlined />, label: 'IP 查询链路' },
          { key: '/fingerprints', icon: <ScanOutlined />, label: 'JA4 指纹库' },
        ],
      },
      {
        type: 'group',
        label: '可观测',
        children: [
          { key: '/monitor', icon: <LineChartOutlined />, label: '监控分析' },
          { key: '/logs', icon: <HistoryOutlined />, label: '查询日志' },
          { key: '/audit', icon: <AuditOutlined />, label: '审计日志' },
          { key: '/notifications', icon: <BellOutlined />, label: '通知中心' },
        ],
      },
      {
        type: 'group',
        label: '系统',
        children: [
          ...(isAdmin ? [{ key: '/users', icon: <TeamOutlined />, label: '用户管理' }] : []),
          { key: '/access', icon: <SafetyCertificateOutlined />, label: '访问控制' },
          { key: '/security', icon: <SafetyCertificateOutlined />, label: '安全与防护' },
          ...(isAdmin ? [{ key: '/integrations', icon: <ApiOutlined />, label: '集成与 Webhook' }] : []),
          { key: '/system', icon: <SettingOutlined />, label: '系统设置' },
        ],
      },
      { key: '/docs', icon: <BookOutlined />, label: 'API 文档' },
      { key: '/tools', icon: <ToolOutlined />, label: '工具箱' },
      { key: '/account', icon: <UserOutlined />, label: '我的账户' },
    ],
    [isAdmin],
  );

  const meta = PAGE_META[location.pathname] || { title: '控制台', sub: '' };
  const ctx: SessionCtx = { token, me, canEdit: isAdmin, logout: onLogout };

  const go = (key: string) => {
    navigate(key);
    setDrawerOpen(false);
    setPaletteOpen(false);
    setPaletteQuery('');
  };

  const paletteItems = MENU_ITEMS.filter(m => !m.admin || isAdmin).filter(m => {
    const q = paletteQuery.trim().toLowerCase();
    if (!q) return true;
    return (m.label + ' ' + m.key).toLowerCase().includes(q);
  });

  const brand = (
    <div className="sider-brand" onClick={() => go('/')}>
      <div className="brand-mark">E</div>
      {!collapsed && (
        <div className="brand-text">
          <strong>{siteName}</strong>
          <span>REQUEST INTELLIGENCE</span>
        </div>
      )}
    </div>
  );

  const siderBody = (
    <>
      {brand}
      <div className="sider-status">
        <span className="status-dot" />
        {!collapsed && <span>服务运行中</span>}
      </div>
      <Menu
        theme="light"
        mode="inline"
        selectedKeys={[location.pathname]}
        items={items}
        onClick={({ key }) => go(key)}
      />
      {!mobile && (
        <Button
          className="sider-collapse"
          icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
          onClick={() => setCollapsed(v => !v)}
        >
          {collapsed ? null : '收起菜单'}
        </Button>
      )}
    </>
  );

  const userMenu: MenuProps = {
    items: [
      { key: 'account', icon: <UserOutlined />, label: '我的账户', onClick: () => navigate('/account') },
      { key: 'docs', icon: <BookOutlined />, label: 'API 文档', onClick: () => navigate('/docs') },
      { type: 'divider' },
      { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true, onClick: onLogout },
    ],
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {!mobile && (
        <Sider width={248} collapsedWidth={76} collapsed={collapsed} trigger={null} className="app-sider">
          {siderBody}
        </Sider>
      )}

      <Drawer
        placement="left"
        width={264}
        open={mobile && drawerOpen}
        onClose={() => setDrawerOpen(false)}
        closable={false}
        styles={{ body: { padding: 0, background: '#ffffff' } }}
      >
        {siderBody}
      </Drawer>

      <Layout>
        <Header className="app-header">
          <div className="header-left">
            {mobile && (
              <Button type="text" icon={<MenuUnfoldOutlined />} onClick={() => setDrawerOpen(true)} />
            )}
            <div>
              <div className="header-title">{meta.title}</div>
              {meta.sub && <div className="header-sub">{meta.sub}</div>}
            </div>
          </div>

          <div className="header-right">
            {!mobile && (
              <Button type="text" icon={<SearchOutlined />} onClick={() => setPaletteOpen(true)} title="Ctrl+K">
                快速跳转
              </Button>
            )}
            <Badge count={unread} size="small" offset={[-2, 2]}>
              <Button type="text" icon={<BellOutlined />} onClick={() => navigate('/notifications')} title="通知中心" />
            </Badge>
            <Tag color={isAdmin ? 'gold' : 'blue'} style={{ marginInlineEnd: 0 }}>
              {isAdmin ? '管理员' : '只读账号'}
            </Tag>
            <Dropdown menu={userMenu} trigger={['click']} placement="bottomRight">
              <div className="user-chip">
                <Avatar
                  size={32}
                  style={{ background: 'linear-gradient(135deg,#6366f1,#22d3ee)', fontWeight: 700 }}
                >
                  {me.username.slice(0, 1).toUpperCase()}
                </Avatar>
                <div>
                  <div className="user-chip-name">{me.username}</div>
                  <div className="user-chip-role">{isAdmin ? '管理员' : '只读'}</div>
                </div>
              </div>
            </Dropdown>
          </div>
        </Header>

        <Content className="app-content">
          <Outlet context={ctx} />
        </Content>
      </Layout>

      <Modal
        title="快速跳转"
        open={paletteOpen}
        onCancel={() => setPaletteOpen(false)}
        footer={null}
        width={520}
        destroyOnClose
      >
        <Input
          autoFocus
          prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
          placeholder="输入页面名称，例如 日志 / 安全 / 指纹"
          value={paletteQuery}
          onChange={e => setPaletteQuery(e.target.value)}
          onPressEnter={() => paletteItems[0] && go(paletteItems[0].key)}
        />
        <div style={{ marginTop: 12, maxHeight: 360, overflow: 'auto' }}>
          {paletteItems.length === 0 ? (
            <div className="empty-pad muted" style={{ textAlign: 'center' }}>没有匹配的页面</div>
          ) : (
            paletteItems.map(m => (
              <div
                key={m.key}
                className="provider-row"
                style={{ cursor: 'pointer', padding: '10px 6px' }}
                onClick={() => go(m.key)}
              >
                <div className="provider-name">{m.icon} {m.label}</div>
                <span className="mono muted">{m.key}</span>
              </div>
            ))
          )}
        </div>
        <p className="section-note">按 Ctrl / ⌘ + K 随时打开；回车进入第一项。</p>
      </Modal>
    </Layout>
  );
};

export default AppLayout;

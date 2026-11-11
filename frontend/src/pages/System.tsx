import React, { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Form,
  Input,
  InputNumber,
  message,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  CloudDownloadOutlined,
  DatabaseOutlined,
  ReloadOutlined,
  SaveOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { Config, SystemInfo, downloadFile, fmtBytes, fmtDuration, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const TIMEZONES = [
  'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore', 'Asia/Tokyo', 'UTC',
  'Europe/London', 'Europe/Berlin', 'America/New_York', 'America/Los_Angeles',
];

const System: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [cfg, setCfg] = useState<Config>({});
  const [sys, setSys] = useState<SystemInfo | null>(null);
  const [env, setEnv] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [c, s, e] = await Promise.all([
        getJSON<Config>('/api/config', token),
        getJSON<SystemInfo>('/api/system', token),
        canEdit ? getJSON<Record<string, string>>('/api/system/environment', token).catch(() => ({})) : Promise.resolve({}),
      ]);
      setCfg(c || {});
      setSys(s);
      setEnv(e || {});
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

  const save = async (patch: Record<string, string>, label: string) => {
    setSaving(true);
    try {
      await postJSON('/api/config', token, patch);
      message.success(label + '已保存');
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setSaving(false);
    }
  };

  const download = async (path: string, name: string) => {
    try {
      await downloadFile(path, token, name);
      message.success('开始下载');
    } catch (err) {
      fail(err);
    }
  };

  // show_* keys default to enabled when unset; only an explicit "false" disables them.
  const bool = (k: string) => cfg[k] !== 'false';
  const setBool = (k: string) => setCfg(prev => ({ ...prev, [k]: prev[k] !== 'false' ? 'false' : 'true' }));

  const showToggles = [
    ['show_ip', 'IP 与地理位置', '关闭后响应中省略 ip 对象'],
    ['show_ja3', 'TLS JA3', '关闭后省略 JA3 字符串与哈希'],
    ['show_client', '客户端识别', '关闭后省略 client 推断结果'],
    ['show_ja4h', 'HTTP JA4H', '关闭后省略 HTTP 层指纹'],
    ['show_raw', '原始 ClientHello', '关闭后不返回 base64 / hex 原始数据'],
    ['show_body', '请求体回显', '关闭后响应中的 body 恒为空'],
    ['enable_online_geo', '在线地理查询', '关闭后只使用本地数据与缓存'],
  ];

  return (
    <>
      <PageHeader
        title="系统设置"
        description="站点标识、时区、功能开关、运行时信息与数据导出。危险操作集中在「安全与防护」页面。"
        extra={<Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>}
      />

      <Spin spinning={loading}>
        <Row gutter={[16, 16]}>
          <Col xs={24} xl={14}>
            <Card title={<Space><SettingOutlined /> 站点与本地化</Space>}>
              <Form layout="vertical">
                <Row gutter={12}>
                  <Col xs={24} md={12}>
                    <Form.Item label="站点名称">
                      <Input disabled={!canEdit} value={cfg.site_name || ''} placeholder="Echo Server" onChange={e => setCfg(p => ({ ...p, site_name: e.target.value }))} />
                    </Form.Item>
                  </Col>
                  <Col xs={24} md={12}>
                    <Form.Item label="时区">
                      <Select
                        disabled={!canEdit}
                        value={cfg.timezone || 'Asia/Shanghai'}
                        onChange={v => setCfg(p => ({ ...p, timezone: v }))}
                        options={TIMEZONES.map(t => ({ value: t, label: t }))}
                      />
                    </Form.Item>
                  </Col>
                </Row>
                <Form.Item label="站点描述">
                  <Input.TextArea rows={2} disabled={!canEdit} value={cfg.site_description || ''} placeholder="显示在登录页与文档中的一句话说明" onChange={e => setCfg(p => ({ ...p, site_description: e.target.value }))} />
                </Form.Item>
                <Row gutter={12}>
                  <Col xs={24} md={12}>
                    <Form.Item label="界面语言">
                      <Select
                        disabled={!canEdit}
                        value={cfg.locale || 'zh-CN'}
                        onChange={v => setCfg(p => ({ ...p, locale: v }))}
                        options={[{ value: 'zh-CN', label: '简体中文' }, { value: 'en-US', label: 'English（预留）' }]}
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24} md={12}>
                    <Form.Item label="界面密度">
                      <Segmented
                        disabled={!canEdit}
                        value={cfg.density || 'default'}
                        onChange={v => setCfg(p => ({ ...p, density: String(v) }))}
                        options={[{ value: 'default', label: '标准' }, { value: 'compact', label: '紧凑' }]}
                      />
                    </Form.Item>
                  </Col>
                </Row>
              </Form>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                disabled={!canEdit}
                loading={saving}
                onClick={() =>
                  save(
                    {
                      site_name: cfg.site_name || '',
                      site_description: cfg.site_description || '',
                      timezone: cfg.timezone || 'Asia/Shanghai',
                      locale: cfg.locale || 'zh-CN',
                      density: cfg.density || 'default',
                    },
                    '站点设置',
                  )
                }
              >
                保存站点设置
              </Button>
              <p className="section-note">语言与密度为界面偏好预留值；当前控制台默认简体中文、标准密度。</p>
            </Card>

            <Card title="回显字段开关" style={{ marginTop: 16 }}>
              {showToggles.map(([key, title, desc]) => (
                <div className="setting-tile" key={key} style={{ marginBottom: 10 }}>
                  <div>
                    <div className="s-title">{title} <Text code>{key}</Text></div>
                    <div className="s-desc">{desc}</div>
                  </div>
                  <Switch disabled={!canEdit} checked={bool(key)} onChange={() => setBool(key)} />
                </div>
              ))}
              <Button
                type="primary"
                icon={<SaveOutlined />}
                disabled={!canEdit}
                loading={saving}
                onClick={() => {
                  const patch: Record<string, string> = {};
                  showToggles.forEach(([key]) => { patch[key] = bool(key) ? 'true' : 'false'; });
                  save(patch, '回显字段');
                }}
              >
                保存字段开关
              </Button>
            </Card>
          </Col>

          <Col xs={24} xl={10}>
            <Card title="运行时信息">
              {sys ? (
                <Descriptions column={1} size="small" bordered>
                  <Descriptions.Item label="版本"><Tag color="blue">{sys.version}</Tag></Descriptions.Item>
                  {sys.build_commit && (
                    <Descriptions.Item label="构建提交"><span className="mono">{sys.build_commit.slice(0, 12)}</span></Descriptions.Item>
                  )}
                  {sys.build_date && (
                    <Descriptions.Item label="构建时间">{fmtTime(sys.build_date)}</Descriptions.Item>
                  )}
                  <Descriptions.Item label="Go 运行时">{sys.go_version}</Descriptions.Item>
                  <Descriptions.Item label="平台">{sys.os} / {sys.arch} · {sys.cpus} vCPU</Descriptions.Item>
                  <Descriptions.Item label="启动时间">{new Date(sys.started_at).toLocaleString('zh-CN', { hour12: false })}</Descriptions.Item>
                  <Descriptions.Item label="运行时长">{fmtDuration(sys.uptime_seconds)}</Descriptions.Item>
                  <Descriptions.Item label="协程 / GC">{sys.goroutines} / {sys.gc_cycles}</Descriptions.Item>
                  <Descriptions.Item label="内存">{fmtBytes(sys.memory_alloc)} / {fmtBytes(sys.memory_sys)}</Descriptions.Item>
                  <Descriptions.Item label="监听端口">HTTPS {sys.https_port} · HTTP {sys.http_port}</Descriptions.Item>
                  <Descriptions.Item label="数据库">{fmtBytes(sys.db_size)}</Descriptions.Item>
                  <Descriptions.Item label="数据库路径"><span className="mono" style={{ wordBreak: 'break-all' }}>{sys.db_path}</span></Descriptions.Item>
                  <Descriptions.Item label="维护模式">{sys.maintenance ? <Tag color="warning">开启</Tag> : <Tag color="success">关闭</Tag>}</Descriptions.Item>
                </Descriptions>
              ) : <Text type="secondary">加载中…</Text>}
            </Card>

            <Card title="数据导出" style={{ marginTop: 16 }}>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/export/logs.csv?limit=10000', 'query-logs.csv')}>查询日志 CSV</Button>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/export/logs.json?limit=10000', 'query-logs.json')}>查询日志 JSON</Button>
                <Button block icon={<CloudDownloadOutlined />} onClick={() => download('/api/audit/export.csv?limit=2000', 'audit-log.csv')}>审计日志 CSV</Button>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/export/users.csv', 'users.csv')}>账号 CSV</Button>
                <Button block icon={<CloudDownloadOutlined />} disabled={!canEdit} onClick={() => download('/api/export/users.json', 'users.json')}>账号 JSON</Button>
                <Button block type="primary" ghost icon={<DatabaseOutlined />} disabled={!canEdit} onClick={() => download('/api/system/backup', 'echo-server-backup.db')}>SQLite 全量备份</Button>
              </Space>
              <Alert style={{ marginTop: 12 }} type="info" showIcon message="备份包含账号哈希与配置，请按敏感数据处理。" />
            </Card>
          </Col>
        </Row>

        {canEdit && (
          <Card title="环境变量与非敏感配置" style={{ marginTop: 16 }}>
            <Table
              dataSource={Object.entries(env).map(([key, value]) => ({ key, value }))}
              rowKey="key"
              size="small"
              pagination={false}
              columns={[
                { title: '键', dataIndex: 'key', width: 240, render: (v: string) => <span className="mono">{v}</span> },
                { title: '值', dataIndex: 'value', render: (v: string) => <span className="mono" style={{ wordBreak: 'break-all' }}>{v || <Text type="secondary">（空）</Text>}</span> },
              ]}
            />
            <Divider />
            <Paragraph type="secondary" style={{ marginBottom: 0 }}>
              回显日志保留天数当前为 <Text code>{cfg.log_retention_days || '不限制'}</Text>；
              维护模式、IP 列表、限流与密钥轮换请前往 <Text code>/ui/security</Text>。
            </Paragraph>
          </Card>
        )}
      </Spin>
    </>
  );
};

export default System;

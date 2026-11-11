import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Input,
  InputNumber,
  message,
  Progress,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CloudDownloadOutlined,
  ExperimentOutlined,
  GlobalOutlined,
  ReloadOutlined,
  SaveOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Config, Dataset, IPProvider, errorText, fmtTime, getJSON, postJSON } from '../api';
import { useApiError } from '../hooks';
import { useSession } from '../session';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const FIELDS = [
  { field: 'asn / org', desc: '自治系统号与运营组织，用于识别云厂商、机房或住宅宽带。' },
  { field: 'country / country_code', desc: '国家名称与 ISO 两位代码，日志筛选与聚合的主维度。' },
  { field: 'region / city / postal', desc: '省州、城市与邮编；精度取决于数据源，可能为空。' },
  { field: 'latitude / longitude', desc: '经纬度，仅在线高精度来源返回；离线模式留空。' },
  { field: 'timezone / utc_offset', desc: 'IANA 时区与 UTC 偏移，便于还原调用方本地时间。' },
  { field: 'connection_type', desc: 'datacenter / residential_proxy / unknown，由本地 CIDR 表与隐私标签共同判定。' },
  { field: 'geo_source', desc: '实际命中的 Provider 或 local；用于确认数据可信度。' },
];

const IPIntel: React.FC = () => {
  const { token, canEdit } = useSession();
  const fail = useApiError();
  const [cfg, setCfg] = useState<Config>({});
  const [chain, setChain] = useState<IPProvider[]>([]);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testIP, setTestIP] = useState('8.8.8.8');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const [c, p, d] = await Promise.all([
        getJSON<Config>('/api/config', token),
        getJSON<IPProvider[]>('/api/ipproviders', token).catch(() => []),
        getJSON<Dataset[]>('/api/datasets', token).catch(() => []),
      ]);
      setCfg(c || {});
      setChain(p || []);
      setDatasets(d || []);
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

  const online = cfg.enable_online_geo !== 'false' && cfg.enable_online_geo !== '';
  const enabledChain = chain.filter(p => p.enabled);
  const healthyChain = enabledChain.filter(p => p.status === 'ok');

  const localEntries = useMemo(() => {
    let n = 0;
    datasets.forEach(d => {
      if (d.name === 'datacenter_cidr' || d.name === 'residential_proxy_cidr' || d.name === 'datacenter_orgs') {
        (d.providers || []).forEach(p => { n += p.entries || 0; });
      }
    });
    return n;
  }, [datasets]);

  const successRate = useMemo(() => {
    const calls = chain.reduce((n, p) => n + p.calls, 0);
    const ok = chain.reduce((n, p) => n + p.successes, 0);
    return calls ? Math.round((ok / calls) * 1000) / 10 : 100;
  }, [chain]);

  const save = async () => {
    setSaving(true);
    try {
      const payload: Config = {
        enable_online_geo: online ? 'true' : 'false',
        geo_provider: cfg.geo_provider || 'auto',
        geo_cache_ttl: cfg.geo_cache_ttl || '24',
        ipinfo_token: cfg.ipinfo_token === '***' ? '' : cfg.ipinfo_token || '',
      };
      await postJSON('/api/config', token, payload);
      setCfg(prev => ({ ...prev, ...payload }));
      message.success('IP 情报设置已保存');
    } catch (err) {
      fail(err);
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    if (!testIP.trim()) {
      message.warning('请输入要测试的 IP');
      return;
    }
    setTesting(true);
    setTestResult('');
    try {
      const res = await postJSON<any>('/api/ipproviders/test', token, { ip: testIP.trim() });
      setTestResult(JSON.stringify(res, null, 2));
    } catch (err) {
      setTestResult('查询失败：' + errorText(err));
    } finally {
      setTesting(false);
    }
  };

  return (
    <>
      <PageHeader
        title="IP 情报"
        description="为回显结果补充 ASN、地理位置与代理类型。在线查询失败会自动降级到下一个来源，离线模式完全不出网。"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>重新加载</Button>
            {canEdit && <Button type="primary" icon={<SaveOutlined />} onClick={save} loading={saving}>保存设置</Button>}
          </Space>
        }
      />

      {!canEdit && <Alert type="info" showIcon style={{ marginBottom: 16 }} message="只读账号：可以查看配置与链路状态，不能修改。" />}

      <Spin spinning={loading}>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={12} lg={6}>
            <Card className="stat-card">
              <Statistic
                title="在线查询"
                value={online ? '已启用' : '离线'}
                valueStyle={{ color: online ? '#059669' : '#d97706', fontSize: 22 }}
              />
            </Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="链路 Provider" value={enabledChain.length} suffix={`/ ${chain.length}`} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card"><Statistic title="本地 CIDR 条目" value={localEntries} /></Card>
          </Col>
          <Col xs={12} lg={6}>
            <Card className="stat-card">
              <Statistic
                title="链路成功率"
                value={successRate}
                suffix="%"
                valueStyle={{ color: successRate >= 90 ? '#059669' : '#d97706' }}
              />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]}>
          <Col xs={24} lg={15}>
            <Card title="在线查询">
              <div className="setting-tile" style={{ marginBottom: 18 }}>
                <div>
                  <div className="s-title"><GlobalOutlined style={{ color: '#6366f1', marginRight: 8 }} />启用在线 IP 情报</div>
                  <div className="s-desc">关闭后只使用本地 CIDR 表，任何回显请求都不会触发外部查询。</div>
                </div>
                <Switch
                  disabled={!canEdit}
                  checked={online}
                  onChange={v => setCfg(prev => ({ ...prev, enable_online_geo: v ? 'true' : 'false' }))}
                />
              </div>

              {!online && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 18 }}
                  message="当前处于离线模式"
                  description="不会发起外部请求，只保留本地数据中心与住宅代理 CIDR 判定。"
                />
              )}

              <Paragraph style={{ marginBottom: 6 }} type="secondary">数据源选择</Paragraph>
              <Select
                style={{ width: '100%', maxWidth: 420 }}
                disabled={!canEdit || !online}
                value={cfg.geo_provider || 'auto'}
                onChange={v => setCfg(prev => ({ ...prev, geo_provider: v }))}
                options={[
                  { value: 'auto', label: '自动 · 按优先级尝试全部已启用 Provider' },
                  { value: 'ipwhois', label: 'ipwho.is · 免费，含经纬度' },
                  { value: 'ipapi', label: 'ip-api.com · 免费，含经纬度' },
                  { value: 'ipinfo', label: 'ipinfo.io · Token 时高精度 + 隐私标签' },
                  { value: 'offline', label: '离线 · 仅本地 CIDR 表' },
                ]}
              />
              <p className="section-note">
                实际查询顺序由 <Text code>IP 查询链路</Text> 页的 Provider 优先级决定；这里的下拉是兼容旧配置的偏好设置。
              </p>

              <Divider />

              <Row gutter={16}>
                <Col xs={24} md={12}>
                  <div className="setting-tile" style={{ display: 'block', height: '100%' }}>
                    <div>
                      <div className="s-title"><CloudDownloadOutlined style={{ marginRight: 6 }} />缓存策略</div>
                      <div className="s-desc">相同 IP 在 TTL 内复用结果，避免免费接口被限流；回显主流程不会因为上游变慢而阻塞。</div>
                      <div style={{ marginTop: 10 }}>
                        <Text type="secondary">当前 TTL：</Text>
                        <Text strong>{Number(cfg.geo_cache_ttl) || 24} 小时</Text>
                      </div>
                    </div>
                  </div>
                </Col>
                <Col xs={24} md={12}>
                  <div className="setting-tile" style={{ display: 'block', height: '100%' }}>
                    <div>
                      <div className="s-title"><ExperimentOutlined style={{ marginRight: 6 }} />失败降级</div>
                      <div className="s-desc">超时、限流或无结果会记录到该 Provider 的统计并自动尝试下一条链路，最终无结果时字段保持为空。</div>
                    </div>
                  </div>
                </Col>
              </Row>
            </Card>

            <Card title="Provider 健康" style={{ marginTop: 16 }} styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={chain}
                rowKey="name"
                size="small"
                pagination={false}
                scroll={{ x: 620 }}
                locale={{ emptyText: '链路尚未初始化' }}
                columns={[
                  {
                    title: 'Provider', dataIndex: 'name', width: 150,
                    render: (v: string, r) => (
                      <Space size={6}>
                        <strong>{v}</strong>
                        {r.builtin && <Tag style={{ marginInlineEnd: 0 }}>内置</Tag>}
                      </Space>
                    ),
                  },
                  { title: '优先级', dataIndex: 'priority', width: 70 },
                  {
                    title: '状态', dataIndex: 'status', width: 92,
                    render: (v: string, r) => (
                      <Tag color={!r.enabled ? 'default' : r.gated ? 'purple' : v === 'ok' ? 'success' : v === 'error' ? 'error' : 'warning'}>
                        {!r.enabled ? '停用' : r.gated ? '已拦截' : v || '待命'}
                      </Tag>
                    ),
                  },
                  {
                    title: '成功率', width: 150,
                    render: (_: unknown, r) => {
                      const pct = r.calls ? Math.round((r.successes / r.calls) * 100) : 0;
                      return <Progress percent={pct} size="small" strokeColor={pct >= 90 ? '#12b76a' : pct >= 50 ? '#f79009' : '#f04438'} />;
                    },
                  },
                  { title: '平均耗时', dataIndex: 'avg_ms', width: 90, render: (v: number, r) => (r.calls ? `${(v || 0).toFixed(0)} ms` : '—') },
                  { title: '最近成功', dataIndex: 'last_success', width: 150, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{fmtTime(v)}</Text> },
                ]}
              />
            </Card>
          </Col>

          <Col xs={24} lg={9}>
            <Card title="凭据与缓存">
              <Paragraph type="secondary" style={{ marginBottom: 6 }}>ipinfo Token（可选）</Paragraph>
              <Input.Password
                disabled={!canEdit}
                value={cfg.ipinfo_token || ''}
                placeholder="启用街区级经纬度与 proxy / vpn / tor 标签"
                onChange={e => setCfg(prev => ({ ...prev, ipinfo_token: e.target.value }))}
              />
              <p className="section-note">Token 不会返回给只读账号；管理接口中显示为 ***。</p>

              <div style={{ height: 20 }} />

              <Paragraph type="secondary" style={{ marginBottom: 6 }}>结果缓存时长</Paragraph>
              <Space>
                <InputNumber
                  min={1}
                  max={720}
                  disabled={!canEdit}
                  value={Number(cfg.geo_cache_ttl) || 24}
                  onChange={v => setCfg(prev => ({ ...prev, geo_cache_ttl: String(v || 24) }))}
                />
                <Text type="secondary">小时</Text>
              </Space>
              <p className="section-note">缓存可显著减少免费接口调用；过期后重新查询。</p>

              <Divider />

              <div className="setting-tile" style={{ background: '#f8fafc' }}>
                <div>
                  <div className="s-title"><CloudDownloadOutlined style={{ marginRight: 8 }} />降级策略</div>
                  <div className="s-desc">某个来源限流、超时或无结果时，链路自动尝试下一个 Provider，不影响回显主流程。</div>
                </div>
              </div>
            </Card>

            <Card title="链路测试" style={{ marginTop: 16 }} extra={<ExperimentOutlined style={{ color: '#6366f1' }} />}>
              <Paragraph type="secondary" style={{ fontSize: 12 }}>
                绕过结果缓存，立即用当前链路查询一个 IP。写操作需要管理员权限。
              </Paragraph>
              <Space.Compact style={{ width: '100%' }}>
                <Input value={testIP} onChange={e => setTestIP(e.target.value)} placeholder="8.8.8.8" onPressEnter={runTest} />
                <Button type="primary" icon={<ThunderboltOutlined />} loading={testing} disabled={!canEdit} onClick={runTest}>测试</Button>
              </Space.Compact>
              <pre className="code-block" style={{ marginTop: 12, maxHeight: 220 }}>{testResult || '结果显示最终胜出的 Provider 与归一化字段'}</pre>
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
          <Col xs={24} xl={15}>
            <Card title="返回字段说明" styles={{ body: { padding: 0 } }}>
              <Table
                dataSource={FIELDS}
                rowKey="field"
                size="small"
                pagination={false}
                columns={[
                  { title: '字段', dataIndex: 'field', width: 240, render: (v: string) => <span className="mono">{v}</span> },
                  { title: '含义', dataIndex: 'desc' },
                ]}
              />
            </Card>
          </Col>
          <Col xs={24} xl={9}>
            <Card title="隐私与合规">
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="外发内容">仅查询 IP 本身，不携带请求头或请求体</Descriptions.Item>
                <Descriptions.Item label="数据源">ipwho.is / ip-api.com / ipinfo.io（可替换）</Descriptions.Item>
                <Descriptions.Item label="离线模式">完全不出网，仅本地 CIDR 判定</Descriptions.Item>
                <Descriptions.Item label="失败处理">字段留空并标记 geo_source=local，不编造坐标</Descriptions.Item>
              </Descriptions>
              <p className="section-note" style={{ marginBottom: 0 }}>
                对隐私敏感的部署建议关闭在线查询，并通过「数据源」页面挂载自有 CIDR 表。
              </p>
            </Card>
          </Col>
        </Row>
      </Spin>
    </>
  );
};

export default IPIntel;

import React, { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Input,
  InputNumber,
  message,
  Progress,
  Row,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import { CopyOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons';
import PageHeader from '../components/PageHeader';

const { Text, Paragraph } = Typography;

const copy = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    message.success('已复制');
  } catch {
    message.warning('浏览器不允许自动复制');
  }
};

const bytesToHex = (buf: ArrayBuffer) =>
  Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');

const ipv4ToInt = (ip: string): number | null => {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
};

const intToIpv4 = (n: number) => [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join('.');

const CidrTool: React.FC = () => {
  const [value, setValue] = useState('192.168.1.10/24');
  const info = useMemo(() => {
    const [ip, p] = value.trim().split('/');
    const base = ipv4ToInt(ip || '');
    const prefix = Number(p);
    if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const network = (base & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const size = 2 ** (32 - prefix);
    const usable = prefix === 32 ? 1 : prefix === 31 ? 2 : Math.max(0, size - 2);
    return {
      ip, prefix, network: intToIpv4(network), broadcast: intToIpv4(broadcast), mask: intToIpv4(mask),
      wildcard: intToIpv4(~mask >>> 0), size, usable,
      first: prefix >= 31 ? intToIpv4(network) : intToIpv4(network + 1),
      last: prefix >= 31 ? intToIpv4(broadcast) : intToIpv4(broadcast - 1),
    };
  }, [value]);

  return (
    <Row gutter={16}>
      <Col xs={24} lg={10}>
        <Card title="输入 IPv4 网段">
          <Input value={value} onChange={e => setValue(e.target.value)} placeholder="192.168.1.10/24" className="mono" />
          <p className="section-note">支持 /0 ~ /32，自动计算网络地址、广播地址与可用主机范围。</p>
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Card title="计算结果">
          {!info ? <Alert type="error" showIcon message="请输入合法的 IPv4 CIDR，例如 10.0.0.0/8" /> : (
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="网络地址"><span className="mono">{info.network}</span></Descriptions.Item>
              <Descriptions.Item label="广播地址"><span className="mono">{info.broadcast}</span></Descriptions.Item>
              <Descriptions.Item label="子网掩码"><span className="mono">{info.mask}</span></Descriptions.Item>
              <Descriptions.Item label="反掩码"><span className="mono">{info.wildcard}</span></Descriptions.Item>
              <Descriptions.Item label="首个可用"><span className="mono">{info.first}</span></Descriptions.Item>
              <Descriptions.Item label="最后可用"><span className="mono">{info.last}</span></Descriptions.Item>
              <Descriptions.Item label="地址总数">{info.size.toLocaleString()}</Descriptions.Item>
              <Descriptions.Item label="可用主机">{info.usable.toLocaleString()}</Descriptions.Item>
            </Descriptions>
          )}
          <p className="section-note">/31 与 /32 按点到点语义计算可用地址；结果仅适用于 IPv4。</p>
        </Card>
      </Col>
    </Row>
  );
};

const IpConvertTool: React.FC = () => {
  const [ip, setIp] = useState('8.8.8.8');
  const [num, setNum] = useState('134744072');
  const fromIp = ipv4ToInt(ip);
  const fromNum = Number(num);
  return (
    <Row gutter={16}>
      <Col xs={24} lg={12}>
        <Card title="IPv4 → 整数 / 十六进制 / 二进制">
          <Input value={ip} onChange={e => setIp(e.target.value)} className="mono" placeholder="8.8.8.8" />
          <pre className="code-block" style={{ marginTop: 12 }}>
            {fromIp === null ? '非法 IPv4' : [
              `十进制: ${fromIp}`,
              `十六进制: 0x${fromIp.toString(16).toUpperCase().padStart(8, '0')}`,
              `二进制: ${fromIp.toString(2).padStart(32, '0').replace(/(.{8})(?=.)/g, '$1.')}`,
            ].join('\n')}
          </pre>
        </Card>
      </Col>
      <Col xs={24} lg={12}>
        <Card title="整数 → IPv4">
          <Input value={num} onChange={e => setNum(e.target.value)} className="mono" placeholder="134744072" />
          <pre className="code-block" style={{ marginTop: 12 }}>
            {!Number.isInteger(fromNum) || fromNum < 0 || fromNum > 0xffffffff
              ? '请输入 0 ~ 4294967295 的整数'
              : `IPv4: ${intToIpv4(fromNum >>> 0)}`}
          </pre>
        </Card>
      </Col>
    </Row>
  );
};

const HashTool: React.FC = () => {
  const [input, setInput] = useState('');
  const [out, setOut] = useState<Record<string, string>>({});
  const [secret, setSecret] = useState('');
  const [hmac, setHmac] = useState('');

  const run = async () => {
    const data = new TextEncoder().encode(input);
    const result: Record<string, string> = {};
    for (const alg of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
      result[alg] = bytesToHex(await crypto.subtle.digest(alg, data));
    }
    setOut(result);
  };

  const runHMAC = async () => {
    if (!secret) {
      message.warning('请填写 HMAC 密钥');
      return;
    }
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
    setHmac(bytesToHex(sig));
  };

  return (
    <Card title="文本哈希（浏览器本地计算，内容不会上传）">
      <Input.TextArea rows={4} value={input} onChange={e => setInput(e.target.value)} placeholder="输入任意文本" />
      <Space style={{ marginTop: 12 }} wrap>
        <Button type="primary" icon={<ThunderboltOutlined />} onClick={run}>计算 SHA-1/256/384/512</Button>
        <Input.Password style={{ width: 220 }} placeholder="HMAC-SHA256 密钥" value={secret} onChange={e => setSecret(e.target.value)} />
        <Button onClick={runHMAC}>计算 HMAC</Button>
      </Space>
      {Object.keys(out).length > 0 && (
        <div style={{ marginTop: 14 }}>
          {Object.entries(out).map(([alg, value]) => (
            <div key={alg} style={{ marginBottom: 10 }}>
              <Space><Tag color="blue">{alg}</Tag><Button size="small" icon={<CopyOutlined />} onClick={() => copy(value)}>复制</Button></Space>
              <pre className="code-block" style={{ marginTop: 4, whiteSpace: 'break-all' }}>{value}</pre>
            </div>
          ))}
        </div>
      )}
      {hmac && (
        <div style={{ marginTop: 10 }}>
          <Tag color="purple">HMAC-SHA256</Tag>
          <pre className="code-block" style={{ whiteSpace: 'break-all' }}>{hmac}</pre>
        </div>
      )}
    </Card>
  );
};

const Base64Tool: React.FC = () => {
  const [plain, setPlain] = useState('');
  const [encoded, setEncoded] = useState('');
  const [error, setError] = useState('');

  const encode = () => {
    const bytes = new TextEncoder().encode(plain);
    let binary = '';
    bytes.forEach(b => { binary += String.fromCharCode(b); });
    setEncoded(btoa(binary));
    setError('');
  };
  const decode = () => {
    try {
      const binary = atob(encoded.trim());
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      setPlain(new TextDecoder().decode(bytes));
      setError('');
    } catch {
      setError('不是合法的 Base64 字符串');
    }
  };

  return (
    <Card title="Base64 编解码（UTF-8）">
      <Row gutter={16}>
        <Col xs={24} lg={12}>
          <Input.TextArea rows={5} value={plain} onChange={e => setPlain(e.target.value)} placeholder="原始文本" />
          <Button type="primary" style={{ marginTop: 10 }} onClick={encode}>编码 →</Button>
        </Col>
        <Col xs={24} lg={12}>
          <Input.TextArea rows={5} value={encoded} onChange={e => setEncoded(e.target.value)} placeholder="Base64" className="mono" />
          <Space style={{ marginTop: 10 }}>
            <Button onClick={decode}>← 解码</Button>
            <Button icon={<CopyOutlined />} onClick={() => copy(encoded)}>复制</Button>
          </Space>
        </Col>
      </Row>
      {error && <Alert style={{ marginTop: 12 }} type="error" showIcon message={error} />}
    </Card>
  );
};

const UrlTool: React.FC = () => {
  const [raw, setRaw] = useState('');
  const [enc, setEnc] = useState('');
  return (
    <Card title="URL 编解码">
      <Input.TextArea rows={3} value={raw} onChange={e => setRaw(e.target.value)} placeholder="原始文本 / 参数" />
      <Space style={{ marginTop: 10 }} wrap>
        <Button type="primary" onClick={() => setEnc(encodeURIComponent(raw))}>encodeURIComponent</Button>
        <Button onClick={() => { try { setRaw(decodeURIComponent(enc)); } catch { message.error('不是合法的 URL 编码'); } }}>解码到上方</Button>
        <Button icon={<CopyOutlined />} onClick={() => copy(enc)}>复制结果</Button>
      </Space>
      <Input.TextArea style={{ marginTop: 10 }} rows={3} value={enc} onChange={e => setEnc(e.target.value)} placeholder="编码结果" className="mono" />
    </Card>
  );
};

const JsonTool: React.FC = () => {
  const [text, setText] = useState('{"hello":"world","n":1}');
  const [err, setErr] = useState('');
  const format = (spaces: number) => {
    try {
      setText(JSON.stringify(JSON.parse(text), null, spaces));
      setErr('');
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Card title="JSON 格式化 / 压缩 / 校验">
      <Input.TextArea rows={9} value={text} onChange={e => setText(e.target.value)} className="mono" />
      <Space style={{ marginTop: 10 }} wrap>
        <Button type="primary" onClick={() => format(2)}>格式化</Button>
        <Button onClick={() => format(0)}>压缩</Button>
        <Button onClick={() => { try { JSON.parse(text); setErr(''); message.success('JSON 合法'); } catch (e) { setErr((e as Error).message); } }}>校验</Button>
        <Button icon={<CopyOutlined />} onClick={() => copy(text)}>复制</Button>
      </Space>
      {err && <Alert style={{ marginTop: 12 }} type="error" showIcon message={err} />}
    </Card>
  );
};

const TimeTool: React.FC = () => {
  const [value, setValue] = useState(String(Math.floor(Date.now() / 1000)));
  const parsed = (() => {
    const n = Number(value.trim());
    if (!Number.isFinite(n)) return null;
    const ms = value.trim().length > 10 ? n : n * 1000;
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return null;
    return { iso: d.toISOString(), local: d.toLocaleString('zh-CN', { hour12: false }), utc: d.toUTCString(), ms };
  })();
  return (
    <Card title="Unix 时间戳转换">
      <Space.Compact style={{ width: '100%', maxWidth: 520 }}>
        <Input value={value} onChange={e => setValue(e.target.value)} className="mono" placeholder="秒或毫秒时间戳" />
        <Button onClick={() => setValue(String(Math.floor(Date.now() / 1000)))}>现在</Button>
      </Space.Compact>
      <pre className="code-block" style={{ marginTop: 12 }}>
        {!parsed ? '无法解析时间戳' : [
          `ISO 8601: ${parsed.iso}`,
          `本地时间: ${parsed.local}`,
          `UTC: ${parsed.utc}`,
          `毫秒: ${parsed.ms}`,
          `秒: ${Math.floor(parsed.ms / 1000)}`,
        ].join('\n')}
      </pre>
      <p className="section-note">10 位按秒解释，13 位按毫秒解释。</p>
    </Card>
  );
};

const TokenTool: React.FC = () => {
  const [len, setLen] = useState(32);
  const [charset, setCharset] = useState('alnum');
  const [token, setToken] = useState('');
  const sets: Record<string, string> = {
    alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    hex: '0123456789abcdef',
    base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  };
  const gen = () => {
    const chars = sets[charset];
    const bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    setToken(Array.from(bytes, b => chars[b % chars.length]).join(''));
  };
  return (
    <Card title="随机 Token 生成器">
      <Space wrap>
        <InputNumber min={8} max={256} value={len} onChange={v => setLen(Number(v) || 32)} addonAfter="位" />
        <Select value={charset} onChange={setCharset} style={{ width: 180 }} options={[
          { value: 'alnum', label: '字母 + 数字' },
          { value: 'hex', label: '十六进制' },
          { value: 'base64', label: 'Base64 URL-safe' },
        ]} />
        <Button type="primary" onClick={gen}>生成</Button>
        <Button icon={<CopyOutlined />} disabled={!token} onClick={() => copy(token)}>复制</Button>
      </Space>
      <pre className="code-block" style={{ marginTop: 12, whiteSpace: 'break-all' }}>{token || '点击生成，使用 crypto.getRandomValues'}</pre>
    </Card>
  );
};

const JwtTool: React.FC = () => {
  const [raw, setRaw] = useState('');
  const decoded = (() => {
    const parts = raw.trim().split('.');
    if (parts.length < 2) return null;
    try {
      const b64 = (s: string) => {
        const pad = s.replace(/-/g, '+').replace(/_/g, '/');
        return decodeURIComponent(atob(pad + '='.repeat((4 - (pad.length % 4)) % 4)).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
      };
      const header = JSON.parse(b64(parts[0]));
      const payload = JSON.parse(b64(parts[1]));
      const exp = payload.exp ? new Date(payload.exp * 1000) : null;
      return { header, payload, exp, expired: exp ? exp.getTime() < Date.now() : false };
    } catch {
      return null;
    }
  })();
  return (
    <Card title="JWT 解码（仅解析，不校验签名）">
      <Input.TextArea rows={4} value={raw} onChange={e => setRaw(e.target.value)} className="mono" placeholder="粘贴 JWT" />
      {decoded && (
        <>
          <Alert
            style={{ margin: '12px 0' }}
            type={decoded.expired ? 'warning' : 'success'}
            showIcon
            message={decoded.expired ? 'Token 已过期' : 'Token 未过期'}
            description={decoded.exp ? `过期时间：${decoded.exp.toLocaleString('zh-CN', { hour12: false })}` : '没有 exp 字段'}
          />
          <Row gutter={16}>
            <Col xs={24} lg={12}><pre className="code-block">{JSON.stringify(decoded.header, null, 2)}</pre></Col>
            <Col xs={24} lg={12}><pre className="code-block">{JSON.stringify(decoded.payload, null, 2)}</pre></Col>
          </Row>
        </>
      )}
      {raw && !decoded && <Alert style={{ marginTop: 12 }} type="error" showIcon message="无法解析，请检查是否为三段式 JWT" />}
    </Card>
  );
};

const CurlTool: React.FC = () => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://example.com/echo?format=json');
  const [headers, setHeaders] = useState('X-API-Token: <token>');
  const [body, setBody] = useState('');
  const cmd = [
    `curl -X ${method} "${url}"`,
    ...headers.split('\n').filter(Boolean).map(h => `  -H "${h.trim()}"`),
    ...(body.trim() ? [`  -d '${body.replace(/'/g, "'\\''")}'`] : []),
  ].join(' \\\n');
  return (
    <Card title="curl 命令生成器">
      <Row gutter={12}>
        <Col xs={24} md={5}>
          <Select value={method} onChange={setMethod} style={{ width: '100%' }} options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(v => ({ value: v, label: v }))} />
        </Col>
        <Col xs={24} md={19}><Input value={url} onChange={e => setUrl(e.target.value)} /></Col>
      </Row>
      <Input.TextArea style={{ marginTop: 10 }} rows={3} value={headers} onChange={e => setHeaders(e.target.value)} placeholder="每行一个请求头" className="mono" />
      <Input.TextArea style={{ marginTop: 10 }} rows={3} value={body} onChange={e => setBody(e.target.value)} placeholder="请求体（可选）" className="mono" />
      <Space style={{ marginTop: 10 }}><Button icon={<CopyOutlined />} onClick={() => copy(cmd)}>复制命令</Button></Space>
      <pre className="code-block" style={{ marginTop: 10 }}>{cmd}</pre>
    </Card>
  );
};

const UaTool: React.FC = () => {
  const [ua, setUa] = useState(navigator.userAgent);
  const detect = (s: string) => {
    const browser =
      /Edg\/([\d.]+)/.exec(s) ? `Edge ${/Edg\/([\d.]+)/.exec(s)?.[1]}` :
      /Chrome\/([\d.]+)/.exec(s) ? `Chrome ${/Chrome\/([\d.]+)/.exec(s)?.[1]}` :
      /Firefox\/([\d.]+)/.exec(s) ? `Firefox ${/Firefox\/([\d.]+)/.exec(s)?.[1]}` :
      /Version\/([\d.]+).*Safari/.exec(s) ? `Safari ${/Version\/([\d.]+)/.exec(s)?.[1]}` :
      /curl\/([\d.]+)/.exec(s) ? `curl ${/curl\/([\d.]+)/.exec(s)?.[1]}` :
      /Go-http-client\/([\d.]+)/.exec(s) ? `Go http client ${/Go-http-client\/([\d.]+)/.exec(s)?.[1]}` : '未知';
    const os =
      /Windows NT 10/.test(s) ? 'Windows 10/11' :
      /Windows NT/.test(s) ? 'Windows' :
      /iPhone|iPad/.test(s) ? 'iOS / iPadOS' :
      /Android ([\d.]+)/.exec(s) ? `Android ${/Android ([\d.]+)/.exec(s)?.[1]}` :
      /Mac OS X ([\d_]+)/.exec(s) ? `macOS ${(/Mac OS X ([\d_]+)/.exec(s)?.[1] || '').replace(/_/g, '.')}` :
      /Linux/.test(s) ? 'Linux' : '未知';
    const device = /Mobile|iPhone|Android/.test(s) ? '移动端' : /iPad|Tablet/.test(s) ? '平板' : '桌面 / 服务端';
    return { browser, os, device };
  };
  const info = detect(ua);
  return (
    <Card title="User-Agent 解析（简易本地规则）">
      <Input.TextArea rows={3} value={ua} onChange={e => setUa(e.target.value)} className="mono" />
      <Descriptions column={1} bordered size="small" style={{ marginTop: 12 }}>
        <Descriptions.Item label="浏览器 / 客户端">{info.browser}</Descriptions.Item>
        <Descriptions.Item label="操作系统">{info.os}</Descriptions.Item>
        <Descriptions.Item label="设备类型">{info.device}</Descriptions.Item>
        <Descriptions.Item label="长度">{ua.length} 字符</Descriptions.Item>
      </Descriptions>
      <p className="section-note">这里只做常见规则匹配；服务端回显使用了更完整的 UA 与 JA4 联合识别。</p>
    </Card>
  );
};

const UuidTool: React.FC = () => {
  const [count, setCount] = useState(5);
  const [list, setList] = useState<string[]>([]);
  const gen = () => {
    const out: string[] = [];
    for (let i = 0; i < Math.max(1, Math.min(100, count)); i++) {
      if (crypto.randomUUID) {
        out.push(crypto.randomUUID());
      } else {
        const b = new Uint8Array(16);
        crypto.getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        const h = bytesToHex(b.buffer);
        out.push(`${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`);
      }
    }
    setList(out);
  };
  return (
    <Card title="UUID v4 生成器">
      <Space wrap>
        <InputNumber min={1} max={100} value={count} onChange={v => setCount(Number(v) || 1)} addonAfter="个" />
        <Button type="primary" icon={<ReloadOutlined />} onClick={gen}>生成</Button>
        <Button icon={<CopyOutlined />} disabled={!list.length} onClick={() => copy(list.join('\n'))}>复制全部</Button>
      </Space>
      <pre className="code-block" style={{ marginTop: 12, minHeight: 60 }}>{list.length ? list.join('\n') : '点击生成，使用 crypto.randomUUID / getRandomValues'}</pre>
    </Card>
  );
};

const UrlParseTool: React.FC = () => {
  const [raw, setRaw] = useState('https://echo.example.com:8443/echo?format=json&fields=ip.country#result');
  const parsed = useMemo(() => {
    try {
      const u = new URL(raw.trim());
      return { u, params: Array.from(u.searchParams.entries()) };
    } catch {
      return null;
    }
  }, [raw]);
  return (
    <Card title="URL 结构解析">
      <Input value={raw} onChange={e => setRaw(e.target.value)} className="mono" placeholder="https://host/path?a=1" />
      {!parsed ? (
        <Alert style={{ marginTop: 12 }} type="error" showIcon message="不是合法的 URL（需要包含协议）" />
      ) : (
        <>
          <Descriptions column={{ xs: 1, md: 2 }} bordered size="small" style={{ marginTop: 12 }}>
            <Descriptions.Item label="协议"><span className="mono">{parsed.u.protocol.replace(':', '')}</span></Descriptions.Item>
            <Descriptions.Item label="主机"><span className="mono">{parsed.u.hostname}</span></Descriptions.Item>
            <Descriptions.Item label="端口"><span className="mono">{parsed.u.port || '默认'}</span></Descriptions.Item>
            <Descriptions.Item label="路径"><span className="mono">{parsed.u.pathname}</span></Descriptions.Item>
            <Descriptions.Item label="锚点"><span className="mono">{parsed.u.hash || '—'}</span></Descriptions.Item>
            <Descriptions.Item label="来源"><span className="mono">{parsed.u.origin}</span></Descriptions.Item>
          </Descriptions>
          <Table
            style={{ marginTop: 12 }}
            dataSource={parsed.params.map(([k, v], i) => ({ key: i, k, v }))}
            size="small"
            pagination={false}
            locale={{ emptyText: '没有查询参数' }}
            columns={[
              { title: '参数', dataIndex: 'k', width: 200, render: (v: string) => <Text code>{v}</Text> },
              { title: '值', dataIndex: 'v', render: (v: string) => <span className="mono">{v}</span> },
            ]}
          />
        </>
      )}
    </Card>
  );
};

const STATUS_CODES = [
  { code: 100, name: 'Continue', group: '1xx 信息' },
  { code: 101, name: 'Switching Protocols', group: '1xx 信息' },
  { code: 200, name: 'OK', group: '2xx 成功' },
  { code: 201, name: 'Created', group: '2xx 成功' },
  { code: 202, name: 'Accepted', group: '2xx 成功' },
  { code: 204, name: 'No Content', group: '2xx 成功' },
  { code: 206, name: 'Partial Content', group: '2xx 成功' },
  { code: 301, name: 'Moved Permanently', group: '3xx 重定向' },
  { code: 302, name: 'Found', group: '3xx 重定向' },
  { code: 304, name: 'Not Modified', group: '3xx 重定向' },
  { code: 307, name: 'Temporary Redirect', group: '3xx 重定向' },
  { code: 308, name: 'Permanent Redirect', group: '3xx 重定向' },
  { code: 400, name: 'Bad Request', group: '4xx 客户端' },
  { code: 401, name: 'Unauthorized', group: '4xx 客户端' },
  { code: 403, name: 'Forbidden', group: '4xx 客户端' },
  { code: 404, name: 'Not Found', group: '4xx 客户端' },
  { code: 405, name: 'Method Not Allowed', group: '4xx 客户端' },
  { code: 408, name: 'Request Timeout', group: '4xx 客户端' },
  { code: 413, name: 'Payload Too Large', group: '4xx 客户端' },
  { code: 415, name: 'Unsupported Media Type', group: '4xx 客户端' },
  { code: 418, name: "I'm a teapot", group: '4xx 客户端' },
  { code: 429, name: 'Too Many Requests', group: '4xx 客户端' },
  { code: 500, name: 'Internal Server Error', group: '5xx 服务端' },
  { code: 501, name: 'Not Implemented', group: '5xx 服务端' },
  { code: 502, name: 'Bad Gateway', group: '5xx 服务端' },
  { code: 503, name: 'Service Unavailable', group: '5xx 服务端' },
  { code: 504, name: 'Gateway Timeout', group: '5xx 服务端' },
];

const HttpStatusTool: React.FC = () => {
  const [q, setQ] = useState('');
  const rows = STATUS_CODES.filter(s => String(s.code).includes(q.trim()) || s.name.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <Card title="HTTP 状态码速查">
      <Input allowClear value={q} onChange={e => setQ(e.target.value)} placeholder="输入状态码或名称，例如 429 / timeout" style={{ maxWidth: 360 }} />
      <Table
        style={{ marginTop: 12 }}
        dataSource={rows}
        rowKey="code"
        size="small"
        pagination={false}
        columns={[
          { title: '状态码', dataIndex: 'code', width: 90, render: (v: number) => <Tag color={v < 300 ? 'green' : v < 400 ? 'blue' : v < 500 ? 'orange' : 'red'}>{v}</Tag> },
          { title: '名称', dataIndex: 'name', render: (v: string) => <span className="mono">{v}</span> },
          { title: '分类', dataIndex: 'group', width: 120, render: (v: string) => <Text type="secondary">{v}</Text> },
        ]}
      />
      <p className="section-note">服务端典型返回：鉴权失败 401、权限不足 403、限流 429、请求体超限 413、维护模式 503。</p>
    </Card>
  );
};

const RegexTool: React.FC = () => {
  const [pattern, setPattern] = useState('(\\d{1,3}\\.){3}\\d{1,3}');
  const [flags, setFlags] = useState('g');
  const [text, setText] = useState('来自 203.0.113.7 与 198.51.100.9 的请求');
  const result = useMemo(() => {
    try {
      const re = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
      const matches: { index: number; value: string; groups: string[] }[] = [];
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(text)) && guard < 200) {
        matches.push({ index: m.index, value: m[0], groups: m.slice(1) });
        if (m[0] === '') re.lastIndex += 1;
        guard += 1;
      }
      return { matches, error: '' };
    } catch (e) {
      return { matches: [], error: (e as Error).message };
    }
  }, [pattern, flags, text]);
  return (
    <Card title="正则测试器">
      <Space.Compact style={{ width: '100%' }}>
        <Input value={pattern} onChange={e => setPattern(e.target.value)} className="mono" placeholder="正则表达式" />
        <Input value={flags} onChange={e => setFlags(e.target.value)} style={{ width: 100 }} className="mono" placeholder="gim" />
      </Space.Compact>
      <Input.TextArea style={{ marginTop: 10 }} rows={4} value={text} onChange={e => setText(e.target.value)} className="mono" placeholder="测试文本" />
      {result.error ? (
        <Alert style={{ marginTop: 10 }} type="error" showIcon message={result.error} />
      ) : (
        <>
          <div style={{ marginTop: 10 }}>
            <Tag color={result.matches.length ? 'success' : 'default'}>{result.matches.length} 处匹配</Tag>
            {result.matches.length > 0 && (
              <Button size="small" icon={<CopyOutlined />} onClick={() => copy(result.matches.map(m => m.value).join('\n'))}>复制匹配结果</Button>
            )}
          </div>
          {result.matches.length > 0 && (
            <Table
              style={{ marginTop: 10 }}
              dataSource={result.matches.map((m, i) => ({ key: i, ...m, groups: m.groups.join(', ') || '—' }))}
              size="small"
              pagination={{ pageSize: 8, hideOnSinglePage: true }}
              columns={[
                { title: '#', dataIndex: 'key', width: 50, render: (v: number) => v + 1 },
                { title: '位置', dataIndex: 'index', width: 80 },
                { title: '匹配', dataIndex: 'value', render: (v: string) => <span className="mono">{v}</span> },
                { title: '分组', dataIndex: 'groups', render: (v: string) => <Text type="secondary" className="mono">{v}</Text> },
              ]}
            />
          )}
        </>
      )}
      <p className="section-note">最多展示 200 处匹配；始终以全局模式执行，避免死循环。</p>
    </Card>
  );
};

const IpRangeTool: React.FC = () => (
  <Card title="特殊 IPv4 网段速查" styles={{ body: { padding: 0 } }}>
    <Table
      dataSource={[
        { cidr: '0.0.0.0/8', name: '本网络', use: '当前网络，通常不作为来源地址' },
        { cidr: '10.0.0.0/8', name: '私有 A 类', use: '内网，不可路由到公网' },
        { cidr: '100.64.0.0/10', name: 'CGNAT', use: '运营商级 NAT，常见于移动网络' },
        { cidr: '127.0.0.0/8', name: '回环', use: '本机地址' },
        { cidr: '169.254.0.0/16', name: '链路本地', use: 'DHCP 失败 / APIPA' },
        { cidr: '172.16.0.0/12', name: '私有 B 类', use: '内网' },
        { cidr: '192.0.2.0/24', name: '文档示例', use: 'TEST-NET-1，仅用于文档' },
        { cidr: '192.168.0.0/16', name: '私有 C 类', use: '家庭 / 办公内网' },
        { cidr: '198.51.100.0/24', name: '文档示例', use: 'TEST-NET-2' },
        { cidr: '203.0.113.0/24', name: '文档示例', use: 'TEST-NET-3' },
        { cidr: '224.0.0.0/4', name: '组播', use: '组播地址，不会出现在 TCP 来源' },
        { cidr: '240.0.0.0/4', name: '保留', use: '保留段' },
      ]}
      rowKey="cidr"
      size="small"
      pagination={false}
      columns={[
        { title: '网段', dataIndex: 'cidr', width: 160, render: (v: string) => <Text code>{v}</Text> },
        { title: '名称', dataIndex: 'name', width: 120 },
        { title: '用途', dataIndex: 'use' },
      ]}
    />
    <p className="section-note" style={{ padding: '0 16px' }}>
      回显日志中的连接类型由本地 CIDR 表判定，私有网段通常显示 unknown，除非自行补充数据源。
    </p>
  </Card>
);

const PasswordTool: React.FC = () => {
  const [pw, setPw] = useState('');
  const analysis = useMemo(() => {
    const len = pw.length;
    let classes = 0;
    if (/[a-z]/.test(pw)) classes += 1;
    if (/[A-Z]/.test(pw)) classes += 1;
    if (/\d/.test(pw)) classes += 1;
    if (/[^A-Za-z0-9]/.test(pw)) classes += 1;
    let score = Math.min(45, len * 3) + classes * 13;
    if (len >= 12) score += 8;
    if (len >= 16) score += 8;
    if (/^(password|admin|123456|qwerty|letmein)/i.test(pw)) score = Math.min(score, 20);
    score = Math.min(100, score);
    const label = !pw ? '未输入' : score >= 80 ? '强' : score >= 55 ? '中' : '弱';
    const color = !pw ? '#cbd5e1' : score >= 80 ? '#12b76a' : score >= 55 ? '#f79009' : '#f04438';
    const entropy = len * Math.log2(Math.max(classes * 26, 2));
    return { len, classes, score, label, color, entropy: Math.round(entropy) };
  }, [pw]);
  return (
    <Card title="密码强度评估（本地计算）">
      <Input.Password value={pw} onChange={e => setPw(e.target.value)} placeholder="输入待评估的密码，不会上传" style={{ maxWidth: 420 }} />
      <Progress percent={analysis.score} strokeColor={analysis.color} format={() => analysis.label} style={{ maxWidth: 420, marginTop: 12 }} />
      <Descriptions column={3} size="small" bordered style={{ marginTop: 12 }}>
        <Descriptions.Item label="长度">{analysis.len}</Descriptions.Item>
        <Descriptions.Item label="字符类别">{analysis.classes} / 4</Descriptions.Item>
        <Descriptions.Item label="估算熵">{analysis.entropy} bit</Descriptions.Item>
      </Descriptions>
      <p className="section-note">熵值按字符集粗略估算，仅作提示；服务端只要求长度 5–128，实际安全取决于随机性与保管方式。</p>
    </Card>
  );
};

const Stack: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Space direction="vertical" size={16} style={{ width: '100%' }}>{children}</Space>
);

const Tools: React.FC = () => (
  <>
    <PageHeader title="工具箱" description="CIDR、IP 转换、哈希、Base64、JWT、curl 等常用调试工具，全部在浏览器本地计算。" />
    <Tabs
      defaultActiveKey="network"
      items={[
        {
          key: 'network',
          label: '网络与 IP',
          children: (
            <Stack>
              <CidrTool />
              <IpConvertTool />
              <UrlParseTool />
              <IpRangeTool />
            </Stack>
          ),
        },
        {
          key: 'codec',
          label: '编码与格式',
          children: (
            <Stack>
              <Base64Tool />
              <UrlTool />
              <JsonTool />
              <TimeTool />
            </Stack>
          ),
        },
        {
          key: 'security',
          label: '安全与令牌',
          children: (
            <Stack>
              <HashTool />
              <TokenTool />
              <JwtTool />
              <UuidTool />
              <PasswordTool />
            </Stack>
          ),
        },
        {
          key: 'http',
          label: 'HTTP 调试',
          children: (
            <Stack>
              <CurlTool />
              <UaTool />
              <HttpStatusTool />
              <RegexTool />
            </Stack>
          ),
        },
      ]}
    />
    <Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
      工具页不向服务器发送输入内容；<Text code>navigator.clipboard</Text> 在非 HTTPS 环境下可能不可用，此时请手动选择复制。
    </Paragraph>
  </>
);

export default Tools;

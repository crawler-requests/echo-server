import React, { ReactNode } from 'react';
import { DatabaseOutlined, ScanOutlined, GlobalOutlined, SafetyCertificateOutlined } from '@ant-design/icons';

const AuthShell: React.FC<{ children: ReactNode }> = ({ children }) => (
  <div className="auth-page">
    <section className="auth-brand">
      <div className="sider-brand" style={{ cursor: 'default' }}>
        <div className="brand-mark">E</div>
        <div className="brand-text">
          <strong>Echo Server</strong>
          <span>REQUEST INTELLIGENCE</span>
        </div>
      </div>

      <div>
        <h1>
          看清每一次连接，
          <br />
          而不只是请求。
        </h1>
        <p className="lead">
          完整的 TLS ClientHello、JA3 / JA4 指纹、HTTP 层特征、客户端识别与 IP 情报，
          集中在一个控制台里。
        </p>
        <ul className="auth-features">
          <li>
            <span className="f-icon"><ScanOutlined /></span>
            TLS / HTTP 指纹捕获与客户端识别
          </li>
          <li>
            <span className="f-icon"><GlobalOutlined /></span>
            ASN、地理位置与住宅代理判定
          </li>
          <li>
            <span className="f-icon"><DatabaseOutlined /></span>
            可自由串联的数据源与云端查询链路
          </li>
          <li>
            <span className="f-icon"><SafetyCertificateOutlined /></span>
            角色权限、账号体系与服务端只读保护
          </li>
        </ul>
      </div>

      <div className="auth-foot">Echo Server · 管理控制台</div>
    </section>

    <main className="auth-form-wrap">
      <div className="auth-card">{children}</div>
    </main>
  </div>
);

export default AuthShell;

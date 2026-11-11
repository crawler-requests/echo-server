import React, { ReactNode } from 'react';

interface Props {
  title: string;
  description?: string;
  extra?: ReactNode;
}

const PageHeader: React.FC<Props> = ({ title, description, extra }) => (
  <div className="page-header">
    <div>
      <h1>{title}</h1>
      {description && <p>{description}</p>}
    </div>
    {extra && <div>{extra}</div>}
  </div>
);

export default PageHeader;

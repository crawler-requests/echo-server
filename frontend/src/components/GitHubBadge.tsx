import React, { useEffect, useState } from 'react';
import { Tooltip } from 'antd';
import { StarFilled } from '@ant-design/icons';

interface BadgeState {
  repo: string;
  url: string;
  stars: number;
  cached: boolean;
  fetched_at?: string;
}

// Module-level cache: the star count is fetched at most once per half hour
// per browser, even across page switches and reloads inside that window.
// The server also caches for 30 minutes, so both layers agree on the cadence.
const CACHE_KEY = 'echo_github_badge';
const CACHE_TTL_MS = 30 * 60 * 1000;

const readCache = (): { state: BadgeState; at: number } | null => {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { state: BadgeState; at: number };
    if (!parsed?.state?.repo || typeof parsed.at !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
};

const writeCache = (state: BadgeState) => {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ state, at: Date.now() }));
  } catch {
    /* storage disabled: the badge just refetches */
  }
};

const formatStars = (n: number): string => (n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k` : String(n));

interface Props {
  token: string;
}

// GitHub repo badge for the console header: a star button that links to the
// repository, so anyone who deploys this instance can find the project. The
// star count is decorative — on a failed fetch the last known value stays.
const GitHubBadge: React.FC<Props> = ({ token }) => {
  const [state, setState] = useState<BadgeState | null>(() => {
    const hit = readCache();
    return hit && Date.now() - hit.at < CACHE_TTL_MS ? hit.state : null;
  });

  useEffect(() => {
    const cached = readCache();
    if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
      setState(cached.state);
      return;
    }
    let cancelled = false;
    fetch('/api/github', { headers: { Authorization: 'Bearer ' + token } })
      .then(res => (res.ok ? res.json() : null))
      .then((data: BadgeState | null) => {
        if (cancelled || !data?.repo) return;
        // Keep the previous star count when the upstream fetch failed, so a
        // rate-limited GitHub does not blank the badge.
        setState(prev => (data.cached || !prev ? data : { ...prev, url: data.url, repo: data.repo }));
        if (data.cached) writeCache(data);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [token]);

  const repo = state?.repo || 'crawler-requests/echo-server';
  const url = state?.url || `https://github.com/${repo}`;
  const hasStars = !!state?.cached;

  return (
    <Tooltip title={`${repo} · 在 GitHub 上查看源码、提 issue 或点个 star`}>
      <a
        className="github-badge"
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        aria-label={`GitHub: ${repo}`}
      >
        <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true" className="github-badge-icon">
          <path
            fill="currentColor"
            d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13.28-.13.48-.37.63-.68-.63.02-1.27-.15-1.27-.15-.47-.09-.99.13-1.28.19.05-.26.37-1.28 2.35-1.75-1.06-.34-2.02-.13-2.37-.08-.47-.53-.63-.63-.68 0 0-.01 0-.03-.01-.63.02-1.34.15-1.98.39-.13.04-.49.22-.81.19.08.18.12.58.19.92 0 0 .01 0-.02.08-.14.36-.64 1.03-1.13 1.28-1.42.62-.91.13-2.01-.09-2.29.11.04.02.02.03.05.21.42.76.86 1.15 1.45.52.87.02 1.56-.02 1.73-.06.17-.15.45-.04.74.46.63.95.05 1.36-.02 1.22-.25.73-1.03.42-1.29-.09-.14-.55-.13-.81-.02-.38.06-.8-.04-1.09.03-.24.12-.54.12-.54s1.08-.58 2.23-1.11c-.05-.26-.05-.52-.05-.61 0-.34.25-.84.25-.84s.28-.51.72-.72c0 0 .13-.02.24.02s.24.07.4.2c.13.13.3.33.45.63.02.24.13.47.15.54.02.08-.01.25-.05.38z"
          />
        </svg>
        {hasStars && (
          <span className="github-badge-stars">
            <StarFilled style={{ fontSize: 12 }} />
            {formatStars(state!.stars)}
          </span>
        )}
      </a>
    </Tooltip>
  );
};

export default GitHubBadge;

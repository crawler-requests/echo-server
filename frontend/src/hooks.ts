import { useCallback } from 'react';
import { message } from 'antd';
import { ApiError, errorText } from './api';
import { useSession } from './session';

// One place turns API failures into either a logout (expired/disabled token)
// or a readable toast, so pages stay focused on their own data.
export function useApiError() {
  const { logout } = useSession();
  return useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        logout();
        return;
      }
      message.error(errorText(err));
    },
    [logout],
  );
}

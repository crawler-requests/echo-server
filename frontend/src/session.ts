import { useOutletContext } from 'react-router-dom';
import { User } from './api';

// Every authenticated page receives the session through the router outlet, so
// pages never read localStorage or duplicate auth logic.
export interface SessionCtx {
  token: string;
  me: User;
  canEdit: boolean;
  logout: () => void;
}

export const useSession = () => useOutletContext<SessionCtx>();

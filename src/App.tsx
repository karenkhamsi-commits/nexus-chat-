/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useState } from 'react';
import { ChatWorkspace } from './components/ChatWorkspace';
import { LoginView } from './components/LoginView';
import type { AuthSession, AuthStatusResponse } from './types/chat';

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const fetchAuthStatus = useCallback(async () => {
    setStatusError(null);
    try {
      const response = await fetch('/api/auth/status');
      if (!response.ok) {
        throw new Error('Failed to check room status');
      }
      const data = (await response.json()) as AuthStatusResponse;
      setAuthStatus(data);
    } catch {
      setStatusError('Unable to reach the NEXUS server. Please try again.');
    }
  }, []);

  useEffect(() => {
    void fetchAuthStatus();
  }, [fetchAuthStatus]);

  const handleSignOut = useCallback(() => {
    setSession(null);
    void fetchAuthStatus();
  }, [fetchAuthStatus]);

  if (statusError) {
    return (
      <div className="nexus-grid-bg flex min-h-dvh flex-col items-center justify-center bg-[#090B0E] px-4 text-center text-[#F1F5F9]">
        <div className="w-full max-w-md rounded-xl border border-white/10 bg-[#10141B] p-6">
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#F8FAFC]">
            WELCOME TO NEXUS
          </h1>
          <p className="mt-2 text-sm text-[#FCA5A5]">{statusError}</p>
          <button
            type="button"
            onClick={() => void fetchAuthStatus()}
            className="mt-5 min-h-[44px] rounded-lg bg-[#2563EB] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#1D4ED8]"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  if (!authStatus) {
    return (
      <div className="nexus-grid-bg flex min-h-dvh items-center justify-center bg-[#090B0E] px-4">
        <div className="h-[340px] w-full max-w-[440px] animate-pulse rounded-xl border border-white/10 bg-[#10141B]" />
      </div>
    );
  }

  if (!session) {
    return (
      <LoginView
        authStatus={authStatus}
        onAuthenticated={(nextSession) => setSession(nextSession)}
        onStatusRefresh={fetchAuthStatus}
      />
    );
  }

  return (
    <ChatWorkspace
      session={session}
      onSignOut={handleSignOut}
    />
  );
      }

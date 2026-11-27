import { useRef, useState, type FormEvent } from 'react';
import { AlertCircle, ArrowLeft, Eye, EyeOff, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import type { AuthSession, AuthStatusResponse } from '../types/chat';

interface LoginViewProps {
authStatus: AuthStatusResponse;
onAuthenticated: (session: AuthSession) => void;
onStatusRefresh: () => Promise<void>;
}

export function LoginView({
authStatus,
onAuthenticated,
onStatusRefresh,
}: LoginViewProps) {
const [username, setUsername] = useState('');
const [accessCode, setAccessCode] = useState('');
const [showAccessCode, setShowAccessCode] = useState(false);

// Setup / reconfiguration fields
const [reconfigureMode, setReconfigureMode] = useState(false);
const [currentCredential, setCurrentCredential] = useState('');
const [memberCode, setMemberCode] = useState('');
const [ownerCode, setOwnerCode] = useState('');
const [showSetupCodes, setShowSetupCodes] = useState(false);

const [submitting, setSubmitting] = useState(false);
const [error, setError] = useState<string | null>(null);

// Refs ensure browser autofill / mobile keyboard composition values are always captured
const loginUsernameRef = useRef<HTMLInputElement | null>(null);
const loginAccessCodeRef = useRef<HTMLInputElement | null>(null);
const setupUsernameRef = useRef<HTMLInputElement | null>(null);
const currentCredentialRef = useRef<HTMLInputElement | null>(null);
const memberCodeRef = useRef<HTMLInputElement | null>(null);
const ownerCodeRef = useRef<HTMLInputElement | null>(null);

const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
event.preventDefault();
setError(null);

const resolvedUsername = (loginUsernameRef.current?.value ?? username).trim();  
const resolvedAccessCode = (loginAccessCodeRef.current?.value ?? accessCode).trim();  

if (!resolvedAccessCode) {  
  setError('Please enter an access code.');  
  return;  
}  

setSubmitting(true);  
try {  
  const response = await fetch('/api/auth/login', {  
    method: 'POST',  
    headers: { 'Content-Type': 'application/json' },  
    body: JSON.stringify({  
      username: resolvedUsername,  
      accessCode: resolvedAccessCode,  
    }),  
  });  
  const data = (await response.json()) as Partial<AuthSession> & { error?: string };  

  if (!response.ok || !data.token || !data.user) {  
    if (response.status === 409) {  
      await onStatusRefresh();  
    }  
    setError(data.error || 'Unable to verify access code.');  
    return;  
  }  

  onAuthenticated({  
    token: data.token,  
    user: data.user,  
    retentionDays: data.retentionDays ?? authStatus.retentionDays,  
  });  
} catch {  
  setError('Connection failed. Please check your network and try again.');  
} finally {  
  setSubmitting(false);  
}

};

const handleSetupOrReconfigure = async (event: FormEvent<HTMLFormElement>) => {
event.preventDefault();
setError(null);

const isBootstrap = authStatus.needsSetup;  
const isClaimOverride = !isBootstrap && authStatus.canClaimOverride;  
const requiresCurrentCredential = !isBootstrap && !isClaimOverride;  

const resolvedUsername = (setupUsernameRef.current?.value ?? username).trim();  
const resolvedCurrentCredential = (  
  currentCredentialRef.current?.value ?? currentCredential  
).trim();  
const resolvedMemberCode = (memberCodeRef.current?.value ?? memberCode).trim();  
const resolvedOwnerCode = (ownerCodeRef.current?.value ?? ownerCode).trim();  

if (requiresCurrentCredential && !resolvedCurrentCredential) {  
  setError(  
    authStatus.hasResetSecret  
      ? 'Please enter the reset code or current owner code.'  
      : 'Please enter the current owner admin code.'  
  );  
  return;  
}  

if (resolvedMemberCode.length < 4) {  
  setError('Member access code must be at least 4 characters.');  
  return;  
}  
if (resolvedOwnerCode.length < 6) {  
  setError('Owner admin code must be at least 6 characters.');  
  return;  
}  
if (resolvedMemberCode === resolvedOwnerCode) {  
  setError('Owner admin code must be different from the member access code.');  
  return;  
}  

const endpoint = isBootstrap  
  ? '/api/auth/bootstrap'  
  : isClaimOverride  
    ? '/api/auth/claim-override'  
    : '/api/auth/reconfigure-with-owner';  

const payload = requiresCurrentCredential  
  ? {  
      username: resolvedUsername,  
      currentCredential: resolvedCurrentCredential,  
      memberCode: resolvedMemberCode,  
      ownerCode: resolvedOwnerCode,  
    }  
  : {  
      username: resolvedUsername,  
      memberCode: resolvedMemberCode,  
      ownerCode: resolvedOwnerCode,  
    };  

setSubmitting(true);  
try {  
  const response = await fetch(endpoint, {  
    method: 'POST',  
    headers: { 'Content-Type': 'application/json' },  
    body: JSON.stringify(payload),  
  });  
  const data = (await response.json()) as Partial<AuthSession> & { error?: string };  

  if (!response.ok || !data.token || !data.user) {  
    if (response.status === 409) {  
      await onStatusRefresh();  
    }  
    setError(data.error || 'Could not update access codes.');  
    return;  
  }  

  onAuthenticated({  
    token: data.token,  
    user: data.user,  
    retentionDays: data.retentionDays ?? authStatus.retentionDays,  
  });  
} catch {  
  setError('Connection failed. Please check your network and try again.');  
} finally {  
  setSubmitting(false);  
}

};

const showSetupForm = authStatus.needsSetup || reconfigureMode;
const isOneTimeClaim = authStatus.needsSetup || authStatus.canClaimOverride;

return (
<div className="nexus-grid-bg relative flex min-h-dvh flex-col items-center justify-center bg-[#090B0E] px-4 py-10 text-[#F1F5F9]">
<main className="w-full max-w-[440px]">
<div className="rounded-xl border border-white/10 bg-[#10141B] p-6 shadow-2xl sm:p-8">
<div className="border-b border-white/10 pb-6">
<p className="font-mono text-xs font-medium tracking-wider text-[#60A5FA]">
Private Group Channel
</p>
<h1 className="mt-2 font-display text-3xl font-bold tracking-tight text-[#F8FAFC] sm:text-[34px]">
WELCOME TO NEXUS
</h1>
<p className="mt-2 text-sm leading-relaxed text-[#94A3B8]">
{authStatus.needsSetup
? 'Set the initial group access code and owner admin code to secure this room.'
: reconfigureMode
? authStatus.canClaimOverride
? 'Configure custom member and owner access codes to take effect for this room.'
: authStatus.hasResetSecret
? 'Verify your reset code or current owner code to set new member and owner access codes.'
: 'Verify the current owner code to update the member and owner access codes.'
: 'Enter the room access code to join the shared channel. Messages expire automatically after 30 days.'}
</p>
</div>

{showSetupForm ? (  
        <form  
          key="nexus-reconfigure-form"  
          onSubmit={handleSetupOrReconfigure}  
          noValidate  
          autoComplete="off"  
          className="mt-6 space-y-5"  
        >  
          <div>  
            <label  
              htmlFor="setup-username"  
              className="block text-sm font-medium text-[#E2E8F0]"  
            >  
              Username (Optional)  
            </label>  
            <input  
              ref={setupUsernameRef}  
              id="setup-username"  
              name="nexus_setup_username"  
              type="text"  
              maxLength={32}  
              autoComplete="off"  
              value={username}  
              onChange={(e) => {  
                setUsername(e.target.value);  
                if (error) setError(null);  
              }}  
              placeholder="Anonymous"  
              className="mt-1.5 min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] px-3.5 py-2 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
            />  
            <p className="mt-1.5 text-xs text-[#64748B]">  
              Leave blank to appear as Anonymous.  
            </p>  
          </div>  

          {!isOneTimeClaim && (  
            <div>  
              <label  
                htmlFor="setup-current-credential"  
                className="block text-sm font-medium text-[#E2E8F0]"  
              >  
                {authStatus.hasResetSecret  
                  ? 'Reset Code or Current Owner Code'  
                  : 'Current Owner Admin Code'}  
              </label>  
              <input  
                ref={currentCredentialRef}  
                id="setup-current-credential"  
                name="nexus_reset_credential"  
                type={showSetupCodes ? 'text' : 'password'}  
                autoComplete="off"  
                value={currentCredential}  
                onChange={(e) => {  
                  setCurrentCredential(e.target.value);  
                  if (error) setError(null);  
                }}  
                placeholder={  
                  authStatus.hasResetSecret  
                    ? 'Enter reset code or current owner code'  
                    : 'Enter current owner code'  
                }  
                className="mt-1.5 min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] px-3.5 py-2 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
              />  
            </div>  
          )}  

          <div>  
            <label  
              htmlFor="setup-member-code"  
              className="block text-sm font-medium text-[#E2E8F0]"  
            >  
              {reconfigureMode ? 'New Member Access Code' : 'Member Access Code'}  
            </label>  
            <input  
              ref={memberCodeRef}  
              id="setup-member-code"  
              name="nexus_new_member_code"  
              type={showSetupCodes ? 'text' : 'password'}  
              autoComplete="off"  
              value={memberCode}  
              onChange={(e) => {  
                setMemberCode(e.target.value);  
                if (error) setError(null);  
              }}  
              placeholder="Minimum 4 characters"  
              className="mt-1.5 min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] px-3.5 py-2 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
            />  
          </div>  

          <div>  
            <div className="flex items-center justify-between gap-2">  
              <label  
                htmlFor="setup-owner-code"  
                className="block text-sm font-medium text-[#E2E8F0]"  
              >  
                {reconfigureMode ? 'New Owner Admin Code' : 'Owner Admin Code'}  
              </label>  
              <button  
                type="button"  
                onClick={() => setShowSetupCodes((prev) => !prev)}  
                className="text-xs font-medium text-[#93C5FD] hover:text-[#BFDBFE]"  
              >  
                {showSetupCodes ? 'Hide Codes' : 'Show Codes'}  
              </button>  
            </div>  
            <input  
              ref={ownerCodeRef}  
              id="setup-owner-code"  
              name="nexus_new_owner_code"  
              type={showSetupCodes ? 'text' : 'password'}  
              autoComplete="off"  
              value={ownerCode}  
              onChange={(e) => {  
                setOwnerCode(e.target.value);  
                if (error) setError(null);  
              }}  
              placeholder="Minimum 6 characters (distinct from member)"  
              className="mt-1.5 min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] px-3.5 py-2 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
            />  
            <p className="mt-1.5 text-xs text-[#64748B]">  
              {isOneTimeClaim && !authStatus.needsSetup  
                ? 'One-time configuration stored as salted server hashes. Future changes require owner verification.'  
                : 'Stored as salted cryptographic hashes on the server. Keep your owner code private.'}  
            </p>  
          </div>  

          {error && (  
            <div  
              role="alert"  
              className="flex items-start gap-2.5 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 p-3 text-xs font-medium text-[#FCA5A5]"  
            >  
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#F87171]" aria-hidden="true" />  
              <span>{error}</span>  
            </div>  
          )}  

          <button  
            type="submit"  
            disabled={submitting}  
            className="flex min-h-[44px] w-full items-center justify-center gap-2 rounded-lg bg-[#2563EB] px-5 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#1D4ED8] disabled:cursor-not-allowed disabled:opacity-60"  
          >  
            <ShieldCheck className="h-4 w-4 shrink-0" aria-hidden="true" />  
            <span>  
              {submitting  
                ? 'Saving Access Codes...'  
                : authStatus.needsSetup  
                  ? 'Initialize & Enter Room'  
                  : authStatus.hasResetSecret && !isOneTimeClaim  
                    ? 'Reset Codes & Enter Room'  
                    : 'Save Codes & Enter Room'}  
            </span>  
          </button>  

          {!authStatus.needsSetup && (  
            <button  
              type="button"  
              onClick={() => {  
                setReconfigureMode(false);  
                setError(null);  
              }}  
              className="flex min-h-[44px] w-full items-center justify-center gap-2 rounded-lg border border-white/15 bg-transparent px-4 py-2 text-xs font-medium text-[#CBD5E1] transition-colors duration-150 hover:bg-white/5"  
            >  
              <ArrowLeft className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />  
              <span>Back to Sign In</span>  
            </button>  
          )}  
        </form>  
      ) : (  
        <form  
          key="nexus-login-form"  
          onSubmit={handleLogin}  
          noValidate  
          className="mt-6 space-y-5"  
        >  
          <div>  
            <label  
              htmlFor="nexus-username"  
              className="block text-sm font-medium text-[#E2E8F0]"  
            >  
              Username (Optional)  
            </label>  
            <input  
              ref={loginUsernameRef}  
              id="nexus-username"  
              name="nexus_username"  
              type="text"  
              maxLength={32}  
              autoComplete="nickname"  
              value={username}  
              onChange={(e) => {  
                setUsername(e.target.value);  
                if (error) setError(null);  
              }}  
              placeholder="Anonymous"  
              className="mt-1.5 min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] px-3.5 py-2 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
            />  
            <p className="mt-1.5 text-xs text-[#64748B]">  
              Leave blank to join as Anonymous.  
            </p>  
          </div>  

          <div>  
            <label  
              htmlFor="nexus-access-code"  
              className="block text-sm font-medium text-[#E2E8F0]"  
            >  
              Access Code  
            </label>  
            <div className="relative mt-1.5">  
              <input  
                ref={loginAccessCodeRef}  
                id="nexus-access-code"  
                name="nexus_access_code"  
                type={showAccessCode ? 'text' : 'password'}  
                autoComplete="current-password"  
                value={accessCode}  
                onChange={(e) => {  
                  setAccessCode(e.target.value);  
                  if (error) setError(null);  
                }}  
                placeholder="Enter group or owner access code"  
                className="min-h-[44px] w-full rounded-lg border border-white/15 bg-[#090B0E] py-2 pl-3.5 pr-12 text-sm text-[#F8FAFC] placeholder:text-[#64748B]"  
              />  
              <button  
                type="button"  
                onClick={() => setShowAccessCode((prev) => !prev)}  
                aria-label={showAccessCode ? 'Hide access code' : 'Show access code'}  
                className="absolute right-0 top-0 flex h-[44px] w-[44px] items-center justify-center text-[#94A3B8] hover:text-[#F8FAFC]"  
              >  
                {showAccessCode ? (  
                  <EyeOff className="h-4 w-4" aria-hidden="true" />  
                ) : (  
                  <Eye className="h-4 w-4" aria-hidden="true" />  
                )}  
              </button>  
            </div>  
          </div>  

          {error && (  
            <div  
              role="alert"  
              className="flex items-start gap-2.5 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 p-3 text-xs font-medium text-[#FCA5A5]"  
            >  
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#F87171]" aria-hidden="true" />  
              <span>{error}</span>  
            </div>  
          )}  

          <button  
            type="submit"  
            disabled={submitting}  
            className="flex min-h-[44px] w-full items-center justify-center gap-2 rounded-lg bg-[#2563EB] px-5 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-[#1D4ED8] disabled:cursor-not-allowed disabled:opacity-60"  
          >  
            <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />  
            <span>{submitting ? 'Verifying Code...' : 'Enter Nexus'}</span>  
          </button>  

          <div className="border-t border-white/10 pt-4 text-center">  
            <button  
              type="button"  
              onClick={() => {  
                setReconfigureMode(true);  
                setError(null);  
              }}  
              className="inline-flex min-h-[40px] items-center justify-center gap-1.5 text-xs font-medium text-[#93C5FD] transition-colors duration-150 hover:text-[#BFDBFE]"  
            >  
              <KeyRound className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />  
              <span>  
                {authStatus.canClaimOverride  
                  ? 'Configure custom member & owner codes'  
                  : 'Reset or reconfigure access codes'}  
              </span>  
            </button>  
          </div>  
        </form>  
      )}  
    </div>  

    <p className="mt-5 text-center text-xs text-[#64748B] tabular-nums">  
      Server-verified access · {authStatus.retentionDays}-day automatic message expiry  
    </p>  
  </main>  
</div>

);
}

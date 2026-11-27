import crypto from 'node:crypto';
import {
  claimAccessCodesAtomic,
  clearEnvOverrideFlag,
  getConfigValue,
  getOrCreateConfigSecret,
  saveReconfiguredCodesAtomic,
  type UserRole,
} from './db.ts';

const SESSION_SECRET =
  process.env.SESSION_SECRET?.trim() ||
  getOrCreateConfigSecret('session_secret', () => crypto.randomBytes(32).toString('hex'));

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface SessionUser {
  sessionId: string;
  username: string;
  role: UserRole;
  iat: number;
  exp: number;
}

export function hashPasscode(plain: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPasscodeHash(plain: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  try {
    const derived = crypto.scryptSync(plain, salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function verifyEnvCodeConstantTime(input: string, expected: string): boolean {
  const a = crypto.createHash('sha256').update(input, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

export function isEnvConfigured(): boolean {
  return Boolean(
    process.env.NEXUS_OWNER_CODE?.trim() || process.env.NEXUS_ACCESS_CODE?.trim()
  );
}

export function hasResetSecret(): boolean {
  return Boolean(process.env.NEXUS_RESET_CODE?.trim());
}

export function getCurrentEnvFingerprint(): string {
  const owner = process.env.NEXUS_OWNER_CODE?.trim() ?? '';
  const member = process.env.NEXUS_ACCESS_CODE?.trim() ?? '';
  return crypto.createHash('sha256').update(`${owner}\0${member}`, 'utf8').digest('hex');
}

export function areDbCodesOverridingEnv(): boolean {
  const ownerHash = getConfigValue('owner_code_hash');
  const memberHash = getConfigValue('member_code_hash');
  if (!ownerHash || !memberHash) return false;
  const overrideFp = getConfigValue('codes_override_env_fp');
  return Boolean(overrideFp && overrideFp === getCurrentEnvFingerprint());
}

export function isSetupRequired(): boolean {
  if (isEnvConfigured()) {
    return false;
  }
  const ownerHash = getConfigValue('owner_code_hash');
  const memberHash = getConfigValue('member_code_hash');
  return !ownerHash || !memberHash;
}

export function canClaimOverride(): boolean {
  if (!isEnvConfigured() || hasResetSecret()) {
    return false;
  }
  const ownerHash = getConfigValue('owner_code_hash');
  const memberHash = getConfigValue('member_code_hash');
  return !ownerHash && !memberHash;
}

export function claimInitialAccessCodes(
  memberCode: string,
  ownerCode: string,
  overrideEnv = false
): boolean {
  if (!overrideEnv && isEnvConfigured()) {
    return false;
  }
  if (overrideEnv && !canClaimOverride()) {
    return false;
  }
  const trimmedMember = memberCode.trim();
  const trimmedOwner = ownerCode.trim();
  const memberHash = hashPasscode(trimmedMember);
  const ownerHash = hashPasscode(trimmedOwner);
  const overrideFp = overrideEnv ? getCurrentEnvFingerprint() : null;
  const claimed = claimAccessCodesAtomic(memberHash, ownerHash, overrideFp);
  if (!claimed) {
    return false;
  }
  const storedMember = getConfigValue('member_code_hash');
  const storedOwner = getConfigValue('owner_code_hash');
  return Boolean(
    storedMember &&
      storedOwner &&
      verifyPasscodeHash(trimmedMember, storedMember) &&
      verifyPasscodeHash(trimmedOwner, storedOwner)
  );
}

export function reconfigureAccessCodes(memberCode: string, ownerCode: string): boolean {
  const trimmedMember = memberCode.trim();
  const trimmedOwner = ownerCode.trim();
  const memberHash = hashPasscode(trimmedMember);
  const ownerHash = hashPasscode(trimmedOwner);
  const overrideFp = isEnvConfigured() ? getCurrentEnvFingerprint() : null;
  saveReconfiguredCodesAtomic(memberHash, ownerHash, overrideFp);
  const storedMember = getConfigValue('member_code_hash');
  const storedOwner = getConfigValue('owner_code_hash');
  return Boolean(
    storedMember &&
      storedOwner &&
      verifyPasscodeHash(trimmedMember, storedMember) &&
      verifyPasscodeHash(trimmedOwner, storedOwner)
  );
}

export function revertToEnvAccessCodes(): boolean {
  if (!isEnvConfigured()) {
    return false;
  }
  clearEnvOverrideFlag();
  return true;
}

export function verifyAccessCode(accessCode: string): UserRole | null {
  const trimmed = accessCode.trim();
  if (!trimmed) return null;

  const dbOverridesEnv = areDbCodesOverridingEnv();
  const envOwner = process.env.NEXUS_OWNER_CODE?.trim();
  const envMember = process.env.NEXUS_ACCESS_CODE?.trim();

  if (dbOverridesEnv || !envOwner) {
    const storedOwnerHash = getConfigValue('owner_code_hash');
    if (storedOwnerHash && verifyPasscodeHash(trimmed, storedOwnerHash)) {
      return 'owner';
    }
  } else if (envOwner) {
    if (verifyEnvCodeConstantTime(trimmed, envOwner)) {
      return 'owner';
    }
  }

  if (dbOverridesEnv || !envMember) {
    const storedMemberHash = getConfigValue('member_code_hash');
    if (storedMemberHash && verifyPasscodeHash(trimmed, storedMemberHash)) {
      return 'member';
    }
  } else if (envMember) {
    if (verifyEnvCodeConstantTime(trimmed, envMember)) {
      return 'member';
    }
  }

  return null;
}

export function verifyOwnerOrResetCredential(credential: string): boolean {
  const trimmed = credential.trim();
  if (!trimmed) return false;
  if (verifyAccessCode(trimmed) === 'owner') {
    return true;
  }
  const resetCode = process.env.NEXUS_RESET_CODE?.trim();
  if (resetCode && verifyEnvCodeConstantTime(trimmed, resetCode)) {
    return true;
  }
  return false;
}

export function sanitizeUsername(raw: unknown): string {
  if (typeof raw !== 'string') return 'Anonymous';
  const cleaned = raw
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 32);
  return cleaned.length > 0 ? cleaned : 'Anonymous';
}

function toBase64Url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function fromBase64Url(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLen), 'base64');
}

export function createSessionToken(username: string, role: UserRole): string {
  const now = Date.now();
  const payload: SessionUser = {
    sessionId: crypto.randomUUID(),
    username,
    role,
    iat: now,
    exp: now + SESSION_TTL_MS,
  };
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(encodedPayload)
    .digest();
  return `${encodedPayload}.${toBase64Url(signature)}`;
}

export function verifySessionToken(token: string): SessionUser | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, encodedSig] = parts;
  if (!encodedPayload || !encodedSig) return null;

  try {
    const expectedSig = crypto
      .createHmac('sha256', SESSION_SECRET)
      .update(encodedPayload)
      .digest();
    const actualSig = fromBase64Url(encodedSig);
    if (expectedSig.length !== actualSig.length) return null;
    if (!crypto.timingSafeEqual(expectedSig, actualSig)) return null;

    const parsed = JSON.parse(fromBase64Url(encodedPayload).toString('utf8')) as SessionUser;
    if (
      !parsed ||
      typeof parsed.sessionId !== 'string' ||
      typeof parsed.username !== 'string' ||
      (parsed.role !== 'member' && parsed.role !== 'owner') ||
      typeof parsed.exp !== 'number'
    ) {
      return null;
    }
    if (Date.now() > parsed.exp) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

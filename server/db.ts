import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export const RETENTION_DAYS = 30;
export const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;

export type UserRole = 'member' | 'owner';

export interface ChatMessage {
  id: string;
  senderName: string;
  senderRole: UserRole;
  content: string;
  createdAt: number;
  expiresAt: number;
}

interface RawMessageRow {
  id: string;
  sender_name: string;
  sender_role: string;
  content: string;
  created_at: number;
  expires_at: number;
}

const dataDir = process.env.NEXUS_DATA_DIR
  ? path.resolve(process.env.NEXUS_DATA_DIR)
  : path.resolve(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'nexus.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_name TEXT NOT NULL,
    sender_role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);
  CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
`);

const stmtPurgeExpired = db.prepare('DELETE FROM messages WHERE expires_at <= ?');
const stmtListActive = db.prepare(
  'SELECT id, sender_name, sender_role, content, created_at, expires_at FROM messages WHERE expires_at > ? ORDER BY created_at ASC'
);
const stmtInsertMessage = db.prepare(
  'INSERT INTO messages (id, sender_name, sender_role, content, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
);
const stmtDeleteAllMessages = db.prepare('DELETE FROM messages');
const stmtGetConfig = db.prepare('SELECT value FROM app_config WHERE key = ?');
const stmtInsertConfigIfAbsent = db.prepare(
  'INSERT OR IGNORE INTO app_config (key, value, updated_at) VALUES (?, ?, ?)'
);
const stmtUpsertConfig = db.prepare(
  'INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES (?, ?, ?)'
);
const stmtDeleteConfig = db.prepare('DELETE FROM app_config WHERE key = ?');

function mapRow(row: RawMessageRow): ChatMessage {
  return {
    id: row.id,
    senderName: row.sender_name,
    senderRole: row.sender_role === 'owner' ? 'owner' : 'member',
    content: row.content,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export function purgeExpiredMessages(now = Date.now()): number {
  const result = stmtPurgeExpired.run(now);
  return result.changes;
}

export function listActiveMessages(now = Date.now()): ChatMessage[] {
  purgeExpiredMessages(now);
  const rows = stmtListActive.all(now) as RawMessageRow[];
  return rows.map(mapRow);
}

export function insertMessage(input: {
  id: string;
  senderName: string;
  senderRole: UserRole;
  content: string;
  createdAt?: number;
}): ChatMessage {
  const createdAt = input.createdAt ?? Date.now();
  const expiresAt = createdAt + RETENTION_MS;
  stmtInsertMessage.run(
    input.id,
    input.senderName,
    input.senderRole,
    input.content,
    createdAt,
    expiresAt
  );
  return {
    id: input.id,
    senderName: input.senderName,
    senderRole: input.senderRole,
    content: input.content,
    createdAt,
    expiresAt,
  };
}

export function deleteMessagesByIds(ids: string[]): number {
  if (ids.length === 0) return 0;
  const placeholders = ids.map(() => '?').join(', ');
  const stmt = db.prepare(`DELETE FROM messages WHERE id IN (${placeholders})`);
  const result = stmt.run(...ids);
  return result.changes;
}

export function deleteAllMessages(): number {
  const result = stmtDeleteAllMessages.run();
  return result.changes;
}

export function getConfigValue(key: string): string | null {
  const row = stmtGetConfig.get(key) as { value: string } | undefined;
  return row ? row.value : null;
}

export function getOrCreateConfigSecret(key: string, generator: () => string): string {
  const existing = getConfigValue(key);
  if (existing) return existing;
  const generated = generator();
  stmtInsertConfigIfAbsent.run(key, generated, Date.now());
  db.pragma('wal_checkpoint(TRUNCATE)');
  return getConfigValue(key) ?? generated;
}

const claimAccessCodesTransaction = db.transaction(
  (memberHash: string, ownerHash: string, overrideEnvFp: string | null): boolean => {
    const existingOwner = stmtGetConfig.get('owner_code_hash') as { value: string } | undefined;
    const existingMember = stmtGetConfig.get('member_code_hash') as { value: string } | undefined;
    if (existingOwner || existingMember) {
      return false;
    }
    const now = Date.now();
    stmtInsertConfigIfAbsent.run('member_code_hash', memberHash, now);
    stmtInsertConfigIfAbsent.run('owner_code_hash', ownerHash, now);
    if (overrideEnvFp) {
      stmtUpsertConfig.run('codes_override_env_fp', overrideEnvFp, now);
    }
    return true;
  }
);

export function claimAccessCodesAtomic(
  memberHash: string,
  ownerHash: string,
  overrideEnvFp: string | null = null
): boolean {
  const claimed = claimAccessCodesTransaction(memberHash, ownerHash, overrideEnvFp);
  if (claimed) {
    db.pragma('wal_checkpoint(TRUNCATE)');
  }
  return claimed;
}

const saveReconfiguredCodesTransaction = db.transaction(
  (memberHash: string, ownerHash: string, overrideEnvFp: string | null): void => {
    const now = Date.now();
    stmtUpsertConfig.run('member_code_hash', memberHash, now);
    stmtUpsertConfig.run('owner_code_hash', ownerHash, now);
    if (overrideEnvFp) {
      stmtUpsertConfig.run('codes_override_env_fp', overrideEnvFp, now);
    } else {
      stmtDeleteConfig.run('codes_override_env_fp');
    }
  }
);

export function saveReconfiguredCodesAtomic(
  memberHash: string,
  ownerHash: string,
  overrideEnvFp: string | null
): void {
  saveReconfiguredCodesTransaction(memberHash, ownerHash, overrideEnvFp);
  db.pragma('wal_checkpoint(TRUNCATE)');
}

export function clearEnvOverrideFlag(): void {
  stmtDeleteConfig.run('codes_override_env_fp');
  db.pragma('wal_checkpoint(TRUNCATE)');
}

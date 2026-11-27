export type UserRole = 'member' | 'owner';

export interface AuthUser {
username: string;
role: UserRole;
}

export interface AuthSession {
token: string;
user: AuthUser;
retentionDays: number;
}

export interface AuthStatusResponse {
needsSetup: boolean;
envConfigured: boolean;
canClaimOverride: boolean;
hasResetSecret: boolean;
usingCustomOverride: boolean;
retentionDays: number;
}

export interface ChatMessage {
id: string;
senderName: string;
senderRole: UserRole;
content: string;
createdAt: number;
expiresAt: number;
}

export interface OnlineUser {
connectionId: string;
username: string;
role: UserRole;
}

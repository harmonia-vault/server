export type Role = "ro" | "rw" | "admin" | "none";
export interface Mutation {
  accountId: string; accountGeneration: string; deviceId: string; environmentId: string;
  keyVersion: string; grantGeneration: string; operation: "put" | "delete";
  idempotencyKey: string; name: string; payload: string;
}
export interface Grant {
  accountId: string; accountGeneration: string; issuerDeviceId: string; subjectDeviceId: string;
  subjectSigningPublicKey: string; subjectReceivingPublicKey: string; environmentId: string;
  keyVersion: string; grantGeneration: string; role: Role; expiresAt: string;
  idempotencyKey: string; envelope: string;
}
export interface SignedMutation { mutation: Mutation; signature: string }
export interface SignedGrant { grant: Grant; signature: string }
export interface Device { id: string; signingPublicKey: string; receivingPublicKey: string; revoked: boolean }
export interface Environment { id: string; keyVersion: string; recoveryEnvelope: string }
export interface Event { sequence: number; mutation: SignedMutation; authorization: SignedGrant }
export interface Session { tokenHash: string; generation: string; expiresAt: number; kind: "login" | "recovery"; deviceId?: string }
export interface DeviceChallenge { id: string; deviceId: string; sessionHash: string; nonce: string; expiresAt: number; generation: string }
export interface Account {
  schema: 1; id: string; email: string; generation: string; verified: boolean; passwordVerifier: string;
  sequence: number; devices: Record<string, Device>; environments: Record<string, Environment>;
  grants: Record<string, SignedGrant>; sessions: Session[]; deviceChallenges: DeviceChallenge[]; events: Event[];
  idempotency: Record<string, { content: string; sequence: number }>;
  recoveryGeneration: string; recoverySigningPublicKey: string | null;
}
export interface Auth { token: string; deviceId: string; accountGeneration: string }
export interface Pull {
  accountId: string; accountGeneration: string; sequence: number;
  grants: SignedGrant[]; events: Event[];
}
export class Fault extends Error {
  constructor(public readonly status: number, public readonly code: string) { super(code); }
}
export const grantKey = (environmentId: string, deviceId: string): string => `${environmentId}/${deviceId}`;

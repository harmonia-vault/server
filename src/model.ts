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
export interface Environment { id: string; keyVersion: string; recoveryEnvelope: string; recoveryGeneration?: string; recoveryKeyVersion?: string }
export interface GrantEvent { sequence: number; grant: SignedGrant; authorization: SignedGrant | null; originHash?: string; recoveryEnrollmentHash?: string }
export interface Event { sequence: number; mutation: SignedMutation; authorization: SignedGrant }
export interface Session { tokenHash: string; generation: string; expiresAt: number; kind: "login" | "recovery"; deviceId?: string; recoveryGeneration?: string; rotationRequired?: boolean; id?: string }
export interface DeviceChallenge { id: string; deviceId: string; sessionHash: string; nonce: string; expiresAt: number; generation: string }
export interface Account {
  schema: 3; id: string; email: string; generation: string; verified: boolean; passwordVerifier: string;
  verificationRequiredAtRegistration: boolean;
  registrationAdmission: import("./registration.js").RegistrationAdmission;
  sequence: number; devices: Record<string, Device>; environments: Record<string, Environment>;
  grants: Record<string, SignedGrant>; sessions: Session[]; deviceChallenges: DeviceChallenge[]; events: Event[];
  idempotency: Record<string, { content: string; sequence: number }>;
  recoveryGeneration: string; recoverySigningPublicKey: string | null; recoveryReceivingPublicKey?: string | null;
  emailProofs?: import("./account-lifecycle.js").EmailProof[];
  resetReceipt?: import("./account-lifecycle.js").ResetReceipt;
  trustRoot?: import("./trust-root.js").TrustRoot;
  grantHistory?: GrantEvent[];
  environmentHistory?: import("./environments.js").EnvironmentEvent[];
  deletedEnvironmentIds?: Record<string, string>;
  environmentLabels?: Record<string, string>;
  deviceRevocations?: Record<string, import("./environments.js").RevocationRecord>;
  notificationTickets?: import("./notifications.js").NotificationTicket[];
  bootChallenges?: import("./lifecycle-wire.js").BootChallenge[];
  recoveryChallenges?: import("./lifecycle-wire.js").RecoveryChallenge[];
  recoveryOperationClosures?: import("./recovery-operation-guards.js").RecoveryOperationClosures;
}
export interface Auth { token: string; deviceId: string; accountGeneration: string }
export interface Pull {
  accountId: string; accountGeneration: string; sequence: number;
  grants: SignedGrant[]; events: Event[]; scope?: "authorizations";
  environmentEvents?: import("./environments.js").EnvironmentEvent[];
  issuerEvidence: import("./recovery-dag-wire.js").IssuerRecoveryDAG | null;
}
export class Fault extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly retryAfterSeconds?: number) { super(code); }
}
export const grantKey = (environmentId: string, deviceId: string): string => `${environmentId}/${deviceId}`;

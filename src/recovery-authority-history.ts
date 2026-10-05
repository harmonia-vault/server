import { verify } from './protocol.js';
import { initializationReference } from './recovery-authority-wire.js';
import type { OriginalInitialization } from './initialization-evidence.js';
import { trustRootPayload, type TrustRoot } from './trust-root.js';
import { canonical } from './enrollment-wire.js';
export interface RecoveryAuthorityHead {
    generation: string;
    signing: string;
    receiving: string;
    head: string;
    sequence: number;
    root: TrustRoot;
    operations: Set<string>;
    seenKeys: Set<string>;
}
export function initialRecoveryAuthority(original: OriginalInitialization): RecoveryAuthorityHead {
    const p = original.proposal, c = original.proof, head = initializationReference(original), root: TrustRoot = { rootDeviceId: p.device.id, rootSigningPublicKey: p.device.signingPublicKey, rootReceivingPublicKey: p.device.receivingPublicKey, recoveryGeneration: p.recoveryGeneration, recoverySigningPublicKey: p.recoverySigningPublicKey, recoveryReceivingPublicKey: p.recoveryReceivingPublicKey, signature: p.trustRootSignature };
    verify(p.recoverySigningPublicKey, canonical(trustRootPayload(c.accountId, c.accountGeneration, root)), root.signature);
    const state: RecoveryAuthorityHead = { generation: p.recoveryGeneration, signing: p.recoverySigningPublicKey, receiving: p.recoveryReceivingPublicKey, head, sequence: 1, root, operations: new Set(), seenKeys: new Set([p.device.signingPublicKey, p.device.receivingPublicKey, p.recoverySigningPublicKey, p.recoveryReceivingPublicKey]) };
    return state;
}

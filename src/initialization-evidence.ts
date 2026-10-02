import { Fault, type Account } from "./model.js";
import { bytes, generation, identifier, verify } from "./protocol.js";
import { canonical, initializationFields, initializationHash, type EnrollmentAccount, type InitializationProposal } from "./enrollment-wire.js";
export interface OriginalInitialization {
  proposal: InitializationProposal;
  proof: { accountId: string; accountGeneration: string; loginTokenHash: string; challengeId: string; nonce: string; expiresAt: string; proposalHash: string };
  deviceSignature: string;
  recoverySignature: string;
  sequence: number;
}
/** 从唯一已接受的原记录投影，不重复存储权威状态，也不向旧夹具补造根。 */
export function originalInitialization(account: Account): OriginalInitialization | null {
  const a = account as EnrollmentAccount;
  const records = Object.values(a.vaultInitializations ?? {}).filter(record => record.complete);
  if (!records.length) return null;
  if (records.length !== 1) throw new Fault(409, "initialization_evidence_invalid");
  const record = records[0]!, complete = record.complete!, proposal = record.proposal, root = account.trustRoot;
  const proposalHash = initializationHash(account.id, account.generation, proposal);
  identifier(record.id); bytes(record.nonce, 32); generation(String(record.expiresAt));
  if (!/^[0-9a-f]{64}$/.test(record.sessionHash) || record.accountGeneration !== account.generation || proposalHash !== record.proposalHash || !root || root.rootDeviceId !== proposal.device.id || root.rootSigningPublicKey !== proposal.device.signingPublicKey || root.rootReceivingPublicKey !== proposal.device.receivingPublicKey || !Number.isSafeInteger(complete.sequence) || complete.sequence !== 1 || complete.sequence > account.sequence) throw new Fault(409, "initialization_evidence_invalid");
  const signingBytes = canonical(initializationFields(account.id, record));
  verify(proposal.device.signingPublicKey, signingBytes, complete.deviceSignature);
  verify(proposal.recoverySigningPublicKey, signingBytes, complete.recoverySignature);
  return structuredClone({ proposal, proof: { accountId: account.id, accountGeneration: record.accountGeneration, loginTokenHash: record.sessionHash,
    challengeId: record.id, nonce: record.nonce, expiresAt: String(record.expiresAt), proposalHash },
    deviceSignature: complete.deviceSignature, recoverySignature: complete.recoverySignature, sequence: complete.sequence });
}

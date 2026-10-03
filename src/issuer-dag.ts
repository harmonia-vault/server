import { Fault, type SignedGrant } from './model.js';
import { bytes, generation, identifier, grantBytes, verify } from './protocol.js';
import { canonical, enrollmentFields, exact, pairingContextFields, type EnrollmentCertificate, type PairingContext } from './enrollment-wire.js';
import { issuerAuthorityHash } from './issuer-proof.js';
import { dagHash, recoveryDAGCapability, type IssuerRecoveryDAG, type DAGArchive } from './recovery-dag-wire.js';
import { verifyIssuerRecoveryDAG, type RecoveryDAGPin } from './recovery-dag.js';
export type EnrollmentApprovalV5 = EnrollmentCertificate & { certificateVersion: '5'; capabilities: [typeof recoveryDAGCapability]; issuerProof: IssuerRecoveryDAG };
export interface ConfirmedDAGEnrollment { context: PairingContext; transcriptHash: string }
function fail(): never { throw new Fault(403, 'recovery_dag_invalid'); }
const within = (child: string, parent: string): boolean => parent === '0' || child !== '0' && BigInt(child) <= BigInt(parent);
/** 固定证书v5域；原v1-v4解析器不接受此wrapper。 */
export function enrollmentV5Fields(certificate: EnrollmentApprovalV5): string[] {
  exact(certificate, ['certificateVersion', 'capabilities', 'context', 'pairingProfile', 'transcriptHash', 'grants', 'issuerProof', 'approverSignature', ...(Object.hasOwn(certificate ?? {}, 'initiatorSignature') ? ['initiatorSignature'] : [])]);
  if (certificate.certificateVersion !== '5' || JSON.stringify(certificate.capabilities) !== JSON.stringify([recoveryDAGCapability])) fail();
  const c = certificate.context;
  exact(c, ['accountId', 'accountGeneration', 'purpose', 'sessionId', 'challengeNonce', 'expiresAt', 'initiatorDeviceId', 'initiatorSigningPublicKey', 'initiatorReceivingPublicKey', 'approverDeviceId', 'approverSigningPublicKey', 'approverReceivingPublicKey']);
  for (const id of [c.accountId, c.sessionId, c.initiatorDeviceId, c.approverDeviceId]) identifier(id);
  generation(c.accountGeneration); generation(c.expiresAt); bytes(c.challengeNonce, 32);
  for (const pub of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey, c.approverSigningPublicKey, c.approverReceivingPublicKey]) bytes(pub, 32);
  if (c.purpose !== 'enroll-device' || c.initiatorDeviceId === c.approverDeviceId || c.initiatorSigningPublicKey === c.initiatorReceivingPublicKey || c.approverSigningPublicKey === c.approverReceivingPublicKey || BigInt(c.expiresAt) > 253402300799n || certificate.issuerProof.accountId !== c.accountId || certificate.issuerProof.accountGeneration !== c.accountGeneration) fail();
  const fields = enrollmentFields(certificate); fields[0] = 'harmonia/device-enrollment/v5'; fields.push(dagHash(certificate.issuerProof)); return fields;
}
/** 仅验证已确认context和签名的历史来源；新接受仍须同Store当前权限与归档重查。 */
export function verifyEnrollmentV5(pin: RecoveryDAGPin, certificate: EnrollmentApprovalV5, confirmed: ConfirmedDAGEnrollment, complete = true): ReturnType<typeof verifyIssuerRecoveryDAG> {
  const fields = canonical(enrollmentV5Fields(certificate)), c = certificate.context;
  if (JSON.stringify(pairingContextFields(c)) !== JSON.stringify(pairingContextFields(confirmed.context)) || certificate.transcriptHash !== confirmed.transcriptHash) fail();
  verify(c.approverSigningPublicKey, fields, certificate.approverSignature);
  if (complete || certificate.initiatorSignature !== undefined) verify(c.initiatorSigningPublicKey, fields, certificate.initiatorSignature!);
  const verified = verifyIssuerRecoveryDAG(pin, certificate.issuerProof), { dag, graph } = verified, source = certificate.issuerProof.source;
  const path: DAGArchive[] = source.kind === 'proof3' ? source.view.path : source.proof.path.map(enrollment => ({ kind: 'paired', enrollment }));
  const targets = source.kind === 'proof3' ? source.view.targets : source.proof.targets, identities = dag.identities, head = dag.head;
  const terminal = path.at(-1);
  let current = graph.identities.get(pin.rootDeviceId)!;
  if (terminal?.kind === 'paired') current = graph.identities.get(terminal.enrollment.approval.context.initiatorDeviceId)!;
  else if (terminal?.kind === 'recovered') current = graph.identities.get(dag.recovered.get(terminal.recoveryEnrollmentHash)!.submission.enrollment.deviceId)!;
  if (!current || current.id !== c.approverDeviceId || current.signing !== c.approverSigningPublicKey || current.receiving !== c.approverReceivingPublicKey || identities.has(c.initiatorDeviceId) || targets.length !== certificate.grants.length) fail();
  for (const pub of [c.initiatorSigningPublicKey, c.initiatorReceivingPublicKey]) {
    if (head.seenKeys.has(pub) || [...identities.values()].some(id => id.signing === pub || id.receiving === pub)) fail();
  }
  const hashes = new Map<string, string>();
  for (const signed of [...sourceAuthorities(source), ...certificate.grants]) {
    const g = signed.grant, h = issuerAuthorityHash(signed);
    for (const key of [`${g.environmentId}/${g.subjectDeviceId}/${g.grantGeneration}`, `${g.issuerDeviceId}/${g.idempotencyKey}`]) { if (hashes.has(key) && hashes.get(key) !== h) fail(); hashes.set(key, h); }
  }
  for (const signed of certificate.grants) {
    const g = signed.grant, target = targets.find(t => t.environmentId === g.environmentId), parent = target && graph.authorities.get(target.authorityHash)?.grant.grant;
    if (!parent || parent.role !== 'admin' || parent.subjectDeviceId !== current.id || parent.subjectSigningPublicKey !== current.signing || parent.subjectReceivingPublicKey !== current.receiving || parent.environmentId !== g.environmentId || parent.keyVersion !== g.keyVersion || !within(g.expiresAt, parent.expiresAt) || g.accountId !== pin.accountId || g.accountGeneration !== pin.accountGeneration || g.issuerDeviceId !== current.id || g.subjectDeviceId !== c.initiatorDeviceId || g.subjectSigningPublicKey !== c.initiatorSigningPublicKey || g.subjectReceivingPublicKey !== c.initiatorReceivingPublicKey || g.grantGeneration !== '1' || g.role === 'none') fail();
    verify(current.signing, grantBytes(g), signed.signature);
  }
  return verified;
}
function sourceAuthorities(source: IssuerRecoveryDAG['source']): SignedGrant[] { return (source.kind === 'proof2' ? source.proof.authorities : source.view.authorities).map(n => n.grant); }

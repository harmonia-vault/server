import { Fault } from './model.js';
import type { Store } from './store.js';
import { requestProtocolMajor } from './protocol-info.js';
import { strictRecoveryJson } from './strict-recovery-body.js';
import { RecoveryOperationResolutionService } from './recovery-operation-resolution.js';
import { recoveryOperationClosureCapability, maxResolutionBytes, type ResolutionRequest } from './recovery-operation-resolution-wire.js';

export async function recoveryOperationResolutionRoute(request: Request, store: Store): Promise<{handled: boolean; result?: unknown}> {
  const u = new URL(request.url), m = u.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/recovery-operation-resolutions-v1$/);
  if (!m) return {handled: false};
  requestProtocolMajor(request);
  if (request.method !== 'POST') throw new Fault(405, 'method_not_allowed');
  if (u.searchParams.get('capability') !== recoveryOperationClosureCapability || [...u.searchParams.keys()].join('|') !== 'capability' || u.searchParams.getAll('capability').length !== 1) throw new Fault(400, 'recovery_capability_required');
  const token = request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1], accountGeneration = request.headers.get('x-harmonia-account-generation');
  if (!token || !accountGeneration) throw new Fault(401, 'unauthorized');
  if (!request.headers.get('content-type')?.startsWith('application/json')) throw new Fault(415, 'json_required');
  const reader = request.body?.getReader(); if (!reader) throw new Fault(400, 'body_required');
  const parts: Uint8Array[] = []; let total = 0;
  try { for (;;) { const part = await reader.read(); if (part.done) break; total += part.value.length;
    if (total > maxResolutionBytes) { await reader.cancel(); throw new Fault(413, 'body_too_large'); } parts.push(part.value); } }
  finally { reader.releaseLock(); }
  const body = strictRecoveryJson(Buffer.concat(parts)) as unknown as ResolutionRequest;
  return {handled: true, result: await new RecoveryOperationResolutionService(store).resolve(m[1]!, {token, accountGeneration}, body)};
}

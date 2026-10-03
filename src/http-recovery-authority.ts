import { Fault } from "./model.js";
import type { Store } from "./store.js";
import type { RecoveryAuth } from "./lifecycle-wire.js";
import { strictRecoveryBody } from "./strict-recovery-body.js";
import { RecoveryAuthorityService } from "./recovery-authority.js";
import { recoveryAuthorityCapability, type RecoveryTransitionSubmission } from "./recovery-authority-wire.js";
import type { RecoveredDeviceSubmission } from "./recovered-device-wire.js";
export async function recoveryAuthorityRoute(request: Request, store: Store): Promise<{
    handled: boolean;
    result?: unknown;
}> {
    const url = new URL(request.url), m = url.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(recovery-authority-challenges|recovery-authority-transitions|recovered-device-challenges|recovered-devices|recovery-vault)(?:\/([A-Za-z0-9._:-]+))?$/);
    if (!m)
        return { handled: false };
    const op = m[2]!, operationId = m[3];
    if (op === 'recovery-vault' && url.searchParams.get('capability') !== recoveryAuthorityCapability)
        return { handled: false };
    const keys = [...url.searchParams.keys()];
    if (url.searchParams.get('capability') !== recoveryAuthorityCapability || url.searchParams.getAll('capability').length !== 1 || keys.some(k => k !== 'capability' && (op !== 'recovery-vault' || k !== 'envelopeEvidence')) || op === 'recovery-vault' && (url.searchParams.get('envelopeEvidence') !== 'recovery-envelope-v1' || url.searchParams.getAll('envelopeEvidence').length !== 1))
        throw new Fault(400, 'recovery_capability_required');
    const token = request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1], accountGeneration = request.headers.get('x-harmonia-account-generation'), deviceId = request.headers.get('x-harmonia-device-id');
    if (!token || !accountGeneration)
        throw new Fault(401, 'unauthorized');
    const auth: RecoveryAuth = { token, accountGeneration, ...(deviceId ? { deviceId } : {}) }, service = new RecoveryAuthorityService(store), id = m[1]!;
    let result: unknown;
    if (request.method === 'POST' && !operationId) {
        const b = await strictRecoveryBody(request);
        switch (op) {
            case 'recovery-authority-challenges':
                result = await service.challenge(id, auth, b as unknown as Parameters<RecoveryAuthorityService['challenge']>[2]);
                break;
            case 'recovery-authority-transitions':
                result = await service.transition(id, auth, b as unknown as RecoveryTransitionSubmission);
                break;
            case 'recovered-device-challenges':
                result = await service.recoveredChallenge(id, auth, b as unknown as Parameters<RecoveryAuthorityService['recoveredChallenge']>[2]);
                break;
            case 'recovered-devices':
                result = await service.recoverDevice(id, auth, b as unknown as RecoveredDeviceSubmission);
                break;
            default: throw new Fault(405, 'method_not_allowed');
        }
    }
    else if (request.method === 'GET' && operationId && op === 'recovery-authority-transitions')
        result = await service.transitionStatus(id, auth, operationId);
    else if (request.method === 'GET' && operationId && op === 'recovered-devices')
        result = await service.recoveredStatus(id, auth, operationId);
    else if (request.method === 'GET' && !operationId && op === 'recovery-vault')
        result = await service.vault(id, auth);
    else
        throw new Fault(405, 'method_not_allowed');
    return { handled: true, result };
}

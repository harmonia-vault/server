import { Fault } from './model.js';
import { recoveryOperationClosureCapability } from './recovery-operation-resolution-wire.js';
import { recoveryDAGCapability } from './recovery-dag-wire.js';

export const protocolMajorHeader = 'Harmonia-Protocol-Major';
export function protocolInfo() {
  return { supportedProtocolMajors: [2], capabilities: {
    '2': [recoveryDAGCapability, recoveryOperationClosureCapability, 'registration-policy-v1', 'email-proof-v1'],
  } };
}
export function requestProtocolMajor(request: Request): 2 {
  if (request.headers.get(protocolMajorHeader) !== '2') throw new Fault(426, 'protocol_major_unsupported');
  return 2;
}
export function protocolInfoResponse(request: Request): Response {
  if (request.method !== 'GET') throw new Fault(405, 'method_not_allowed');
  if (new URL(request.url).search) throw new Fault(400, 'query_forbidden');
  return withProtocolMajor(Response.json(protocolInfo(), { headers: {
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  } }));
}
export function withProtocolMajor(response: Response): Response {
  const headers = new Headers(response.headers); headers.set(protocolMajorHeader, '2');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

import { Fault } from './model.js';
import { recoveryDAGCapability } from './recovery-dag-wire.js';

export const protocolMajorHeader = 'Harmonia-Protocol-Major';
/** 产品版本、URL版本和证书数字均不代替此独立协议协商。 */
export function protocolInfo(): {
  supportedProtocolMajors: [1, 2]; capabilities: { '1': string[]; '2': [typeof recoveryDAGCapability] };
} {
  return { supportedProtocolMajors: [1, 2], capabilities: {
    '1': ['issuer-origin-v1', 'issuer-recovery-v1', 'registration-policy-v1', 'email-proof-v1'],
    '2': [recoveryDAGCapability],
  } };
}
export function requestProtocolMajor(request: Request, requiresDAG = false): 1 | 2 {
  const u=new URL(request.url);
  requiresDAG ||= u.searchParams.get('capability')===recoveryDAGCapability || /\/(?:recovery-authority-(?:challenges|transitions)-v2|recovered-(?:device-challenges|devices)-v2|recovery-vault-v2|pairings-v5)(?:\/|$)/.test(u.pathname);
  const value = request.headers.get(protocolMajorHeader);
  // 旧客户端没有该字段时维持major1；逗号合并值或非规范数字不能成为major2。
  if (value !== null && value !== '1' && value !== '2') throw new Fault(426, 'protocol_major_unsupported');
  const major = value === '2' ? 2 : 1;
  if (requiresDAG && major !== 2) throw new Fault(426, 'protocol_upgrade_required');
  return major;
}
export function protocolInfoResponse(request: Request): Response {
  const url = new URL(request.url);
  if (request.method !== 'GET') throw new Fault(405, 'method_not_allowed');
  if (url.search) throw new Fault(400, 'query_forbidden');
  const major=requestProtocolMajor(request);
  return withProtocolMajor(Response.json(protocolInfo(), { headers: {
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  } }),major);
}
/** 包括失败响应在内每请求回显实际选择的major，不默默响应另一profile。 */
export function withProtocolMajor(response: Response, major: 1 | 2): Response {
  const headers = new Headers(response.headers); headers.set(protocolMajorHeader, String(major));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

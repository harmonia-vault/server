import test from 'node:test';
import assert from 'node:assert/strict';
import { protocolInfo, protocolInfoResponse, requestProtocolMajor, withProtocolMajor } from '../src/protocol-info.js';
import { Fault } from '../src/model.js';
const request = (major?: string) => new Request('https://example.invalid/protocol-info', { headers: major === undefined ? {} : { 'Harmonia-Protocol-Major': major } });
test('协议只接受 major2，缺失或旧版本均拒绝', async () => {
  assert.deepEqual(protocolInfo().supportedProtocolMajors, [2]);
  assert.deepEqual(protocolInfo().capabilities['2'], ['issuer-recovery-dag-v1','recovery-operation-closure-v1','registration-policy-v1','email-proof-v1']);
  assert.equal(requestProtocolMajor(request('2')), 2);
  assert.throws(() => requestProtocolMajor(request()), (e: unknown) => e instanceof Fault && e.status === 426 && e.code === 'protocol_major_unsupported');
  for (const value of ['0','1','02','3','1, 2','5']) assert.throws(() => requestProtocolMajor(request(value)), (e: unknown) => e instanceof Fault && e.status === 426);
  const response = protocolInfoResponse(request()); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), protocolInfo());
});
test('协议发现拒绝未知query/错误method，错误响应也绑定明确major', () => {
  assert.throws(() => protocolInfoResponse(new Request('https://example.invalid/protocol-info?capability=other')));
  assert.throws(() => protocolInfoResponse(new Request('https://example.invalid/protocol-info',{method:'POST'})));
  const response = withProtocolMajor(Response.json({error:'recovery_dag_invalid'},{status:403}));
  assert.equal(response.status,403);assert.equal(response.headers.get('Harmonia-Protocol-Major'),'2');
});

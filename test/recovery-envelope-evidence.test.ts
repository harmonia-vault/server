import test from 'node:test';
import assert from 'node:assert/strict';
import {ed25519} from '@noble/curves/ed25519.js';
import {environmentChangeBytes} from '../src/environments.js';
import {environmentChangeHash} from '../src/environment-origin.js';
import {transitionBytesV2} from '../src/recovery-dag-wire.js';
import {nodeHarness,workerHarness,setupEnvironments,freshRecovery,b64,seeds,verifyGraph,type Harness} from './recovery-origin-fixtures.js';
import {transitionPacket} from './recovered-management-fixtures.js';
const path='/recovery-vault-v2?capability=issuer-recovery-dag-v1';
async function rotate(h:Harness) {
  const c=await h.send('/recovery-authority-challenges-v2?capability=issuer-recovery-dag-v1','POST',{operationId:'continuous-1',authorizationKind:'old-recovery'},'R');
  assert.equal(c.status,200,JSON.stringify(c.data));
  const submission=transitionPacket(h,c.data),r=await h.send('/recovery-authority-transitions-v2?capability=issuer-recovery-dag-v1','POST',{submission,dependencyBundle:c.data.dependencyBundle},'R');
  assert.equal(r.status,200,JSON.stringify(r.data));return {submission,sequence:r.data.sequence};
}
for(const [runtime,create] of [['Node TCP',nodeHarness],['workerd HTTP',workerHarness]] as const) {
  test(`${runtime} 恢复封套与环境签名、当前DAG在同一快照返回`,async()=>{
    const h=await create();try {
      await setupEnvironments(h);await freshRecovery(h);
      const r=await h.send(path,'GET',undefined,'R');assert.equal(r.status,200,JSON.stringify(r.data));verifyGraph(r.data.issuerEvidence);
      const evidence=r.data.envelopeEvidence;assert.deepEqual(Object.keys(evidence).sort(),['environmentChanges','profile']);assert.equal(evidence.environmentChanges.length,2);
      for(const e of evidence.environmentChanges) {
        assert.equal(e.sequence,Number(e.change.change.expectedSequence)+1);
        assert.equal(e.origin.origin.changeHash,environmentChangeHash(environmentChangeBytes(e.change.change),e.change.signature));
        assert.equal(ed25519.verify(Buffer.from(e.change.signature,'base64url'),environmentChangeBytes(e.change.change),ed25519.getPublicKey(seeds.B!)),true);
        assert.equal(e.change.change.recoveryEnvelope,r.data.environments.find((v:any)=>v.environmentId===e.change.change.environmentId).envelope);
      }
      assert.equal((await h.send(path+'&extra=unknown','GET',undefined,'R')).status,400);
      assert.equal((await h.send(path,'GET',undefined,'login')).status,403);
      assert.equal((await h.send('/recovery-vault','GET',undefined,'R')).status,404);
      const accepted=await rotate(h),next=await h.send(path,'GET',undefined,'R');assert.equal(next.status,200,JSON.stringify(next.data));
      const graph=verifyGraph(next.data.issuerEvidence);assert.ok(graph.identities.size>0);assert.equal(next.data.sequence,accepted.sequence);assert.equal(next.data.recoveryGeneration,'2');
      const record=next.data.dependencyBundle.records.find((r:any)=>r.kind==='transition-v2');assert.deepEqual(record.record.submission,accepted.submission);
      assert.equal(ed25519.verify(Buffer.from(accepted.submission.newRecoverySignature,'base64url'),transitionBytesV2(accepted.submission.transition),Buffer.from(accepted.submission.transition.newRecoverySigningPublicKey,'base64url')),true);
      assert.deepEqual(next.data.environments,accepted.submission.envelopes);assert.equal(next.data.rotationRequired,false);
    }finally{await h.close();}
  });
}
test('裸封套不能替换签名承诺，篡改DAG或历史签名拒绝，SQL失败不改变状态',async()=>{
  const h=await nodeHarness();try{
    await setupEnvironments(h);await freshRecovery(h);const original=h.read();
    h.change(a=>{a.environments['environment-Y']!.recoveryEnvelope=b64(Buffer.alloc(80,123));});
    const r=await h.send(path,'GET',undefined,'R');assert.equal(r.status,200);assert.notEqual(r.data.environments.find((e:any)=>e.environmentId==='environment-Y').envelope,r.data.envelopeEvidence.environmentChanges.find((e:any)=>e.change.change.environmentId==='environment-Y').change.change.recoveryEnvelope);
    h.change(a=>Object.assign(a,structuredClone(original)));
    h.change(a=>{a.environmentHistory![0]!.change.change.recoveryEnvelope=b64(Buffer.alloc(80,124));});assert.equal((await h.send(path,'GET',undefined,'R')).status,403);h.change(a=>Object.assign(a,structuredClone(original)));
    await rotate(h);const accepted=h.read();h.change(a=>{const r=a.recoveryDAGHistory!.find(r=>r.kind==='transition-v2')!;if(r.kind==='transition-v2')r.record.submission.newRecoverySignature=b64(Buffer.alloc(64,125));});assert.equal((await h.send(path,'GET',undefined,'R')).status,403);h.change(a=>Object.assign(a,structuredClone(accepted)));
    const before=JSON.stringify(h.read()),restore=h.failNextCommit!();try{assert.equal((await h.send(path,'GET',undefined,'R')).status,500);}finally{restore();}assert.equal(JSON.stringify(h.read()),before);assert.equal((await h.send(path,'GET',undefined,'R')).status,200);
  }finally{await h.close();}
});

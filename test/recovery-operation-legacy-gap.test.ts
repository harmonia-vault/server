import test from 'node:test';
import assert from 'node:assert/strict';
import {closureHarness,intentTarget,transitionCommand,resolutionPath,dagCap} from './recovery-operation-fixtures.js';
import {recoveryKeys} from './fixtures.js';
import {sign,b64} from './recovery-origin-fixtures.js';
import {hash} from '../src/enrollment-wire.js';
import {x25519} from '@noble/curves/ed25519.js';
import type {DAGAuthorityChallenge} from '../src/recovery-dag-service.js';
for(const runtime of ['NodeTCP','workerd'] as const) {
 test(runtime+' independent: closed receipt remains queryable after another DAG transition and rejected legacy route',{timeout:40000},async()=>{
  const h=await closureHarness(runtime);
  try {
   await h.session('R');await h.session('S');
   const target=await intentTarget(h,'independent-closed-before-legacy');
   const closed=await h.send(resolutionPath,'POST',await h.request(target,'resolve-or-close'),'S');
   assert.equal(closed.status,200,closed.data.error);assert.equal(closed.data.state,'closed');
   const c=await h.send('/recovery-authority-challenges-v2?'+dagCap,'POST',{operationId:'independent-proposal-only',authorizationKind:'old-recovery'});
   assert.equal(c.status,200,c.data.error);
   const p=transitionCommand(h,c.data as DAGAuthorityChallenge),t=p.submission.transition;
   const beforeLegacy=await h.read();assert.equal((await h.send('/recovery-rotations','POST',{})).status,404);assert.deepEqual(await h.read(),beforeLegacy);
   const complete=await h.send('/recovery-authority-transitions-v2?'+dagCap,'POST',p);assert.equal(complete.status,200,complete.data.error);
   await h.session('S-current',Buffer.alloc(32,71),'2');
   const before=await h.read();assert.equal(before.recoveryGeneration,'2');assert.equal(before.recoveryOperationClosures!.entries[target.operationId]!.sequence,closed.data.sequence);
   const query=await h.send(resolutionPath,'POST',await h.request(target,'query','S-current'),'S-current');
   assert.equal(query.status,200,'fresh authenticated current-code query: '+query.data.error);assert.deepEqual(query.data,closed.data);
   assert.deepEqual((await h.send(resolutionPath,'POST',await h.request(target,'resolve-or-close','S-current'),'S-current')).data,closed.data);
   const noPermission=await h.send(resolutionPath,'POST',await h.request(target,'query','login'),'login');assert.equal(noPermission.status,403);assert.equal(noPermission.data.error,'recovery_rotation_required');
   const stale=await h.send(resolutionPath,'POST',await h.request(target,'query','S'),'S');assert.equal(stale.status,401);assert.equal(stale.data.error,'unauthorized');
   const wrongGen=await h.send(resolutionPath,'POST',await h.request(target,'query','S-current'),'S-current',{generation:'2'});assert.equal(wrongGen.status,401);
   for(const changed of [{...target,declaredIntentHash:hash(['other-original'])},{...target,deviceReceivingPublicKey:b64(x25519.getPublicKey(Buffer.alloc(32,117)))},{...target,basis:{...target.basis,expectedSequence:String(before.sequence)}}]){
    const mismatch=await h.send(resolutionPath,'POST',await h.request(changed,'query','S-current'),'S-current');assert.equal(mismatch.status,409);assert.equal(mismatch.data.error,'idempotency_conflict');
   }
   const newID={...target,operationId:'no-terminal-new-id-after-transition'},resolved=await h.send(resolutionPath,'POST',await h.request(newID,'resolve-or-close','S-current'),'S-current');assert.equal(resolved.status,200);assert.equal(resolved.data.state,'closed');
   const after=await h.read();assert.equal(after.sequence,before.sequence+1);assert.deepEqual(after.recoveryOperationClosures!.entries[target.operationId],before.recoveryOperationClosures!.entries[target.operationId]);


  }finally{await h.close();}
 });
}

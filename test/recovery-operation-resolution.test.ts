import test from 'node:test';
import assert from 'node:assert/strict';
import {ed25519,x25519} from '@noble/curves/ed25519.js';
import {b64,seeds} from './recovery-origin-fixtures.js';
import {hash} from '../src/enrollment-wire.js';
import {verifyRecoveryDependencyBundle} from '../src/recovery-dag.js';
import {accountDAGPin} from '../src/recovery-dag-account.js';
import {resolutionTargetHash} from '../src/recovery-operation-resolution-wire.js';
import {closureHarness,intentTarget,challengedTarget,sealedTarget,transitionCommand,protectedAuthority,resolutionPath,dagCap,localEd,localX,type ClosureHarness} from './recovery-operation-fixtures.js';
import type {DAGAuthorityChallenge, DAGRecoveredChallenge} from '../src/recovery-dag-service.js';
import {pendingRecoveryOperationIds,assertRecoveryOperationCapacity,type RecoveryOperationAccount} from '../src/recovery-operation-guards.js';

const create = async (h: ClosureHarness,id: string, who='R') => {
  const r=await h.send(`/recovery-authority-challenges-v2?${dagCap}`,'POST',{operationId:id,authorizationKind:who==='A'?'all-environments-admin':'old-recovery',chainMode:'continuous'},who);
  assert.equal(r.status,200,r.data.error);return r.data as DAGAuthorityChallenge;
};
const close = async (h: ClosureHarness,t: Parameters<ClosureHarness['request']>[0],mode: 'query'|'resolve-or-close'='resolve-or-close', who='S') => h.send(resolutionPath,'POST',await h.request(t,mode,who),who);
for (const runtime of ['NodeTCP','workerd'] as const) {
  test(`${runtime} 1/6：接受优先，失效会话拒绝后fresh当前码查询原hash/seq，无覆盖`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');const t0=await intentTarget(h,'accepted-original'),c=await create(h,t0.operationId),p=transitionCommand(h,c),t=sealedTarget(challengedTarget(t0,c),p);
      await h.session('S');const stale=await h.request(t,'resolve-or-close');const accepted=await h.send(`/recovery-authority-transitions-v2?${dagCap}`,'POST',p);assert.equal(accepted.status,200,accepted.data.error);
      const refused=await h.send(resolutionPath,'POST',stale,'S');assert.ok([401,403].includes(refused.status));assert.equal((await h.read()).recoveryOperationClosures,undefined);
      await h.session('S',Buffer.alloc(32,71),'2');const r=await close(h,t);assert.equal(r.status,200,r.data.error);assert.equal(r.data.state,'accepted');assert.equal(r.data.contentHash,t.declaredContentHash);assert.equal(r.data.sequence,accepted.data.sequence);
      assert.deepEqual((await close(h,t,'query')).data,r.data);assert.equal((await h.read()).sequence,accepted.data.sequence);
      assert.equal((await close(h,{...t,declaredContentHash:hash(['different'])})).status,409);assert.equal((await close(h,{...t,originalSessionHash:hash(['different-session'])})).status,409);
      assert.equal((await h.read()).recoveryOperationClosures,undefined);
    }finally{await h.close();}
  });
  test(`${runtime} 2/6：关闭优先、持久失败回滚、未知回应同ID重查、合法原包迟到拒绝`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');const t0=await intentTarget(h,'closed-original'),c=await create(h,t0.operationId),p=transitionCommand(h,c),t=sealedTarget(challengedTarget(t0,c),p);
      // 正包先经过成熟完整签链验证，拒绝不能误算成畸形包先失败。
      verifyRecoveryDependencyBundle(accountDAGPin(await h.read()),{initialization:p.dependencyBundle.initialization,records:[...p.dependencyBundle.records,{kind:'transition-v2',record:{submission:p.submission,sequence:Number(c.expectedSequence)+1}}]});
      await h.session('S');const before=await h.read();await h.fault(true);assert.equal((await close(h,t)).status,500);await h.fault(false);
      const rollback=await h.read();assert.equal(rollback.sequence,before.sequence);assert.equal(rollback.recoveryOperationClosures,undefined);assert.deepEqual(protectedAuthority(rollback),protectedAuthority(before));assert.ok(rollback.recoveryDAGChallenges?.[t.operationId]);
      // 合成传输丢弃首次成功回应；结果只能经另一个fresh会话同ID查询确认。
      await close(h,t);await h.session('S-next');const query=await close(h,t,'query','S-next');assert.equal(query.status,200,query.data.error);assert.equal(query.data.state,'closed');assert.equal(query.data.sequence,before.sequence+1);assert.equal(query.data.observedChallengeHash,t.knownChallengeHash);
      const rejected=await h.send(`/recovery-authority-transitions-v2?${dagCap}`,'POST',p);assert.equal(rejected.status,409);assert.equal(rejected.data.error,'operation_closed');
      const after=await h.read();assert.equal(after.sequence,query.data.sequence);assert.deepEqual(protectedAuthority(after),protectedAuthority(before));assert.equal(after.recoveryDAGChallenges?.[t.operationId],undefined);assert.deepEqual((await close(h,t,'resolve-or-close','S-next')).data,query.data);
    }finally{await h.close();}
  });
  test(`${runtime} 3/6：无挑战先封锁、丢挑战回应可闭锁、跨kind/profile/rotation禁止复用`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');await h.session('S');const t=await intentTarget(h,'intent-never-arrived');const before=(await h.read()).sequence;
      assert.equal((await close(h,t,'query')).data.state,'pending');assert.equal((await h.read()).recoveryOperationClosures,undefined);
      const r=await close(h,t);assert.equal(r.status,200,r.data.error);assert.equal(r.data.observedChallengeHash,null);assert.equal(r.data.sequence,before+1);
      const late=await h.send(`/recovery-authority-challenges-v2?${dagCap}`,'POST',{operationId:t.operationId,authorizationKind:'old-recovery',chainMode:'continuous'});assert.equal(late.data.error,'operation_closed');
      const device={operationId:t.operationId,deviceId:'late-device',deviceSigningPublicKey:b64(ed25519.getPublicKey(localEd)),deviceReceivingPublicKey:b64(x25519.getPublicKey(localX))};
      for(const route of [`/recovered-device-challenges-v2?${dagCap}`,'/recovered-device-challenges?capability=issuer-recovery-v1']) assert.equal((await h.send(route,'POST',device)).data.error,'operation_closed');
      assert.equal((await h.send('/recovery-authority-challenges?capability=issuer-recovery-v1','POST',{operationId:t.operationId,authorizationKind:'old-recovery',chainMode:'continuous'})).data.error,'operation_closed');
      const other=await create(h,'other-valid-id'),p=transitionCommand(h,other),proposal={idempotencyKey:t.operationId,newRecoveryGeneration:p.submission.transition.newRecoveryGeneration,newRecoverySigningPublicKey:p.submission.transition.newRecoverySigningPublicKey,newRecoveryReceivingPublicKey:p.submission.transition.newRecoveryReceivingPublicKey,envelopes:p.submission.envelopes,newTrustRoot:p.submission.newTrustRoot};
      assert.equal((await h.send('/recovery-rotations','POST',proposal)).data.error,'operation_closed');assert.equal((await h.send(`/recovery-rotations/${t.operationId}/complete`,'POST',{challengeId:other.challengeId,signature:p.submission.newRecoverySignature})).data.error,'operation_closed');
      // 新墓碑不应关闭未使用能力的其他legacy ID。
      assert.equal((await h.send('/recovery-authority-challenges?capability=issuer-recovery-v1','POST',{operationId:'distinct-legacy',authorizationKind:'old-recovery',chainMode:'continuous'})).status,200);
      const lost=await intentTarget(h,'challenge-response-lost');await create(h,lost.operationId);const observed=await close(h,lost);assert.equal(observed.status,200,observed.data.error);assert.match(observed.data.observedChallengeHash,/^[0-9a-f]{64}$/);
      assert.equal((await close(h,{...lost,declaredIntentHash:hash(['another-claim'])})).status,409);
      const collision=await intentTarget(h,'collision-existing'),c=await create(h,collision.operationId),known=challengedTarget(collision,c);
      assert.equal((await close(h,{...known,originalSessionHash:hash(['wrong'])})).status,409);assert.equal((await close(h,{...known,knownChallengeHash:hash(['wrong'])})).status,409);assert.ok((await h.read()).recoveryDAGChallenges?.[known.operationId]);
    }finally{await h.close();}
  });
  test(`${runtime} 4/6：实际并发HTTP create/close和submit/close，独立SQLite连接或同账号DO线性化`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');await h.session('S');const t=await intentTarget(h,'concurrent-create'),request=await h.request(t,'resolve-or-close');
      const [created,closed]=await Promise.all([h.send(`/recovery-authority-challenges-v2?${dagCap}`,'POST',{operationId:t.operationId,authorizationKind:'old-recovery',chainMode:'continuous'},'R',{peer:true}),h.send(resolutionPath,'POST',request,'S')]);
      assert.ok(created.status===200||created.data.error==='operation_closed');assert.equal(closed.status,200,closed.data.error);assert.equal(closed.data.state,'closed');const a=await h.read();assert.equal(a.sequence,Number(t.basis.expectedSequence)+1);assert.equal(a.recoveryDAGChallenges?.[t.operationId],undefined);
      const t0=await intentTarget(h,'concurrent-submit'),c=await create(h,t0.operationId),p=transitionCommand(h,c),sealed=sealedTarget(challengedTarget(t0,c),p),req=await h.request(sealed,'resolve-or-close');
      const [submitted,resolved]=await Promise.all([h.send(`/recovery-authority-transitions-v2?${dagCap}`,'POST',p,'R',{peer:true}),h.send(resolutionPath,'POST',req,'S')]);
      const final=await h.read();assert.equal(final.sequence,Number(c.expectedSequence)+1);const accepted=final.recoveryDAGHistory?.some(r=>r.kind==='transition-v2'&&r.record.submission.transition.operationId===sealed.operationId)??false,terminal=!!final.recoveryOperationClosures?.entries[sealed.operationId];assert.notEqual(accepted,terminal);
      if(accepted){assert.equal(submitted.status,200,submitted.data.error);assert.ok([401,403].includes(resolved.status));await h.session('S',Buffer.alloc(32,71),'2');assert.equal((await close(h,sealed,'query')).data.state,'accepted');}
      else{assert.equal(resolved.data.state,'closed');assert.equal(submitted.data.error,'operation_closed');assert.equal((await close(h,sealed,'query')).data.state,'closed');}
    }finally{await h.close();}
  });
  test(`${runtime} 5/6：重启/后续恢复代际保留收据，永久预算不驱逐，满字节空间整体拒绝`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');await h.session('S');const t=await intentTarget(h,'across-recovery-generation'),closed=await close(h,t);assert.equal(closed.status,200,closed.data.error);
      const c=await create(h,'later-generation'),p=transitionCommand(h,c);assert.equal((await h.send(`/recovery-authority-transitions-v2?${dagCap}`,'POST',p)).status,200);
      await h.session('S',Buffer.alloc(32,71),'2');assert.deepEqual((await close(h,t,'query')).data,closed.data);await h.restart();assert.deepEqual((await close(h,t,'query')).data,closed.data);
      await h.session('R',Buffer.alloc(32,71),'2');const held=await intentTarget(h,'preexisting-budget-reservation'),ch=await create(h,held.operationId),heldTarget=challengedTarget(held,ch),a=await h.read(),template=a.recoveryOperationClosures!.entries[t.operationId]!;
      for(let i=0;i<255;i++){const id='budget-'+i,entry=structuredClone(template);entry.target.operationId=id;entry.targetHash=resolutionTargetHash(entry.target);entry.sequence=++a.sequence;a.recoveryOperationClosures!.entries[id]=entry;}
      assert.deepEqual([...pendingRecoveryOperationIds(a)],[held.operationId]);const allocationBoundary=structuredClone(a);delete allocationBoundary.recoveryOperationClosures!.entries['budget-254'];delete allocationBoundary.recoveryDAGChallenges![held.operationId];assert.doesNotThrow(()=>assertRecoveryOperationCapacity(allocationBoundary,'new-at-255'));allocationBoundary.recoveryDAGChallenges![held.operationId]=ch;assert.throws(()=>assertRecoveryOperationCapacity(allocationBoundary,'new-at-256'),/account_capacity_reached/);
      await h.replace(a);const unknown=await intentTarget(h,'no-budget-new-id'),blocked=await close(h,unknown);assert.equal(blocked.status,503);assert.equal(blocked.data.error,'account_capacity_reached');assert.equal((await h.read()).sequence,a.sequence);assert.deepEqual((await close(h,t,'query')).data,closed.data);
      assert.equal((await h.send(`/recovery-authority-challenges-v2?${dagCap}`,'POST',{operationId:'new-reservation',authorizationKind:'old-recovery',chainMode:'continuous'})).status,503);
      const swapped=await close(h,heldTarget);assert.equal(swapped.status,200,swapped.data.error);assert.equal(swapped.data.sequence,a.sequence+1);assert.equal(Object.keys((await h.read()).recoveryOperationClosures!.entries).length,257);
    }finally{await h.close();}
    const full=await closureHarness(runtime);try{
      await full.session('R');await full.session('S');const target=await intentTarget(full,'no-byte-space'),a=await full.read(),padded=a as RecoveryOperationAccount&{syntheticCapacityPadding:string};padded.syntheticCapacityPadding='x'.repeat(1_000_000-Buffer.byteLength(JSON.stringify(a))-128);assert.ok(Buffer.byteLength(JSON.stringify(padded))<1_000_000);await full.replace(padded);
      const r=await close(full,target);assert.equal(r.status,503);assert.equal(r.data.error,'account_capacity_reached');const after=await full.read();assert.equal(after.sequence,a.sequence);assert.equal(after.recoveryOperationClosures,undefined);
    }finally{await full.close();}
  });
  test(`${runtime} 6/6：统一strict读写迁移、当前proof/双钥绑定、wire/major和损坏状态拒绝`,{timeout:40000},async()=>{
    const h=await closureHarness(runtime);try {
      await h.session('R');await h.session('S');const t=await intentTarget(h,'strict-wire-original'),r=await h.request(t,'query'),before=await h.read();
      const loginRequest=await h.request(t,'query','login');const loginDenied=await h.send(resolutionPath,'POST',loginRequest,'login');assert.equal(loginDenied.status,403);assert.equal(loginDenied.data.error,'recovery_rotation_required');assert.equal((await h.send(resolutionPath,'POST',r,'S',{generation:'2'})).status,401);assert.equal((await h.send(resolutionPath,'POST',r,'S',{major:'1'})).status,426);
      assert.equal((await close(h,{...t,basis:{...t.basis,expectedSequence:String(before.sequence+1)}})).status,409);
      const wrong=structuredClone(r);wrong.target.deviceSigningPublicKey=b64(ed25519.getPublicKey(Buffer.alloc(32,121)));assert.equal((await h.send(resolutionPath,'POST',wrong,'S')).status,403);
      const dup=JSON.stringify(r).replace('"mode":"query"','"mode":"query","mode":"query"');assert.equal((await h.send(resolutionPath,'POST',undefined,'S',{raw:dup})).status,400);
      assert.equal((await h.send(resolutionPath,'POST',undefined,'S',{raw:new Uint8Array([123,255,125])})).status,400);assert.equal((await h.send(resolutionPath+'&token=forbidden','POST',r,'S')).status,400);
      assert.equal((await h.send(resolutionPath,'POST',{...r,extra:true},'S')).status,400);assert.equal((await h.send(resolutionPath,'POST',undefined,'S',{raw:' '.repeat(8193)})).status,413);assert.equal((await h.read()).sequence,before.sequence);assert.equal((await h.read()).recoveryOperationClosures,undefined);
      // all-admin旧挑战精确身份仍由已验来源图证明，不借新恢复权填caller。
      const ca=await create(h,'admin-original','A'),admin=challengedTarget(await intentTarget(h,ca.operationId),ca),root=h.account.devices['device-A']!;admin.deviceId=root.id;admin.deviceSigningPublicKey=root.signingPublicKey;admin.deviceReceivingPublicKey=root.receivingPublicKey;
      const bad=structuredClone(admin);bad.deviceReceivingPublicKey=b64(x25519.getPublicKey(Buffer.alloc(32,122)));const br=await h.request(bad,'resolve-or-close','S',seeds.A!);assert.equal((await h.send(resolutionPath,'POST',br,'S')).status,409);assert.equal((await h.read()).recoveryOperationClosures,undefined);
      const ar=await h.request(admin,'resolve-or-close','S',seeds.A!);assert.equal((await h.send(resolutionPath,'POST',ar,'S')).status,200);
      const valid=await h.read(),entry=valid.recoveryOperationClosures!.entries[admin.operationId]!;
      for(const corrupt of ['version','target-hash','challenge-collision'] as const){const a=structuredClone(valid);if(corrupt==='version')(a.recoveryOperationClosures as unknown as {version:number}).version=2;else if(corrupt==='target-hash')a.recoveryOperationClosures!.entries[admin.operationId]!.targetHash=hash(['wrong']);else a.recoveryDAGChallenges={...a.recoveryDAGChallenges,[admin.operationId]:ca};await h.replace(a);const v=await h.send(`/recovery-vault-v2?${dagCap}`);assert.equal(v.status,409);assert.equal(v.data.error,'recovery_operation_state_invalid');await h.replace(valid);}
      assert.equal((await h.read()).recoveryOperationClosures!.entries[admin.operationId]!.targetHash,entry.targetHash);
      // 已接受/已关闭不能同时存在；这里用真正接受过的原包验证统一读边界。
      const tc=await create(h,'real-accepted-for-collision'),tp=transitionCommand(h,tc);assert.equal((await h.send(`/recovery-authority-transitions-v2?${dagCap}`,'POST',tp)).status,200);
      await h.session('S',Buffer.alloc(32,71),'2');const afterAccepted=await h.read(),collision=structuredClone(afterAccepted),fake=structuredClone(entry);fake.target.operationId=tc.operationId;fake.targetHash=resolutionTargetHash(fake.target);fake.sequence=++collision.sequence;collision.recoveryOperationClosures!.entries[tc.operationId]=fake;await h.replace(collision);
      const refusedCollision=await h.send(`/recovery-vault-v2?${dagCap}`);assert.equal(refusedCollision.status,409);assert.equal(refusedCollision.data.error,'recovery_operation_state_invalid');await h.replace(afterAccepted);
      // recovered-v2 挑战只有实际冻结的目标双钥；错收钥必须先拒绝且不写墓碑。
      const rt0=await intentTarget(h,'recovered-device-original'),rr=await h.send(`/recovered-device-challenges-v2?${dagCap}`,'POST',{operationId:rt0.operationId,deviceId:rt0.deviceId,deviceSigningPublicKey:rt0.deviceSigningPublicKey,deviceReceivingPublicKey:rt0.deviceReceivingPublicKey});assert.equal(rr.status,200,rr.data.error);
      const recovered=challengedTarget(rt0,rr.data as DAGRecoveredChallenge,'recovered-v2'),wrongRecovered={...recovered,deviceReceivingPublicKey:b64(x25519.getPublicKey(Buffer.alloc(32,123)))};assert.equal((await close(h,wrongRecovered)).status,409);assert.equal((await h.read()).recoveryOperationClosures!.entries[recovered.operationId],undefined);assert.ok((await h.read()).recoveredDAGChallenges?.[recovered.operationId]);
      const rc=await close(h,recovered);assert.equal(rc.status,200,rc.data.error);assert.equal(rc.data.state,'closed');assert.equal(rc.data.observedChallengeHash,recovered.knownChallengeHash);assert.equal((await h.read()).recoveredDAGChallenges?.[recovered.operationId],undefined);

    }finally{await h.close();}
  });
}

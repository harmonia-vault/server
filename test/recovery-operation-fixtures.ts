import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {build} from 'esbuild';
import {Miniflare} from 'miniflare';
import {ed25519, x25519} from '@noble/curves/ed25519.js';
import {nodeStore} from '../src/node-store.js';
import {nodeServer} from '../src/node-runtime.js';
import {VaultService, tokenHash} from '../src/service.js';
import {canonical, hash} from '../src/enrollment-wire.js';
import {recoveryKeys} from './fixtures.js';
import {nodeHarness, b64, sign, seeds} from './recovery-origin-fixtures.js';
import {trustRootPayload} from '../src/trust-root.js';
import {verifiedAccountDAG, accountDAGBundle} from '../src/recovery-dag-account.js';
import {recoveryManifestHash, recoveryAdminHash, recoveryEnvelopesHash, recoveryRootHash, initializationReference} from '../src/recovery-authority-wire.js';
import {sourceHash, transitionBytesV2, transitionHashV2, type RecoveryTransitionCommandV2} from '../src/recovery-dag-wire.js';
import {dependencyBasisHash, operationChallengeHash, resolutionSigningFields, type ResolutionRequest, type ResolutionTarget} from '../src/recovery-operation-resolution-wire.js';
import type {DAGAuthorityChallenge, DAGRecoveredChallenge} from '../src/recovery-dag-service.js';
import type {RecoveryOperationAccount} from '../src/recovery-operation-guards.js';

export const dagCap = 'capability=issuer-recovery-dag-v1';
export const resolutionPath = '/recovery-operation-resolutions-v1?capability=recovery-operation-closure-v1';
export const localEd = Buffer.alloc(32, 101), localX = Buffer.alloc(32, 102);
export type Reply = {status: number; major: string | null; data: any};
const vector = JSON.parse(readFileSync(new URL('./vectors/recovery-authority-v1.json', import.meta.url), 'utf8'));
let built: Promise<string> | undefined;
export async function closureHarness(runtime: 'NodeTCP' | 'workerd') {
  const original = await nodeHarness(); const account = structuredClone(original.read()) as RecoveryOperationAccount; await original.close();
  const dir = mkdtempSync(join(tmpdir(), 'harmonia-closure-')), tokens = new Map([['login', b64(Buffer.alloc(32,61))], ['A', b64(Buffer.alloc(32,65))]]);
  let db: ReturnType<typeof nodeStore> | undefined, second: ReturnType<typeof nodeStore> | undefined;
  let server: ReturnType<typeof nodeServer> | undefined, peer: ReturnType<typeof nodeServer> | undefined, mf: Miniflare | undefined;
  let base = '', peerBase = '';
  const script = runtime === 'workerd' ? await (built ??= build({entryPoints: ['test/recovery-operation-worker-harness.ts'], absWorkingDir: process.cwd(), bundle: true, write: false, format: 'esm', platform: 'browser', target: 'es2023', external: ['cloudflare:workers','node:*'], banner: {js: 'import {Buffer} from "node:buffer";'}}).then(r => r.outputFiles[0]!.text)) : '';
  const start = async (create: boolean) => {
    if (runtime === 'NodeTCP') {
      db = nodeStore(join(dir,'accounts.sqlite')); if (create) db.store.create(account);
      second = nodeStore(join(dir,'accounts.sqlite'));
      server = nodeServer(new VaultService(db.store, {allowRegistration: false, requireEmailVerification: true}));
      peer = nodeServer(new VaultService(second.store, {allowRegistration: false, requireEmailVerification: true}));
      for (const s of [server, peer]) {s.server.listen(0,'127.0.0.1'); await once(s.server,'listening');}
      const addr = server.server.address(), paddr = peer.server.address(); assert.ok(addr && typeof addr !== 'string' && paddr && typeof paddr !== 'string');
      base = `http://127.0.0.1:${addr.port}`; peerBase = `http://127.0.0.1:${paddr.port}`;
    } else {
      mf = new Miniflare({modules: true, script, compatibilityDate: '2026-07-30', compatibilityFlags: ['nodejs_compat'], durableObjects: {INSTANCES: {className: 'InstanceRegistry', useSQLite: true}, ACCOUNTS: {className: 'ClosureSyntheticVault', useSQLite: true}, FIXTURES: {className: 'ClosureSyntheticVault', useSQLite: true}}, d1Databases: {DIRECTORY: 'directory'}, durableObjectsPersist: join(dir,'objects'), d1Persist: join(dir,'directory')});
      if (create) {const r = await mf.dispatchFetch('https://synthetic.invalid/test/seed', {method: 'POST', body: JSON.stringify(account)}); assert.equal(r.status,200);}
    }
  };
  const stop = async () => {
    if (mf) {await mf.dispose(); mf = undefined;}
    for (const s of [server,peer]) if (s) {s.closeNotifications(); s.server.close(); await once(s.server,'close');}
    db?.sql.close(); second?.sql.close(); server = undefined; peer = undefined; db = undefined; second = undefined;
  };
  await start(true);
  const read = async (): Promise<RecoveryOperationAccount> => runtime === 'NodeTCP' ? db!.store.read(account.id)! as RecoveryOperationAccount : await (await mf!.dispatchFetch(`https://synthetic.invalid/test/closure/state/${account.id}`)).json() as RecoveryOperationAccount;
  const replace = async (a: RecoveryOperationAccount) => {if (runtime === 'NodeTCP') db!.sql.execute('UPDATE accounts SET data=? WHERE id=?', [JSON.stringify(a),a.id]); else assert.equal((await mf!.dispatchFetch(`https://synthetic.invalid/test/closure/replace/${a.id}`, {method: 'POST', body: JSON.stringify(a)})).status,200);};
  const send = async (path: string, method = 'GET', body?: unknown, who = 'R', options: {major?: string; generation?: string; peer?: boolean; raw?: Uint8Array<ArrayBuffer> | string} = {}): Promise<Reply> => {
    const headers = {'content-type': 'application/json', authorization: 'Bearer '+tokens.get(who), 'x-harmonia-account-generation': options.generation ?? '1', ...(who === 'A' ? {'x-harmonia-device-id': 'device-A'} : {}), ...((options.major ?? '2') ? {'Harmonia-Protocol-Major': options.major ?? '2'} : {})};
    const init = {method, headers, ...(body === undefined && options.raw === undefined ? {} : {body: options.raw ?? JSON.stringify(body)})};
    const response = runtime === 'NodeTCP' ? await fetch((options.peer ? peerBase : base)+`/v1/accounts/${account.id}`+path,init) : await mf!.dispatchFetch(`https://synthetic.invalid/v1/accounts/${account.id}${path}`,init);
    const major=response.headers.get('Harmonia-Protocol-Major');assert.equal(major,options.major??'2');
    return {status: response.status, major, data: await response.json()};
  };
  const session = async (alias: string, seed = Buffer.alloc(32,88), generation = '1') => {
    const c = await send('/recovery-challenges','POST',{accountGeneration: '1'},'login'); assert.equal(c.status,200,c.data.error);
    const k = recoveryKeys(seed,account.id,generation), r = await send('/recovery-sessions','POST',{accountGeneration:'1',challengeId:c.data.challengeId,signature:sign(c.data.signingPayload,k.signingSeed)},'login');assert.equal(r.status,200,r.data.error); tokens.set(alias,r.data.token);
    return r.data.token as string;
  };
  const request = async (target: ResolutionTarget, mode: ResolutionRequest['mode'] = 'query', who = 'S', seed: Uint8Array = localEd): Promise<ResolutionRequest> => {
    const r: ResolutionRequest = {version: 1,mode,target: structuredClone(target),deviceSignature: ''};
    r.deviceSignature = sign(resolutionSigningFields(r,await tokenHash(tokens.get(who)!)),seed);return r;
  };
  return {account,tokens,read,replace,send,session,request, fault: async (on: boolean) => {
    if (runtime === 'NodeTCP') {db!.sql.execute('DROP TRIGGER IF EXISTS synthetic_closure_fault');if (on) db!.sql.execute("CREATE TRIGGER synthetic_closure_fault BEFORE UPDATE ON accounts WHEN json_extract(NEW.data,'$.recoveryOperationClosures') IS NOT NULL AND json_extract(OLD.data,'$.recoveryOperationClosures') IS NULL BEGIN SELECT RAISE(ABORT,'synthetic closure write failure'); END");}
    else assert.equal((await mf!.dispatchFetch(`https://synthetic.invalid/test/closure/fault/${account.id}`,{method:'POST',body:JSON.stringify({on})})).status,200);
  },restart: async () => {await stop();await start(false);},close: async () => {await stop();rmSync(dir,{recursive:true,force:true});}};
}
export type ClosureHarness = Awaited<ReturnType<typeof closureHarness>>;
export async function intentTarget(h: ClosureHarness, id: string): Promise<ResolutionTarget> {
  const a = await h.read(), b = accountDAGBundle(a), d = verifiedAccountDAG(a);
  return {profile: 'issuer-recovery-dag-v1',kind:'transition-v2',accountId:a.id,accountGeneration:a.generation,operationId:id,originalSessionHash:await tokenHash(h.tokens.get('R')!),authorizationKind:'old-recovery',deviceId:'synthetic-local-device',deviceSigningPublicKey:b64(ed25519.getPublicKey(localEd)),deviceReceivingPublicKey:b64(x25519.getPublicKey(localX)),stage:'intent',basis:{initializationHash:initializationReference(b.initialization),expectedSequence:String(a.sequence),recoveryGeneration:d.head.generation,recoveryHeadHash:d.head.head,recoverySigningPublicKey:d.head.signing,recoveryReceivingPublicKey:d.head.receiving,dependencyBundleHash:dependencyBasisHash(b),environmentManifestHash:recoveryManifestHash(Object.values(a.environments).map(e=>({environmentId:e.id,keyVersion:e.keyVersion})).sort((a,b)=>a.environmentId<b.environmentId?-1:1))},declaredIntentHash:hash(['synthetic-intent',id]),knownChallengeHash:'',declaredContentHash:''};
}
export function challengedTarget(target: ResolutionTarget, c: DAGAuthorityChallenge | DAGRecoveredChallenge, kind = target.kind): ResolutionTarget {
  const t = structuredClone(target);t.kind = kind;t.stage = 'challenged';t.knownChallengeHash = operationChallengeHash(t.accountId,kind,c);
  t.basis.expectedSequence = c.expectedSequence;t.basis.dependencyBundleHash = dependencyBasisHash(c.dependencyBundle);
  if (kind === 'transition-v2') {const old = c as DAGAuthorityChallenge; t.originalSessionHash = old.sessionHash;t.authorizationKind = old.authorizationKind;t.basis.recoveryGeneration = old.oldRecoveryGeneration;t.basis.recoveryHeadHash = old.previousTransitionHash;t.basis.recoverySigningPublicKey = old.oldRecoverySigningPublicKey;t.basis.recoveryReceivingPublicKey = old.oldRecoveryReceivingPublicKey;t.basis.environmentManifestHash = recoveryManifestHash(old.environmentManifest);}
  else {const old = c as DAGRecoveredChallenge;t.originalSessionHash=old.restrictedSessionHash;t.deviceId=old.deviceId;t.deviceSigningPublicKey=old.deviceSigningPublicKey;t.deviceReceivingPublicKey=old.deviceReceivingPublicKey;t.basis.recoveryGeneration=old.recoveryGeneration;t.basis.recoveryHeadHash=old.recoveryTransitionHash;}
  return t;
}
export function transitionCommand(h: ClosureHarness, c: DAGAuthorityChallenge, oldSeed = Buffer.alloc(32,88), newSeed = Buffer.alloc(32,71)): RecoveryTransitionCommandV2 {
  const s = structuredClone(vector.oldRecoveryTransition.submission), t = s.transition, newGeneration = String(BigInt(c.oldRecoveryGeneration)+1n), keys = recoveryKeys(newSeed,h.account.id,newGeneration), old = recoveryKeys(oldSeed,h.account.id,c.oldRecoveryGeneration), root = c.dependencyBundle.initialization.proposal.device;
  s.environmentManifest=c.environmentManifest;s.authoritySet=c.authoritySet;s.issuerEvidence=c.issuerEvidence;s.legacyState=null;s.envelopes=c.environmentManifest.map(e=>({...e,envelope:b64(Buffer.alloc(80,41))}));
  s.newTrustRoot={rootDeviceId:root.id,rootSigningPublicKey:root.signingPublicKey,rootReceivingPublicKey:root.receivingPublicKey,recoveryGeneration:newGeneration,recoverySigningPublicKey:keys.signingPublicKey,recoveryReceivingPublicKey:keys.receivingPublicKey,signature:''};s.newTrustRoot.signature=sign(trustRootPayload(h.account.id,'1',s.newTrustRoot),keys.signingSeed);
  Object.assign(t,{accountId:h.account.id,accountGeneration:'1',operationId:c.operationId,challengeId:c.challengeId,nonce:c.nonce,expiresAt:String(c.expiresAt),sessionHash:c.sessionHash,expectedSequence:c.expectedSequence,previousTransitionHash:c.previousTransitionHash,oldRecoveryGeneration:c.oldRecoveryGeneration,oldRecoverySigningPublicKey:c.oldRecoverySigningPublicKey,oldRecoveryReceivingPublicKey:c.oldRecoveryReceivingPublicKey,newRecoveryGeneration:newGeneration,newRecoverySigningPublicKey:keys.signingPublicKey,newRecoveryReceivingPublicKey:keys.receivingPublicKey,authorizationKind:c.authorizationKind,authorizerDeviceId:c.authorizerDeviceId,environmentManifestHash:recoveryManifestHash(s.environmentManifest),authoritySetHash:c.authorizationKind==='old-recovery'?'':recoveryAdminHash(s.authoritySet),issuerEvidenceHash:c.issuerEvidence?sourceHash(c.issuerEvidence):'',envelopesHash:recoveryEnvelopesHash(s.envelopes),newTrustRootHash:recoveryRootHash(h.account.id,'1',s.newTrustRoot),chainMode:'continuous',legacyStateHash:''});
  s.authorizationSignature=b64(ed25519.sign(transitionBytesV2(t),c.authorizationKind==='old-recovery'?old.signingSeed:seeds.A!));s.newRecoverySignature=b64(ed25519.sign(transitionBytesV2(t),keys.signingSeed));return {submission:s,dependencyBundle:c.dependencyBundle};
}
export function sealedTarget(t: ResolutionTarget, p: RecoveryTransitionCommandV2): ResolutionTarget {return {...t,stage:'sealed',declaredContentHash:transitionHashV2(p.submission)};}
export function protectedAuthority(a: RecoveryOperationAccount): unknown {return {recoveryGeneration:a.recoveryGeneration,recoverySigningPublicKey:a.recoverySigningPublicKey,recoveryReceivingPublicKey:a.recoveryReceivingPublicKey,environments:a.environments,devices:a.devices,grants:a.grants,trustRoot:a.trustRoot,grantHistory:a.grantHistory,events:a.events,recoveryDAGHistory:a.recoveryDAGHistory};}

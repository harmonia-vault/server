import { Fault } from './model.js';
import type { Store } from './store.js';
import type { RecoveryAuth } from './lifecycle-wire.js';
import { strictRecoveryBody } from './strict-recovery-body.js';
import { recoveryDAGCapability, decodeRecoveryTransitionCommandV2, decodeRecoveredDeviceCommandV2 } from './recovery-dag-wire.js';
import { RecoveryDAGService } from './recovery-dag-service.js';
import { requestProtocolMajor } from './protocol-info.js';
export async function recoveryDAGRoute(request:Request,store:Store):Promise<{handled:boolean;result?:unknown}>{
 const u=new URL(request.url),m=u.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/(recovery-authority-challenges-v2|recovery-authority-transitions-v2|recovered-device-challenges-v2|recovered-devices-v2|recovery-vault-v2)(?:\/([A-Za-z0-9._:-]+))?$/);
 if(!m)return {handled:false};requestProtocolMajor(request,true);
 if(u.searchParams.get('capability')!==recoveryDAGCapability||[...u.searchParams.keys()].join('|')!=='capability'||u.searchParams.getAll('capability').length!==1)throw new Fault(400,'recovery_capability_required');
 const token=request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1],accountGeneration=request.headers.get('x-harmonia-account-generation'),deviceId=request.headers.get('x-harmonia-device-id');if(!token||!accountGeneration)throw new Fault(401,'unauthorized');
 const auth:RecoveryAuth={token,accountGeneration,...(deviceId?{deviceId}:{})},s=new RecoveryDAGService(store),id=m[1]!,op=m[2]!,operation=m[3];let result:unknown;
 if(request.method==='POST'&&!operation){const body=await strictRecoveryBody(request);switch(op){
  case 'recovery-authority-challenges-v2':result=await s.challenge(id,auth,body as unknown as Parameters<RecoveryDAGService['challenge']>[2]);break;
  case 'recovery-authority-transitions-v2':result=await s.transition(id,auth,decodeRecoveryTransitionCommandV2(new TextEncoder().encode(JSON.stringify(body))));break;
  case 'recovered-device-challenges-v2':result=await s.recoveredChallenge(id,auth,body as unknown as Parameters<RecoveryDAGService['recoveredChallenge']>[2]);break;
  case 'recovered-devices-v2':result=await s.recoverDevice(id,auth,decodeRecoveredDeviceCommandV2(new TextEncoder().encode(JSON.stringify(body))));break;
  default:throw new Fault(405,'method_not_allowed');
 }}else if(request.method==='GET'&&operation&&op==='recovery-authority-transitions-v2')result=await s.transitionStatus(id,auth,operation);
 else if(request.method==='GET'&&operation&&op==='recovered-devices-v2')result=await s.recoveredStatus(id,auth,operation);
 else if(request.method==='GET'&&!operation&&op==='recovery-vault-v2')result=await s.vault(id,auth);
 else throw new Fault(405,'method_not_allowed');
 return {handled:true,result};
}

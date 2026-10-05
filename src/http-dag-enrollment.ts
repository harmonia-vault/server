import { Fault, type Auth } from './model.js';
import type { Store } from './store.js';
import { DAGEnrollmentService, type DAGApprovalRequest, type DAGPairingProposal } from './dag-enrollment.js';
import { strictRecoveryBody } from './strict-recovery-body.js';
import { exact } from './enrollment-wire.js';
import type { LoginAuth, Relay } from './enrollment.js';
import { requestProtocolMajor } from './protocol-info.js';
export async function dagEnrollmentRoute(request:Request,store:Store):Promise<{handled:boolean;result?:unknown}>{
  const u=new URL(request.url),m=u.pathname.match(/^\/v1\/accounts\/([A-Za-z0-9._:-]+)\/pairings-v5(?:\/([A-Za-z0-9._:-]+)(?:\/(relay|approve|complete))?)?$/);
  if(!m)return {handled:false};requestProtocolMajor(request);if(u.search)throw new Fault(400,'query_forbidden');
  const token=request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1],accountGeneration=request.headers.get('x-harmonia-account-generation'),deviceId=request.headers.get('x-harmonia-device-id');if(!token||!accountGeneration)throw new Fault(401,'unauthorized');
  const auth:LoginAuth&{deviceId?:string}={token,accountGeneration,...(deviceId?{deviceId}:{})},s=new DAGEnrollmentService(store),id=m[1]!,key=m[2],step=m[3];let result:unknown;
  if(request.method==='POST'&&!key)result=await s.begin(id,auth,await strictRecoveryBody(request) as unknown as DAGPairingProposal);
  else if(request.method==='GET'&&key&&!step)result=await s.status(id,auth,key);
  else if(request.method==='POST'&&key&&step==='relay')result=await s.relay(id,auth,key,await strictRecoveryBody(request) as unknown as Relay);
  else if(request.method==='POST'&&key&&step==='approve'){if(!deviceId)throw new Fault(403,'device_proof_required');result=await s.approve(id,auth as Auth,key,await strictRecoveryBody(request) as unknown as DAGApprovalRequest);}
  else if(request.method==='POST'&&key&&step==='complete'){const b=await strictRecoveryBody(request);exact(b,['signature']);if(typeof b.signature!=='string')throw new Fault(400,'string_required');result=await s.complete(id,auth,key,b.signature);}
  else throw new Fault(405,'method_not_allowed');return {handled:true,result};
}

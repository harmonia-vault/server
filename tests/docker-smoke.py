import subprocess,uuid,json,time
prefix='harmonia-smoke-'+uuid.uuid4().hex[:12]
name=prefix+'-server';volume=prefix+'-data';image='harmonia-server:local-test'
created_volume=False;created_container=False

def command(*args,check=True):
 p=subprocess.run(['docker',*args],capture_output=True,text=True)
 if check and p.returncode:raise RuntimeError('docker '+args[0]+' failed: '+p.stderr)
 return p

def fetch(path,body=None):
 program='const r=await fetch("http://127.0.0.1:8787'+path+'",'+json.dumps({'method':'GET'} if body is None else {'method':'POST','headers':{'content-type':'application/json'},'body':json.dumps(body)})+'); console.log(JSON.stringify({status:r.status,body:await r.json()}));'
 p=command('exec',name,'node','--input-type=module','-e',program)
 return json.loads(p.stdout)

def ready():
 for _ in range(30):
  try:
   response=fetch('/health')
   if response['status']==200:return
  except Exception:pass
  time.sleep(.2)
 raise RuntimeError('synthetic container did not become ready')

try:
 command('volume','create',volume);created_volume=True
 command('run','--detach','--name',name,'--volume',volume+':/data','--env','HARMONIA_ALLOW_REGISTRATION=true','--env','HARMONIA_REQUIRE_EMAIL_VERIFICATION=false',image);created_container=True
 ready()
 credential='ab'*32;email='container-synthetic@example.invalid'
 registered=fetch('/v1/register',{'email':email,'credential':credential})
 assert registered['status']==200,registered
 command('restart',name);ready()
 login=fetch('/v1/login',{'email':email,'credential':credential})
 assert login['status']==200,login
 assert login['body']['accountId']==registered['body']['accountId']
 check=command('exec',name,'node','--input-type=module','-e','import {statSync} from "node:fs";console.log(JSON.stringify({uid:process.getuid(),mode:statSync("/data").mode&0o777}));')
 identity=json.loads(check.stdout);assert identity['uid']!=0 and identity['mode']==0o700,identity
 unsafe=command('run','--rm','--env','HARMONIA_BIND=0.0.0.0','--env','HARMONIA_DATABASE=/tmp/synthetic.sqlite',image,check=False)
 assert unsafe.returncode!=0 and 'remote_plain_http_binding_disabled' in unsafe.stderr
 print(json.dumps({'result':'通过','checks':['容器本地HTTP启动','随机隔离持久卷注册合成空账号','重启后登录与账号ID保留','非root进程及/data权限0700','远程明文绑定拒绝'],'containerPortPublished':False,'cleanup':'仅删除本测试创建的容器和卷'},ensure_ascii=False))
finally:
 if created_container:command('rm','--force',name,check=False)
 if created_volume:command('volume','rm',volume,check=False)

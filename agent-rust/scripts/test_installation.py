#!/usr/bin/env python3
"""Actual native manager test, only on a new GitHub-hosted disposable VM."""
import argparse, datetime, http.server, json, os, pathlib, platform, re, shutil, subprocess, sys, tempfile, threading, time
if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':raise SystemExit('This test only changes fresh GitHub-hosted test VMs; refusing this computer')
parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True,type=pathlib.Path);parser.add_argument('--report',required=True,type=pathlib.Path);args=parser.parse_args();binary=args.binary.resolve();kind={'Darwin':'macos','Linux':'linux','Windows':'windows'}[platform.system()]
version=re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"', (pathlib.Path(__file__).resolve().parents[1]/'Cargo.toml').read_text(), re.M).group(1)
root=pathlib.Path(os.environ.get('ProgramData','C:/ProgramData'))/'OpenDirectory' if kind=='windows' else pathlib.Path('/Library/Application Support/OpenDirectory' if kind=='macos' else '/etc/opendirectory')
config=root/'CI config %spaces'/'agent.json';service=pathlib.Path('/Library/LaunchDaemons/com.opendirectory.agent.plist' if kind=='macos' else '/etc/systemd/system/od-agent.service');program=pathlib.Path('/Library/Application Support/OpenDirectory/bin' if kind=='macos' else '/usr/local/lib/opendirectory')
def run(*command,check=True):return subprocess.run([str(x) for x in command],check=check,capture_output=True,text=True)
def admin(*command,check=True):return run(*command,check=check) if kind=='windows' else run('sudo',*command,check=check)
def powershell(script,check=True):return run('powershell.exe','-NoProfile','-NonInteractive','-Command',script,check=check)
if kind=='windows' and (pathlib.Path(os.environ['ProgramFiles'])/'OpenDirectory').exists():raise SystemExit('Existing program directory found')
if root.exists() or kind!='windows' and (service.exists() or kind=='linux' and program.exists()):raise SystemExit('Existing OpenDirectory paths found; refusing to modify them')
if kind=='windows' and powershell("if(Get-ScheduledTask -TaskName OpenDirectoryAgent -ErrorAction SilentlyContinue){exit 1}",check=False).returncode:raise SystemExit('Existing task found')
if kind=='macos' and admin('launchctl','print','system/com.opendirectory.agent',check=False).returncode==0:raise SystemExit('Existing LaunchDaemon found')
if kind=='linux' and admin('systemctl','show','-p','LoadState','--value','od-agent.service').stdout.strip() not in ('','not-found'):raise SystemExit('Existing systemd service found')
assert run(binary,'--version').stdout.strip()=='od-agent-service '+version
secret='odad_'+'a'*43;device='11111111-1111-4111-8111-111111111111';received=[];errors=[]
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  try:
   body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))));assert self.headers.get('Authorization')=='Bearer '+secret and body['deviceId']==device
   if self.path=='/api/device-agent/sync/claim':value={'schemaVersion':1,'syncProtocol':1,'deviceId':device,'command':None}
   elif self.path=='/api/device-agent/heartbeat':
    assert body['report']['platform']==kind and body['report']['agentVersion']==version;assert body['inventory']['schemaVersion']==body['security']['schemaVersion']==1;assert int(body['inventory']['memory']['totalBytes'])>0
    received.append({'platform':kind,'version':body['report']['agentVersion'],'hardware':True,'security':True});value={'schemaVersion':1,'agentProtocol':1,'deviceId':device,'receivedAt':stamp(),'compliance':{'status':'not-configured','policyRevision':'0','evaluatedAt':stamp()}}
   else:raise ValueError('Unknown endpoint')
   data=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
  except Exception:errors.append('Invalid native agent request');self.send_error(400)
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
values={'server_url':'http://127.0.0.1:'+str(server.server_port),'enrollment_token':None,'device_id':device,'device_token':secret,'insecure_skip_verify':False,'ca_cert_path':None,'heartbeat_interval_secs':30,'command_poll_interval_secs':30,'compliance_interval_secs':300}
def heartbeat_after(count):
 for attempt in range(100):
  if len(received)>count:return
  time.sleep(.25)
 raise RuntimeError('No actual native-service heartbeat received')
try:
 with tempfile.TemporaryDirectory(prefix='od-native-install-') as temporary:
  source=pathlib.Path(temporary)/'agent.json';source.write_text(json.dumps(values))
  if kind=='windows':config.parent.mkdir(parents=True);shutil.copyfile(source,config)
  else:admin('mkdir','-p',config.parent);admin('install','-m','600',source,config)
  preview=json.loads(run(binary,'--config-path',config,'install','--dry-run').stdout);assert preview['config']==str(config)
  admin(binary,'--config-path',config,'install');heartbeat_after(0)
  count=len(received);admin(binary,'--config-path',config,'install');heartbeat_after(count)
  # A customized existing definition needs a separate explicit replacement.
  if kind=='windows':powershell("$t=Get-ScheduledTask -TaskName OpenDirectoryAgent;Set-ScheduledTask -TaskName OpenDirectoryAgent -Description 'CI customized definition'|Out-Null")
  else:admin('sh','-c','printf "\\n# CI customized definition\\n" >> "$1"','sh',service)
  denied=admin(binary,'--config-path',config,'install',check=False);assert denied.returncode!=0
  count=len(received);admin(binary,'--config-path',config,'install','--replace-existing');heartbeat_after(count)
  assert not errors
  if kind=='linux':admin('systemctl','is-active','--quiet','od-agent.service');admin('systemctl','is-enabled','--quiet','od-agent.service')
  if kind=='windows':powershell("if((Get-ScheduledTask -TaskName OpenDirectoryAgent).State -ne 'Running'){exit 1};$a=Get-Acl -LiteralPath '"+str(config).replace("'","''")+"';if(-not $a.AreAccessRulesProtected){exit 1}")
  if kind!='windows':assert int(admin('stat','-f' if kind=='macos' else '-c','%Lp' if kind=='macos' else '%a',config).stdout.strip(),8)==0o600
  args.report.write_text(json.dumps({'platform':kind,'architecture':platform.machine(),'version':version,'nativeManagerStarted':True,'actualHeartbeats':len(received),'customConfigPathWithSpacesAndPercent':True,'idempotentReinstall':True,'differentDefinitionRefused':True,'explicitReplacementStarted':True,'privateConfiguration':True},indent=2)+'\n')
finally:
 if kind=='windows':powershell("Stop-ScheduledTask -TaskName OpenDirectoryAgent -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName OpenDirectoryAgent -Confirm:$false -ErrorAction SilentlyContinue",check=False);shutil.rmtree(pathlib.Path(os.environ['ProgramFiles'])/'OpenDirectory',ignore_errors=True);shutil.rmtree(root,ignore_errors=True)
 else:
  if kind=='linux':admin('systemctl','disable','--now','od-agent.service',check=False)
  else:admin('launchctl','bootout','system/com.opendirectory.agent',check=False)
  admin('rm','-f',service);admin('rm','-rf',root)
  if kind=='linux':admin('rm','-rf',program);admin('systemctl','daemon-reload',check=False)
 server.shutdown();server.server_close()

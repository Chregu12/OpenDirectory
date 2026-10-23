'use strict';
const {spawnSync}=require('node:child_process');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const entry=JSON.stringify(require.resolve('../utils/config'));
function configuration(environment={},check='true'){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'auth-config-'));
 try{return spawnSync(process.execPath,['-e',`const c=require(${entry});process.stdout.write(String(${check}))`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_ENV:'production',JWT_SECRET:'disposable-runtime-configuration-key-with-32-characters',SESSION_SECRET:'',...environment}});}
 finally{fs.rmSync(directory,{recursive:true,force:true});}
}
test('production rejects missing, short and previously hardcoded JWT keys',()=>{
 for(const JWT_SECRET of ['', 'short','changeme-jwt-secret-at-least-32-chars!!']){const result=configuration({JWT_SECRET});expect(result.status).not.toBe(0);expect(result.stderr).toContain('Production JWT_SECRET');}
});
test('the default HTTP session key is stable and distinct from the configured JWT key',()=>{
 const result=configuration({},`c.session.secret!==c.jwt.secret&&c.session.secret.length===64&&(delete require.cache[require.resolve(${entry})],require(${entry}).session.secret===c.session.secret)`);
 expect(result.status).toBe(0);expect(result.stdout).toBe('true');
});
test('an explicit production HTTP session key is honored and weak values are rejected',()=>{
 const result=configuration({SESSION_SECRET:'disposable-independent-session-key-with-32-characters'},'c.session.secret===process.env.SESSION_SECRET');expect(result.status).toBe(0);expect(result.stdout).toBe('true');
 for(const SESSION_SECRET of ['short','changeme-session-secret-32-chars!!'])expect(configuration({SESSION_SECRET}).status).not.toBe(0);
});

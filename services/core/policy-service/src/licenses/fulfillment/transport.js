'use strict';

class ProviderError extends Error {
  constructor(code,{ uncertain=false,retryAfter=null }={}) { super(code); this.code=code; this.uncertain=uncertain; this.retryAfter=retryAfter; }
}
async function jsonRequest(fetchImpl,url,options,stage) {
  const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),5000);
  const abort=()=>controller.abort();options.signal?.addEventListener('abort',abort,{once:true});if(options.signal?.aborted)controller.abort();
  try {
    const response=await fetchImpl(url,{ ...options,redirect:'manual',cache:'no-store',signal:controller.signal });
    if (response.status!==200) {
      const retry=response.headers.get('retry-after'); const numeric=Number(retry);
      const seconds=Number.isInteger(numeric)&&numeric>0?numeric:Math.ceil((Date.parse(retry)-Date.now())/1000);
      await response.body?.cancel();
      throw new ProviderError(stage+'_http_'+response.status,{ uncertain:stage==='graph_write' && ![400,401,403,404,405,410,412,415,422,429].includes(response.status),
        retryAfter:response.status===429 ? Number.isInteger(seconds) && seconds>0 ? Math.min(3600,seconds) : 60 : null });
    }
    if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('invalid_type');
    const chunks=[]; let size=0;
    for await (const chunk of response.body) { size+=chunk.length; if (size>262144) throw new Error('oversized'); chunks.push(Buffer.from(chunk)); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw new ProviderError(stage+'_unavailable',{ uncertain:stage==='graph_write' });
  } finally { clearTimeout(timer);options.signal?.removeEventListener('abort',abort); }
}
function bearer(value) { return typeof value==='string' && value.length<=16384 && /^[A-Za-z0-9._~+/-]+=*$/.test(value); }
class ClientCredentialToken {
  constructor({ url,clientId,clientSecret,scope,fetchImpl=(...args)=>fetch(...args),stage,requireScope=false }) { Object.assign(this,{ url,clientId,clientSecret,scope,fetchImpl,stage,requireScope }); this.cached=null; }
  clear() { this.cached=null; }
  async get(signal) {
    if(signal?.aborted)throw new ProviderError(this.stage+'_unavailable');
    if (this.cached && this.cached.until>Date.now()) return this.cached.token;
    const data=await jsonRequest(this.fetchImpl,this.url,{ method:'POST',signal,headers:{ 'Content-Type':'application/x-www-form-urlencoded' },
      body:new URLSearchParams({ grant_type:'client_credentials',client_id:this.clientId,client_secret:this.clientSecret,scope:this.scope }).toString() },this.stage);
    if (data.token_type?.toLowerCase()!=='bearer' || !bearer(data.access_token) || !Number.isInteger(data.expires_in) || data.expires_in<60 || data.expires_in>86400 || this.requireScope&&data.scope!==this.scope) throw new ProviderError(this.stage+'_invalid_response');
    this.cached={ token:data.access_token,until:Date.now()+(data.expires_in-30)*1000 }; return data.access_token;
  }
}
module.exports = { ProviderError,jsonRequest,ClientCredentialToken };

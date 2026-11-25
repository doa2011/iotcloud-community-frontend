import {verifyCapabilities} from './deviceWire.js';

import {t} from './i18n.js';
import {normalizeMAC} from './deviceProtocol.js';
import {createDeviceHttpSession} from './deviceHttpSession.js';

function normalizeDeviceAddress(raw){
 if(!raw)return '';
 const value=String(raw).trim();
 if(!value||/[\\s\\u0000-\\u001f]/.test(value))throw Error(t('p.8c1e3096f2fd'));
 let url;
 try{
  if(/^[a-z][a-z0-9+.-]*:\/\//i.test(value))url=new URL(value);
  else{
   let host=value.replace(/\/$/,'');
   // Accept an unbracketed bare IPv6 literal. IPv6 with an explicit port
   // must use the standard [address]:port form to remain unambiguous.
   if(host.includes(':')&&!host.startsWith('[')&&/^[0-9a-f:]+$/i.test(host))host='['+host+']';
   const unwrapped=host.startsWith('[')?host.slice(1,host.indexOf(']')):host.replace(/:\\d+$/,'');
   const privateV4=/^(?:10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.)/i.test(unwrapped);
   const localV6=/^(?:::1|fc|fd|fe80)/i.test(unwrapped);
   const localName=/\\.local$/i.test(unwrapped);
   // Preserve convenient HTTP for directly attached/private endpoints. All
   // other bare addresses default to HTTPS; explicit http:// remains allowed.
   url=new URL((privateV4||localV6||localName?'http://':'https://')+host);
  }
 }catch{throw Error(t('p.8c1e3096f2fd'));}
 if(!['http:','https:'].includes(url.protocol)||!url.hostname||url.username||url.password||
    url.pathname!=='/'||url.search||url.hash)throw Error(t('p.8c1e3096f2fd'));
 const port=Number(url.port||(url.protocol==='https:'?443:80));
 if(!Number.isInteger(port)||port<1||port>65535)throw Error(t('p.8c1e3096f2fd'));
 return url.origin;
}
// The device address is user-supplied. Do not impose RFC1918, CGNAT,
// subnet, private/public, hostname, IPv4 or IPv6 allowlists here.
export function localAddress(raw){return normalizeDeviceAddress(raw);}
export function connectionAddress(raw){return normalizeDeviceAddress(raw);}
const storageKey=(scope,key)=>'phicomm.device-connection.'+encodeURIComponent(scope)+':'+encodeURIComponent(key);
export function loadPreference(scope,key,storage=localStorage){
 try{const p=JSON.parse(storage.getItem(storageKey(scope,key))||'{}');return {mode:p.mode==='mqtt'?'mqtt':'auto',address:connectionAddress(p.address||''),lastAddress:connectionAddress(p.lastAddress||'')};}catch{return {mode:'auto',address:'',lastAddress:''};}
}
export function savePreference(scope,key,value,storage=localStorage){
 const p={mode:value.mode==='mqtt'?'mqtt':'auto',address:connectionAddress(value.address||''),lastAddress:connectionAddress(value.lastAddress||'')};storage.setItem(storageKey(scope,key),JSON.stringify(p));return p;
}
export function createDeviceTransport({fetcher=globalThis.fetch,records={},onStatus=()=>{}}={}){
 let active=0,disposed=false;const entries=new Map(),queue=[];
 const drain=()=>{while(active<2&&queue.length){active++;queue.shift()();}};
 const slot=()=>new Promise(resolve=>{queue.push(resolve);drain();});
 const current=(key,e)=>!disposed&&entries.get(key)===e;
 const pagehide=()=>{for(const e of entries.values())e.session.auth.release();};
 globalThis.addEventListener?.('pagehide',pagehide);
 async function request(e,path,{signal,...options}={},timeout=20000,raw=false){
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),timeout),cancel=()=>abort.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)abort.abort();e.controllers.add(abort);
  try{
   const r=await e.session.fetch(path,{...options,signal:abort.signal});
   if(!r.ok){let reply;try{reply=await e.session.wire.decodeResponse(r);}catch{}const error=Error(r.status===401?t('p.aca4ebdbc19f'):reply?.message||reply?.code||t('p.23a84a23f636')+r.status);error.status=r.status;error.code=reply?.code||(r.status===503?'busy':'http_error');if(reply?.code)error.reply=reply;throw error;}
   return raw?{status:r.status,bytes:await r.arrayBuffer()}:await e.session.wire.decodeResponse(r);
  }finally{clearTimeout(timer);e.controllers.delete(abort);signal?.removeEventListener('abort',cancel);}
 }
 function invalidate(e){for(const c of e.controllers)c.abort();e.controllers.clear();e.session.release();}
 function configure(key,device,prefs,password='',force=false){
  const address=prefs.address||prefs.lastAddress||'',old=entries.get(key);
  if(!force&&old&&old.address===address&&old.mode===prefs.mode&&old.password===password&&['mac','model','firmware_version','firmware_variant','variant','wire_format','wire_version'].every(field=>old.device[field]===device[field]))return;
  if(old)invalidate(old);
  const entry={device:{...device},address,mode:prefs.mode,password,controllers:new Set(),promise:null};
  entry.session=createDeviceHttpSession({fetcher,origin:address,expectedIdentity:device,password,onRequired:()=>{if(current(key,entry))Object.assign(records[key],{ready:false,reason:t('p.aca4ebdbc19f')});}});
  entries.set(key,entry);
  records[key]={ready:false,checking:false,address,reason:prefs.mode==='mqtt'?t('p.148579fd130e'):address?t('p.3a811788f296'):t('p.fed0dc5b0c2f')};
 }
 async function probe(key,force=false){
  const e=entries.get(key);if(!e||disposed||e.mode==='mqtt'||!e.address)return false;if(e.promise)return e.promise;if(!force&&e.lastProbe&&Date.now()-e.lastProbe<30000)return !!records[key]?.ready;e.lastProbe=Date.now();
  e.promise=(async()=>{
   await slot();
   try{
    if(!current(key,e))return false;
    records[key].checking=true;
    // One deadline covers identity and the initial status read.
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
    e.controllers.add(controller);
    try{
     await e.session.ready(controller.signal);const identity=e.session.wire.identity,i={...identity,firmware_variant:identity.variant,api_version:1};
     const status=await request(e,'/api/v1/command',{method:'POST',value:{action:'status.get',params:{}},signal:controller.signal},5000);
     if(status.code!=='ok'||!status.data||normalizeMAC(status.data.device_id)!==normalizeMAC(e.device.mac))throw Error(t('p.6966db4cb1c5'));
     if(current(key,e)){records[key]={ready:true,checking:false,address:e.address,reason:t('p.a2d6d3fd2463'),info:i};onStatus(key,status.data);}
     return current(key,e);
    }finally{clearTimeout(timer);e.controllers.delete(controller);}
   }catch(err){if(current(key,e))records[key]={ready:false,checking:false,address:e.address,reason:err.name==='AbortError'?t('p.dc4ace469fac'):err.message||t('p.f09b3b04b23a')};return false;}
   finally{active--;drain();e.promise=null;}
  })();return e.promise;
 }
 async function dispatch(key,requestData,mqttRequest){
  const e=entries.get(key);if(!e)return mqttRequest();if(e?.mode!=='mqtt'&&e?.address&&!records[key]?.ready)await probe(key);
  if(!e||!current(key,e))return {code:'offline',message:t('p.ec7c88a78b95')};
  if(!records[key]?.ready||e.mode==='mqtt')return mqttRequest();
  try{
   const result=await request(e,'/api/v1/command',{method:'POST',value:requestData});
   if(!current(key,e))return {code:'offline',message:t('p.9b8764282633')};
   if(requestData.action==='capabilities.get'&&result.code==='ok'&&e.session.wire.format==='msgpack')verifyCapabilities(result.data,e.session.wire.identity);
   if(requestData.action==='status.get'&&result.code==='ok')onStatus(key,result.data);
   return result;
  }catch(err){
   if(err.reply&&current(key,e))return err.reply;
   if(err.code==='busy'&&current(key,e))return {code:'busy',message:err.message};
   if(current(key,e))Object.assign(records[key],{ready:false,reason:err.message||t('p.b1d97389d90c')});
   if(requestData.action.endsWith('.get')&&current(key,e))return mqttRequest();
   return {code:'uncertain',message:t('p.f8277e40c9dd')};
  }
 }
 function upload(key,file,rescue,onProgress=()=>{},XMLHttpRequestClass=globalThis.XMLHttpRequest,target){
  const e=entries.get(key);
  const reject=text=>({promise:Promise.resolve({status:0,text}),abort(){}});
  if(!e||e.mode==='mqtt'||!records[key]?.ready)return reject(t('p.6bc40dfa1f9f'));
  if(target!==undefined){
   if(target?.variant!=='hub'||target?.confirm!=='full-to-hub'||e.device.model!=='daikin'||rescue)return reject(t('p.bcce0d150ca6'));
   try{if(localAddress(e.address)!==e.address)return reject(t('p.6bc40dfa1f9f'));}catch{return reject(t('p.6bc40dfa1f9f'));}
  }
  const xhr=new XMLHttpRequestClass(),controller={abort:()=>xhr.abort()};e.controllers.add(controller);
  const promise=new Promise(resolve=>{
   xhr.open('POST',e.address+(target?'/api/v1/ota/convert':rescue?'/api/v1/ota/upload-unsigned':'/api/v1/ota/upload'));xhr.timeout=310000;xhr.withCredentials=false;xhr.responseType='arraybuffer';xhr.setRequestHeader('Accept',e.session.wire.headers().Accept);xhr.setRequestHeader('Content-Type','application/octet-stream');const authorization=e.session.auth.headers().Authorization;if(authorization)xhr.setRequestHeader('Authorization',authorization);
   if(target){xhr.setRequestHeader('X-IoTCloud-Target-Variant','hub');xhr.setRequestHeader('X-IoTCloud-Confirm','full-to-hub');}
   xhr.upload.onprogress=event=>{if(current(key,e)&&event.lengthComputable)onProgress(event.loaded,event.total);};
   xhr.onload=async()=>{
    e.session.auth.observe(xhr.status,authorization);let text='';
    try{if(xhr.response!==undefined&&xhr.response!==null){const reply=await e.session.wire.decodeResponse(new Response(xhr.response,{status:xhr.status,headers:{'Content-Type':xhr.getResponseHeader?.('Content-Type')||e.session.wire.headers().Accept}}));text=reply.message||reply.code||'';}else text=xhr.responseText||'';}catch{text='HTTP '+xhr.status;}
    resolve({status:xhr.status,text});
   };
   xhr.onerror=xhr.ontimeout=xhr.onabort=()=>resolve({status:0,text:t('p.404da89a85cb')});
   xhr.send(file);
  }).finally(()=>e.controllers.delete(controller));return {promise,abort:controller.abort};
 }
 async function resource(key,path,options={}){
  const e=entries.get(key),method=options.method||'GET';
  if(!((path==='/api/v1/config/backup'&&method==='GET')||(path==='/api/v1/config/restore'&&method==='POST')))throw Error(t('backup.invalid_path'));
  if(!e||e.mode==='mqtt'||!e.address||!current(key,e))throw Error(t('backup.device_changed'));
  // File transfer is authenticated against the configured device HTTP endpoint.
  // Do not require LAN discovery: routed/VPN access can work even when the LAN
  // probe is unavailable. The actual request below remains the connectivity test.
  const result=await request(e,path,{method,body:options.body,signal:options.signal,headers:{'Content-Type':'application/octet-stream'}},20000,true);
  if(!current(key,e))throw Error(t('backup.device_changed'));
  return result;
 }
 function retain(keys){for(const [key,e] of entries)if(!keys.includes(key)){invalidate(e);entries.delete(key);delete records[key];}}
 function stop(){disposed=true;globalThis.removeEventListener?.('pagehide',pagehide);for(const e of entries.values())invalidate(e);entries.clear();drain();}
 return {configure,probe,dispatch,upload,resource,retain,stop};
}

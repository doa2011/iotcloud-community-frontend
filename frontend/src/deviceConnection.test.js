import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDeviceTransport,localAddress,connectionAddress,savePreference,loadPreference} from './deviceConnection.js';
const device={mac:'aabbccddeeff',model:'a1',version:'v2'};
const response=data=>({ok:true,status:200,json:async()=>data});
const info={code:'ok',data:{device_id:device.mac,model:'a1',api_version:1}};
const status={code:'ok',data:{device_id:device.mac,fan_on:true}};
const legacy=fetcher=>async(url,options)=>url.endsWith('/auth/login')?{ok:false,status:404}:fetcher(url,options);
function fixture(fetcher){fetcher=legacy(fetcher);const records={},seen=[];const t=createDeviceTransport({fetcher,records,onStatus:(...s)=>seen.push(s)});t.configure('d',device,{mode:'auto',address:'http://192.168.1.10'},'web-pass');return {t,records,seen};}
test('private addresses and preferences are validated and isolated without credentials',()=>{
 for(const value of ['https://192.168.1.1','192.168.1.1/path','127.0.0.1','8.8.8.8','192.168.1.1:0','http://user:pass@192.168.1.1'])assert.throws(()=>localAddress(value));
 assert.equal(localAddress('192.168.1.1:8080'),'http://192.168.1.1:8080');
 const values=new Map(),storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v)};
 savePreference('node/account','d',{mode:'mqtt',address:'192.168.1.10',password:'secret'},storage);
 assert.equal(loadPreference('node/account','d',storage).mode,'mqtt');assert.equal(loadPreference('node/other','d',storage).address,'');assert.ok(![...values.values()].join('').includes('secret'));
});
test('auth, identity and initial status are required; LAN works without MQTT',async()=>{
 const calls=[];const {t,records}=fixture(async(url,opts)=>{calls.push([url,opts]);return response(url.endsWith('/info')?info:status);});
 assert.equal(await t.probe('d'),true);assert.equal(records.d.ready,true);assert.equal(calls[0][1].headers.Authorization,undefined);assert.match(calls[1][1].headers.Authorization,/^Basic /);assert.equal(calls[0][1].credentials,'omit');
 let mqtt=0;const result=await t.dispatch('d',{action:'status.get'},()=>{mqtt++;});assert.equal(result.code,'ok');assert.equal(mqtt,0);t.stop();
 for(const fetcher of [async()=>({status:401,ok:false}),async()=>response({...info,data:{...info.data,device_id:'000000000000'}}),async url=>response(url.endsWith('/info')?info:{code:'error'})]){const f=fixture(fetcher);assert.equal(await f.t.probe('d'),false);assert.equal(f.records.d.ready,false);f.t.stop();}
});
test('force MQTT makes no LAN requests; writes are never replayed after loss',async()=>{
 let fail=false;const calls=[];const {t,records}=fixture(async url=>{calls.push(url);if(fail)throw Error('lost');return response(url.endsWith('/info')?info:status);});
 await t.probe('d');fail=true;let mqtt=0;
 assert.equal((await t.dispatch('d',{action:'fan.set',request_id:'same-id'},()=>{mqtt++;})).code,'uncertain');assert.equal(mqtt,0);
 assert.equal((await t.dispatch('d',{action:'status.get'},()=>{mqtt++;return {code:'ok'};})).code,'ok');assert.equal(mqtt,1);t.stop();
});
test('read failure falls back; force MQTT disables probes and upload',async()=>{
 let fail=false,mqtt=0;const {t}=fixture(async url=>{if(fail)throw Error('blocked');return response(url.endsWith('/info')?info:status);});await t.probe('d');fail=true;
 assert.equal((await t.dispatch('d',{action:'status.get'},()=>{mqtt++;return {code:'ok'};})).code,'ok');assert.equal(mqtt,1);
 t.configure('d',device,{mode:'mqtt',address:'http://192.168.1.10'});assert.equal(await t.probe('d'),false);assert.equal((await t.upload('d',new Blob(),false).promise).status,0);t.stop();
});
test('only two probes run concurrently and stale identity replies cannot enable old addresses',async()=>{
 let active=0,max=0;const gates=[];const records={};const t=createDeviceTransport({records,fetcher:legacy(async url=>{active++;max=Math.max(max,active);await new Promise(r=>gates.push(r));active--;return response(url.endsWith('/info')?info:status);})});
 for(let i=0;i<3;i++)t.configure('d'+i,device,{mode:'auto',address:'http://192.168.1.'+(10+i)});
 const jobs=[0,1,2].map(i=>t.probe('d'+i));await new Promise(setImmediate);assert.equal(gates.length,2);
 t.configure('d0',device,{mode:'mqtt',address:''});
 while(gates.length||active){gates.splice(0).forEach(r=>r());await new Promise(setImmediate);}
 await Promise.all(jobs);assert.equal(max,2);assert.equal(records.d0.ready,false);t.stop();
});
test('signed hub conversion keeps explicit guards and authenticates only when a web password exists',async()=>{
 const requests=[];
 class XHR{
  constructor(){this.upload={};this.headers={};}
  open(method,url){this.method=method;this.url=url;}
  setRequestHeader(name,value){this.headers[name]=value;}
  send(file){this.file=file;requests.push(this);this.status=202;this.responseText='accepted';this.onload();}
  abort(){this.onabort?.();}
 }
 const daikin={...device,model:'daikin'},records={},t=createDeviceTransport({records,fetcher:legacy(async url=>response(url.endsWith('/info')?{...info,data:{...info.data,model:'daikin',firmware_variant:'full'}}:status))});
 const configure=password=>t.configure('d',daikin,{mode:'auto',address:'http://192.168.1.115'},password);
 configure('web-secret');await t.probe('d');
 const file=new Blob(['intact signed envelope']),target={variant:'hub',confirm:'full-to-hub'};
 for(const rescue of [false,true]){
  assert.equal((await t.upload('d',file,rescue,()=>{},XHR).promise).status,202);
  assert.equal(requests.at(-1).url,'http://192.168.1.115/api/v1/ota/'+(rescue?'upload-unsigned':'upload'));
  assert.equal(Object.keys(requests.at(-1).headers).some(k=>k.startsWith('X-IoTCloud-')),false);
 }
 assert.equal((await t.upload('d',file,false,()=>{},XHR,target).promise).status,202);
 const conversion=requests.at(-1);assert.equal(conversion.url,'http://192.168.1.115/api/v1/ota/convert');assert.equal(conversion.file,file);assert.equal(conversion.withCredentials,false);
 assert.deepEqual(conversion.headers,{Accept:'application/json','Content-Type':'application/octet-stream',Authorization:'Basic '+Buffer.from('admin:web-secret').toString('base64'),'X-IoTCloud-Target-Variant':'hub','X-IoTCloud-Confirm':'full-to-hub'});
 const count=requests.length;
 for(const invalid of [null,{}, {variant:'full',confirm:'hub-to-full'}, {variant:'hub',confirm:'wrong'}])assert.equal((await t.upload('d',file,false,()=>{},XHR,invalid).promise).status,0);
 assert.equal((await t.upload('d',file,true,()=>{},XHR,target).promise).status,0);
 assert.equal(requests.length,count,'failed conversion guards cannot send an upload');
 configure('');await t.probe('d');assert.equal((await t.upload('d',file,false,()=>{},XHR,target).promise).status,202);
 assert.equal(requests.at(-1).file,file);assert.equal(requests.at(-1).url,'http://192.168.1.115/api/v1/ota/convert');
 assert.deepEqual(requests.at(-1).headers,{Accept:'application/json','Content-Type':'application/octet-stream','X-IoTCloud-Target-Variant':'hub','X-IoTCloud-Confirm':'full-to-hub'});
 t.configure('d',daikin,{mode:'mqtt',address:'http://192.168.1.115'},'web-secret');assert.equal((await t.upload('d',file,false,()=>{},XHR,target).promise).status,0);
 assert.equal(requests.length,count+1,'MQTT-only conversion cannot send an upload');t.stop();
 const a1=fixture(async url=>response(url.endsWith('/info')?info:status));await a1.t.probe('d');assert.equal((await a1.t.upload('d',file,false,()=>{},XHR,target).promise).status,0);a1.t.stop();assert.equal(requests.length,count+1);
});

test('remote endpoint preferences preserve strict local conversion guard',()=>{
 for(const value of ['https://g3.example.com','https://[2001:db8::1]:8443','http://100.64.1.2','100.127.1.2']){
  const address=connectionAddress(value);assert.throws(()=>localAddress(address));
  const values=new Map(),storage={getItem:k=>values.get(k),setItem:(k,v)=>values.set(k,v)};
  savePreference('remote','d',{mode:'auto',address},storage);assert.equal(loadPreference('remote','d',storage).address,address);
 }
 for(const value of ['http://8.8.8.8','http://100.128.1.2','https://user:pass@g3.example.com','https://g3.example.com/path','https://g3.example.com?x=1','https://g3.example.com:0'])assert.throws(()=>connectionAddress(value));
});

test('remote backup and restore use authenticated HTTP without status probe',async()=>{
 const calls=[],payload=new Uint8Array([1,2,3]);
 const t=createDeviceTransport({fetcher:legacy(async(url,opts)=>{
  calls.push([url,opts]);
  if(url.endsWith('/info'))return response(info);
  if(url.endsWith('/api/v1/config/backup')||url.endsWith('/api/v1/config/restore'))return {ok:true,status:200,arrayBuffer:async()=>payload.buffer};
  throw Error('unexpected status probe');
 })});
 try{
  t.configure('d',device,{mode:'auto',address:'https://g3.example.com'},'web-pass');
  const backup=await t.resource('d','/api/v1/config/backup');
  assert.deepEqual(new Uint8Array(backup.bytes),payload);
  await t.resource('d','/api/v1/config/restore',{method:'POST',body:payload});
  const transfers=calls.filter(([url])=>url.includes('/config/'));
  assert.equal(transfers.length,2);
  assert.equal(transfers[0][1].method,'GET');
  assert.equal(transfers[1][1].method,'POST');
  assert.equal(transfers[1][1].body,payload);
  for(const [url,opts] of transfers){assert.ok(url.startsWith('https://g3.example.com/'));assert.match(opts.headers.Authorization,/^Basic /);}
  await assert.rejects(t.resource('d','/api/v1/config/restore'));
  t.configure('d',device,{mode:'mqtt',address:'https://g3.example.com'},'web-pass');
  await assert.rejects(t.resource('d','/api/v1/config/backup'));
  assert.equal(calls.filter(([url])=>url.includes('/config/')).length,2);
 }finally{t.stop();}
});

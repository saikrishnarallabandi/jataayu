'use strict';
const assert=require('node:assert/strict');
const {pathToFileURL}=require('node:url');
const {activate}=require('./index');
const version=require('./openclaw.plugin.json').version;
(async()=>{
  let hostRunner;
  if(process.env.OPENCLAW_MIDDLEWARE_RUNNER){
    const host=await import(pathToFileURL(process.env.OPENCLAW_MIDDLEWARE_RUNNER));
    hostRunner=host.createAgentToolResultMiddlewareRunner||host.t;
    assert.equal(typeof hostRunner,'function');
  }
  for(const mode of ['enforce','shadow','off'])for(const verdict of ['SAFE','HIGH','error']){
    let handler,release,requests=0,settled=false;
    const rows=[],gate=new Promise(resolve=>release=resolve);
    const controller=activate({pluginConfig:{toolReturnMode:mode,receiptTraffic:'synthetic'},on:()=>{},registerTool:()=>{},
      registerAgentToolResultMiddleware:(fn,options)=>{handler=fn;assert.deepEqual(options,{runtimes:['openclaw']});}},
      {receiptSink:row=>rows.push(row),request:async req=>{
        const response={schema_version:1,core_version:version,core_fingerprint:'fixture'};
        if(req.operation==='health')return response;
        requests++;assert(req.content.includes('structured injection'));
        await gate;if(verdict==='error')throw Error('fixture');
        return {...response,result:{status:verdict,blocked:verdict==='HIGH'}};
      }});
    await controller.health;
    const ctx={runtime:'openclaw',sessionKey:'fixture'};
    const original={content:[{type:'text',text:'plain result'}],details:{payload:'structured injection'}};
    const event={toolCallId:'fixture-call',toolName:'read',args:{},result:original};
    const apply=hostRunner?hostRunner(ctx,[handler]).applyToolResultMiddleware:async event=>(await handler(event,ctx))?.result??event.result;
    const pending=apply(event).then(result=>{settled=true;return result;});
    await new Promise(resolve=>setImmediate(resolve));
    if(mode!=='off')assert.equal(settled,false,'screening must finish before result delivery');
    release();const result=await pending;
    const replaced=mode==='enforce'&&verdict!=='SAFE';
    if(replaced){assert(result.content[0].text.includes('withheld'));assert(!JSON.stringify(result).includes('structured injection'));}
    else assert.deepEqual(result,original);
    assert.equal(requests,mode==='off'?0:1);
    assert.equal(rows[0].adapter_disposition,replaced?'replace':'pass');
    assert.equal(rows[0].screening_path,'awaited_middleware');
    assert(!JSON.stringify(rows).includes('structured injection'));
  }
  console.log(`Awaited middleware tests passed (${hostRunner?'installed host runner':'adapter contract'})`);
})().catch(error=>{console.error(error);process.exitCode=1;});

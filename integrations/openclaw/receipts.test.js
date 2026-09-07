'use strict';
const assert=require('node:assert/strict');
const {activate}=require('./index');
const {createReceipts}=require('./receipts');
const version=require('./openclaw.plugin.json').version;
const health={schema_version:1,core_version:version,core_fingerprint:'fixture'};
function setup(request,config={}){
  const rows=[],hooks={};
  const controller=activate({pluginConfig:{effectBoundaryMode:'shadow',toolReturnMode:'shadow',receiptTraffic:'synthetic',...config},
    on:(name,fn)=>hooks[name]=fn,registerTool:()=>{}},
    {receiptSink:row=>rows.push(row),request:async req=>req.operation==='health'?health:{...health,result:await request(req)}});
  return {rows,hooks,controller};
}
(async()=>{
  const secret='synthetic-password-do-not-log';
  const t=setup(async req=>{if(req.params?.delay)await new Promise(r=>setTimeout(r,15));
    return {decision:'needs_approval',effect_class:'read',reason:secret,violations:[secret],commit_token:secret,classification_source:'unknown'};});
  await t.controller.health;
  await Promise.all(['a','b'].map(id=>t.hooks.before_tool_call({toolName:'unknown',toolCallId:id,params:{password:secret,delay:id==='a'}},{sessionKey:id})));
  assert.equal(t.rows.length,2);
  assert.equal(new Set(t.rows.map(r=>r.session_id)).size,2);
  assert(t.rows.every(r=>r.mode==='shadow'&&r.would_intervene&&r.adapter_disposition==='pass'&&r.host_acknowledgement==='unobserved'));
  assert(!JSON.stringify(t.rows).includes(secret));
  assert(!JSON.stringify(t.rows).includes('commit_token'));
  let release;const gate=new Promise(r=>release=r);
  const p=setup(async()=>{await gate;return {status:'SAFE',blocked:false};});
  const pending=p.hooks.after_tool_call({toolName:'read',toolCallId:'late',result:secret},{sessionKey:'s'});
  const persisted=p.hooks.tool_result_persist({toolName:'read',toolCallId:'late',message:{content:secret}},{sessionKey:'s'});
  assert.equal(persisted,undefined);
  assert.equal(p.rows[0].screening_state,'pending');
  release();await pending;
  assert.equal(p.rows.find(r=>r.hook==='after_tool_call').completed_after_persist,true);
  const isolated=setup(async req=>({status:req.content==='hostile'?'HIGH':'SAFE',blocked:req.content==='hostile'}),{toolReturnMode:'enforce'});
  await isolated.hooks.after_tool_call({toolName:'read',toolCallId:'same',result:'clean'},{sessionKey:'one'});
  await isolated.hooks.after_tool_call({toolName:'read',toolCallId:'same',result:'hostile'},{sessionKey:'two'});
  assert.equal(isolated.hooks.tool_result_persist({toolCallId:'same',message:{content:'clean'}},{sessionKey:'one'}),undefined);
  assert(isolated.hooks.tool_result_persist({toolCallId:'same',message:{content:'hostile'}},{sessionKey:'two'}).message);
  const contextOnly=setup(async req=>({status:req.content==='hostile'?'HIGH':'SAFE',blocked:req.content==='hostile'}),{toolReturnMode:'enforce'});
  for(const sessionKey of ['safe','blocked']){
    const ctx={sessionKey,toolCallId:'ctx-only'};
    await contextOnly.hooks.after_tool_call({toolName:'read',result:sessionKey==='safe'?'clean':'hostile'},ctx);
  }
  assert.equal(contextOnly.hooks.tool_result_persist({message:{content:'clean'}},{sessionKey:'safe',toolCallId:'ctx-only'}),undefined);
  assert(contextOnly.hooks.tool_result_persist({message:{content:'hostile'}},{sessionKey:'blocked',toolCallId:'ctx-only'}).message);
  assert(contextOnly.rows.filter(row=>row.hook==='tool_result_persist').every(row=>row.screening_state==='complete'));
  // Event and context locations can differ between the two host callbacks.
  await contextOnly.hooks.after_tool_call({toolName:'read',toolCallId:'mixed',result:'clean'},{sessionKey:'mixed'});
  assert.equal(contextOnly.hooks.tool_result_persist({message:{content:'clean'}},{sessionKey:'mixed',toolCallId:'mixed'}),undefined);
  const broken=setup(async()=>{throw Error(secret);});
  await broken.hooks.before_tool_call({toolName:'exec'},{});
  assert.equal(broken.rows[0].error_category,'runtime_failure');
  assert.equal(broken.rows[0].correlation_status,'missing_session');
  assert(!JSON.stringify(broken.rows).includes(secret));
  let errors=0;const r=createReceipts({config:{},version:'test',fingerprint:'test',sink:()=>{throw Error(secret);},logger:{error:()=>errors++}});
  assert.equal(r.wrap('tool_result_persist',()=>({message:{content:'safe'}}),'enforce')({},{}).message.content,'safe');
  assert.equal(errors,1);
  const disabled=createReceipts({config:{},version:'test',fingerprint:'test',logger:{error:()=>errors++}});
  const before=errors;
  for(let i=0;i<100;i++)assert.equal(disabled.wrap('before_tool_call',()=>undefined,'shadow')({},{}),undefined);
  assert.equal(errors,before,'an unset receipt path must not emit write errors');
  console.log('Decision receipt privacy, concurrency, and ordering tests passed');
})().catch(e=>{console.error(e);process.exitCode=1;});

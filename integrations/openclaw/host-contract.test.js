'use strict';
// Run against the installed host module, in a separate process with an empty registry.
// This never loads the live plugin registry or sends a real message/tool action.
const assert=require('node:assert/strict');
const {pathToFileURL}=require('node:url');
const {register}=require('./index');
const version=require('./openclaw.plugin.json').version;
(async()=>{
  if(!process.env.OPENCLAW_HOOK_RUNNER)throw Error('Set OPENCLAW_HOOK_RUNNER to the installed host hook-runner module');
  const host=await import(pathToFileURL(process.env.OPENCLAW_HOOK_RUNNER));
  const createRunner=host.createHookRunner||host.s;
  assert.equal(typeof createRunner,'function','host createHookRunner export changed');
  const registry={typedHooks:[],hooks:[]},rows=[];
  let release;const gate=new Promise(resolve=>release=resolve);
  const controller=register({pluginConfig:{effectBoundaryMode:'enforce',toolReturnMode:'shadow',receiptTraffic:'synthetic'},
    on:(hookName,handler,options={})=>registry.typedHooks.push({pluginId:'jataayu-fixture',hookName,handler,...options}),registerTool:()=>{}},
    {receiptSink:row=>rows.push(row),request:async req=>{
      const base={schema_version:1,core_version:version,core_fingerprint:'host-fixture'};
      if(req.operation==='health')return base;
      if(req.operation==='authorize')return {...base,result:{decision:'deny',reason:'fixture denial'}};
      await gate;return {...base,result:{status:'SAFE',blocked:false}};
    }});
  await controller.health;
  const runner=createRunner(registry,{catchErrors:false});
  const ctx={sessionKey:'fixture-session',runId:'fixture-run',toolCallId:'fixture-call'};
  const blocked=await runner.runBeforeToolCall({toolName:'exec',params:{},toolCallId:'fixture-call'},ctx);
  assert.equal(blocked.block,true,'real host dispatcher must preserve the block');
  const background=runner.runAfterToolCall({toolName:'read',result:'harmless document',toolCallId:'fixture-call'},ctx);
  const early=runner.runToolResultPersist({toolName:'read',toolCallId:'fixture-call',message:{content:'harmless document'}},ctx);
  assert.equal(early?.message.content,'harmless document','shadow persistence must preserve content');
  assert.equal(rows.find(row=>row.hook==='tool_result_persist').screening_state,'pending');
  release();await background;
  assert(rows.some(row=>row.hook==='after_tool_call'&&row.verdict==='SAFE'));
  console.log('Installed OpenClaw dispatcher: block propagation and asynchronous screening race verified');
})().catch(error=>{console.error(error);process.exitCode=1;});

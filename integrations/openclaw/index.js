'use strict';
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {createBridge}=require('./bridge');
const {createReceipts}=require('./receipts');
const VERSION=require('./openclaw.plugin.json').version;
const hash=crypto.createHash('sha256');
for(const name of ['index.js','bridge.js','receipts.js','openclaw.plugin.json'])hash.update(fs.readFileSync(path.join(__dirname,name)));
const ADAPTER_FINGERPRINT=hash.digest('hex');
const NOTICE='This content was withheld by the security guard. Please provide safe context or ask the operator to review it.';
const MODES=new Set(['enforce','shadow','off']);
function textOf(value){if(typeof value==='string')return value;if(value==null)return '';if(Array.isArray(value))return value.map(textOf).join('\n');if(value.content)return textOf(value.content);if(typeof value.text==='string')return value.text;return JSON.stringify(value);}
function keyOf(event,ctx={}){return ctx.sessionKey||ctx.sessionId||event.sessionKey||event.sessionId||ctx.runId||event.runId||null;}
function identity(value){return String(value||'').toLowerCase().replace(/^(?:(?:whatsapp|discord|user):)+/,'');}
function groupOf(to){return /@g\.us|@broadcast|:group:|group-chat|:channel:|discord-channel/i.test(to);}
function toolResult(result){return {content:[{type:'text',text:JSON.stringify(result)}],details:result};}

function activate(api, dependencies={}) {
  const config=api.pluginConfig||{};
  if(config.enabled===false)return;
  const modes={effect:config.effectBoundaryMode||'enforce',returns:config.toolReturnMode||'enforce',vet:config.skillVetMode||'enforce'};
  for(const mode of Object.values(modes))if(!MODES.has(mode))throw new Error('Invalid Jataayu enforcement mode');
  const receipts=createReceipts({config,version:VERSION,fingerprint:ADAPTER_FINGERPRINT,sink:dependencies.receiptSink,logger:api.logger||console});
  const on=(name,handler,mode='enforce')=>api.on(name,receipts.wrap(name,handler,mode),['before_agent_run','message_sending'].includes(name)?{priority:100}:undefined);
  const middlewareRuntimes=modes.returns==='shadow'?['openclaw','codex']:['openclaw'];
  const raw=dependencies.request||createBridge(config);
  const base={schema_version:1,config};
  let coreFingerprint;
  let fleetReady=!config.fleetExtensionPath;
  const health=raw({...base,operation:'health'}).then(response=>{
    if(response.schema_version!==1||response.error||response.core_version!==VERSION||!response.core_fingerprint)throw new Error('Jataayu core/adapter version mismatch');
    coreFingerprint=response.core_fingerprint;
    receipts.setCore(coreFingerprint);
    const status={core_version:response.core_version,core_fingerprint:coreFingerprint,adapter_version:VERSION,
      adapter_fingerprint:ADAPTER_FINGERPRINT,schema_version:1,pid:process.pid,fleet_ready:fleetReady,modes,tool_result_observation_runtimes:typeof api.registerAgentToolResultMiddleware==='function'?middlewareRuntimes:[],tool_result_replacement_runtimes:typeof api.registerAgentToolResultMiddleware==='function'?['openclaw']:[],loaded_at:new Date().toISOString()};
    try{if(config.runtimeStatusPath)fs.writeFileSync(config.runtimeStatusPath,JSON.stringify(status),{mode:0o600});}catch{}
    return status;
  });
  // Activation is synchronous in OpenClaw; every security operation awaits readiness.
  health.catch(()=>{});
  async function request(operation,data={},timeout=6000){
    await health;
    receipts.note({input_bytes:typeof data.content==='string'?Buffer.byteLength(data.content):0,deadline_ms:timeout});
    const response=await raw({...base,operation,...data},timeout);
    if(response.error||response.schema_version!==1||response.core_version!==VERSION||response.core_fingerprint!==coreFingerprint||!response.result||typeof response.result!=='object')throw new Error('Invalid or changed Jataayu runtime; reload required');
    const r=response.result;
    if(operation==='authorize'&&!['allow','deny','needs_approval'].includes(r.decision))throw new Error('Invalid authorization verdict');
    if(['inbound','tool_return'].includes(operation)&&!['SAFE','LOW','MEDIUM','HIGH'].includes(r.status))throw new Error('Invalid screening verdict');
    if(operation==='outbound'&&!['SAFE','WARN','BLOCK'].includes(r.status))throw new Error('Invalid outbound verdict');
    if(operation==='recover'&&(!['send','withhold'].includes(r.action)||typeof r.text!=='string'||typeof r.changed!=='boolean'))throw new Error('Invalid recovery verdict');
    if(operation==='vet'&&!['SAFE','REVIEW','MALICIOUS'].includes(r.verdict))throw new Error('Invalid skill verdict');
    receipts.verdict(operation,r);
    return r;
  }
  // Hooks keep origin metadata only. Effects, policy and screening live in Python.
  const origins=new Map(), results=new Map(), middlewareResults=new Map();
  function bounded(map,key,value){if(!key)return;map.set(key,value);while(map.size>512)map.delete(map.keys().next().value);}
  function external(key,source='external_result'){bounded(origins,key,[...new Set([...(origins.get(key)||[]),source])]);}
  function resultKey(event,ctx={}){const key=keyOf(event,ctx),call=event.toolCallId||ctx.toolCallId;return key&&call?JSON.stringify([key,call]):null;}
  let fleet={};
  if(config.fleetExtensionPath){
    try{fleet=require(config.fleetExtensionPath);fleet.activate?.(api);fleetReady=true;}
    catch{api.on('before_dispatch',event=>event.isGroup?{handled:true}:undefined);}
  }
  // Legacy payload-bearing ledgers are superseded by metadata-only decision receipts.
  function record(kind,event){if(event.classifier_error)receipts.note({classifier_error:'unavailable'});
    if(Number.isFinite(event.classifier_p_injection))receipts.note({classifier_score:event.classifier_p_injection});
    if(Number.isFinite(event.classifier_ms))receipts.note({classifier_ms:event.classifier_ms});}
  function failed(kind,error){receipts.note({error_category:error?.code&&/^runtime_[a-z_]+$/.test(error.code)?error.code:'runtime_failure',would_intervene:true});}
  const trusted=config.ownerIdentifiers||config.trustedSenders||[];
  function owner(event){return event.senderIsOwner===true||trusted.some(id=>id&&[event.senderId,event.sender,event.from,event.userId].some(v=>identity(v)===identity(id)));}

  on('before_agent_run',async(event,ctx)=>{
    const key=keyOf(event,ctx), isOwner=owner(event);
    // Missing state after eviction/restart does not imply a fresh trusted context.
    receipts.note({provenance_reason:!key?'missing_identity':!isOwner?'non_owner_input':event.isNewSession===true?'new_owner_session':'unknown_history'});
    if(!isOwner)external(key,'external_input');
    else if(!origins.has(key))bounded(origins,key,event.isNewSession===true?['owner']:['unknown-history']);
    if(config.enforceInbound===false)return {outcome:'pass'};
    const content=textOf(event.prompt||event.content||event.text);
    if(!content)return {outcome:'pass'};
    try{
      const r=await request('inbound',{content,surface:isOwner?'direct-message':'unknown'});
      const blocked=!isOwner&&config.blockOnInboundHigh!==false&&(r.blocked||r.status==='HIGH');
      let extra={};try{extra=await fleet.classifierShadow?.(content,r.status,config);}catch{/* observer only */}
      record('inbound',{...r,...extra,blocked,decision:blocked?'block':isOwner?'owner-allow':'pass',content,content_len:content.length});
      return blocked?{outcome:'block',reason:r.findings,message:NOTICE,category:'prompt-injection'}:{outcome:'pass'};
    }catch(error){failed('inbound',error);return isOwner?{outcome:'pass'}:{outcome:'block',reason:'Security check unavailable',message:NOTICE};}
  },config.enforceInbound===false?'off':'enforce');
  function payloadHash(result){
    const payload=result&&typeof result==='object'?{content:result.content,details:result.details}:result??null;
    return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  }
  function rememberMiddleware(event,ctx,result,verdict){
    bounded(middlewareResults,resultKey(event,ctx),{hash:payloadHash(result),tool:event.toolName,verdict});
  }
  // Codex can await shadow observations but discards replacement output.
  // Never register its middleware as enforcement-capable.
  if(typeof api.registerAgentToolResultMiddleware==='function'){
    api.registerAgentToolResultMiddleware(receipts.wrap('agent_tool_result',async(event,ctx)=>{
      if(!(config.trustedResultTools||[]).includes(event.toolName))external(keyOf(event,ctx));
      receipts.note({screening_path:'awaited_middleware',host_runtime:ctx?.runtime||'openclaw',replacement_supported:ctx?.runtime!=='codex'});
      if(modes.returns==='off'){receipts.note({screening_state:'disabled'});return;}
      try{
        // Include details: structured output can carry instructions too.
        const r=await request('tool_return',{tool_name:event.toolName,content:JSON.stringify(event.result)},config.toolReturnTimeoutMs||6000);
        receipts.note({screening_state:'complete'});
        if(modes.returns==='enforce'&&(r.blocked||r.status==='HIGH')){
          const result={content:[{type:'text',text:NOTICE}],details:{jataayuWithheld:true}};
          rememberMiddleware(event,ctx,result,{status:'HIGH',blocked:true});return {result};
        }
        rememberMiddleware(event,ctx,event.result,r);
      }catch(error){
        failed('tool-return',error);receipts.note({screening_state:'error'});
        if(modes.returns==='enforce'){
          const result={content:[{type:'text',text:NOTICE}],details:{jataayuWithheld:true}};
          rememberMiddleware(event,ctx,result,{status:'HIGH',blocked:true});return {result};
        }
      }
    },modes.returns),{runtimes:middlewareRuntimes});
  }
  // Retain legacy observations/persistence protection for host paths that do not
  // invoke middleware. These receipts are distinct from awaited screening.
  on('after_tool_call',async(event,ctx)=>{
    receipts.note({screening_path:'legacy_after_hook'});
    const key=keyOf(event,ctx);
    // Provenance is independent of detector outcome and remains across turns.
    if(!(config.trustedResultTools||[]).includes(event.toolName))external(key);
    if(modes.returns==='off')return;
    const prior=middlewareResults.get(resultKey(event,ctx));
    if(prior?.verdict&&prior.tool===event.toolName&&prior.hash===payloadHash(event.result)){
      receipts.verdict('tool_return',prior.verdict);
      receipts.note({screening_path:'awaited_middleware_reuse',screening_state:'complete',screening_reused:true});
      bounded(results,resultKey(event,ctx),{state:'complete',blocked:prior.verdict.blocked||prior.verdict.status==='HIGH',persisted:false});
      return;
    }
    const screening={state:'pending',blocked:true,persisted:false};
    bounded(results,resultKey(event,ctx),screening);
    try{
      const r=await request('tool_return',{tool_name:event.toolName,content:textOf(event.result??event.output??event.content)},config.toolReturnTimeoutMs||6000);
      screening.state='complete';screening.blocked=r.blocked||r.status==='HIGH';
      receipts.note({completed_after_persist:screening.persisted});
      record('effect',{kind:'tool-return',mode:modes.returns,tool:event.toolName,...r});
    }catch(error){screening.state='error';receipts.note({completed_after_persist:screening.persisted});failed('tool-return',error);}
  },modes.returns);
  on('tool_result_persist',(event,ctx)=>{
    const key=resultKey(event,ctx),verdict=results.get(key);results.delete(key);
    const completed=middlewareResults.get(key);middlewareResults.delete(key);
    if(completed&&completed.tool===event.toolName&&completed.hash===payloadHash(event.message)){
      if(verdict)verdict.persisted=true;
      receipts.note({screening_path:'awaited_middleware',screening_state:'complete',would_intervene:completed.verdict?.blocked===true||completed.verdict?.status==='HIGH'});
      return;
    }
    if(completed){
      receipts.note({screening_path:'awaited_middleware',screening_state:'payload_changed',would_intervene:true});
      if(modes.returns==='enforce')return {message:{...event.message,content:[{type:'text',text:NOTICE}],details:{jataayuWithheld:true}}};
      return;
    }
    receipts.note({screening_path:'legacy_persist_hook'});
    if(verdict)verdict.persisted=true;
    receipts.note({screening_state:modes.returns==='off'?'disabled':verdict?.state||'missing',would_intervene:modes.returns==='off'?null:verdict?.blocked!==false});
    if(modes.returns!=='enforce')return;
    // Missing/late screening is not proof that a result is safe.
    if(verdict?.blocked===false)return;
    return {message:{...event.message,content:[{type:'text',text:NOTICE}],details:{jataayuWithheld:true}}};
  },modes.returns);
  on('before_tool_call',async(event,ctx)=>{
    middlewareResults.delete(resultKey(event,ctx));
    results.delete(resultKey(event,ctx));
    if(modes.effect==='off')return;
    const key=keyOf(event,ctx), sources=origins.get(key);
    receipts.note({provenance_reason:!key?'missing_identity':!sources?'unknown_history':sources.includes('external_result')?'external_result':sources.includes('external_input')?'external_input':sources.includes('unknown-history')?'unknown_history':'owner_session'});
    try{
      const r=await request('authorize',{tool_name:event.toolName,params:event.params||{},origins:origins.get(keyOf(event,ctx))||[]},config.effectTimeoutMs||6000);
      record('effect',{kind:'effect_boundary',mode:modes.effect,tool:event.toolName,...r});
      if(modes.effect==='shadow'||r.decision==='allow')return;
      if(r.decision==='needs_approval'&&config.effectApprovalMode==='ask')return {requireApproval:{title:`Approve ${event.toolName}?`,description:r.reason,severity:'warning'}};
      return {block:true,blockReason:r.reason};
    }catch(error){failed('effect_boundary',error);if(modes.effect==='enforce')return {block:true,blockReason:'Jataayu authorization unavailable'};}
  },modes.effect);
  on('before_install',async event=>{
    if(modes.vet==='off')return;
    try{
      if(!event.sourcePath)throw new Error('Missing installation source');
      const r=await request('vet',{source_path:event.sourcePath,name:event.targetName},config.skillVetTimeoutMs||20000);
      record('effect',{kind:'skill_vet',mode:modes.vet,...r});
      if(modes.vet==='enforce'&&r.verdict!=='SAFE')return {block:true,blockReason:r.explanation};
      return {findings:[]};
    }catch(error){failed('skill_vet',error);return modes.vet==='enforce'?{block:true,blockReason:'Jataayu vetting unavailable'}:{findings:[]};}
  },modes.vet);
  on('message_sending',async event=>{
    if(config.enforceOutbound===false)return;
    const to=String(event.to||''),content=textOf(event.content),group=groupOf(to);
    if(!content)return;
    const recipients=config.ownerRecipients||config.trustedSenders||[];
    const ownerDM=!group&&recipients.some(id=>id&&identity(to)===identity(id));
    try{
      if(!fleetReady){receipts.note({reason_code:'fleet_unavailable',would_intervene:true});return {content:NOTICE};}
      const privateResult=fleet.beforeOutbound?.({content,to,ownerDM,group});
      if(privateResult){receipts.note({reason_code:'fleet_replacement',would_intervene:true});return privateResult;}
      if(ownerDM){receipts.note({reason_code:'owner_destination_bypass',would_intervene:false});return;}
      const surface=to.includes('@g.us')?'whatsapp-group':/discord/i.test(to)?'discord-channel':/github/i.test(to)?'github-comment':'group-chat';
      const r=await request('recover',{content,surface},config.recoverTimeoutMs||90000);
      if(r.action==='send'){
        if(r.changed)record('outbound',{...r,to,surface,content,rewritten:r.text,decision:'recover'});
        return r.text!==content?{content:r.text}:undefined;
      }
      record('outbound',{...r,to,surface,content,decision:'withhold'});
      try{fleet.alertWithheld?.(r,config);}catch{}
      return {content:NOTICE};
    }catch(error){failed('outbound',error);return {content:NOTICE};}
  },config.enforceOutbound===false?'off':'enforce');
  for(const operation of ['inbound','outbound'])api.registerTool({
    name:`jataayu_check_${operation}`,description:`Advisory ${operation} security check`,
    parameters:{type:'object',properties:{content:{type:'string'},surface:{type:'string'}},required:['content']},
    async execute(_id,params){try{return toolResult(await request(operation,{content:params.content,surface:params.surface||'unknown'}));}catch{return toolResult({status:'ERROR',safe:false});}}
  });
  return {health,request};
}
module.exports={id:'jataayu',name:'Jataayu Security',register:activate,activate,ADAPTER_FINGERPRINT};

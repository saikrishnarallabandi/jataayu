'use strict';
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {createBridge}=require('./bridge');
const VERSION=require('./openclaw.plugin.json').version;
const hash=crypto.createHash('sha256');
for(const name of ['index.js','bridge.js','openclaw.plugin.json'])hash.update(fs.readFileSync(path.join(__dirname,name)));
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
  const raw=dependencies.request||createBridge(config);
  const base={schema_version:1,config};
  let coreFingerprint;
  let fleetReady=!config.fleetExtensionPath;
  const health=raw({...base,operation:'health'}).then(response=>{
    if(response.schema_version!==1||response.error||response.core_version!==VERSION||!response.core_fingerprint)throw new Error('Jataayu core/adapter version mismatch');
    coreFingerprint=response.core_fingerprint;
    const status={core_version:response.core_version,core_fingerprint:coreFingerprint,adapter_version:VERSION,
      adapter_fingerprint:ADAPTER_FINGERPRINT,schema_version:1,pid:process.pid,fleet_ready:fleetReady,modes,loaded_at:new Date().toISOString()};
    try{if(config.runtimeStatusPath)fs.writeFileSync(config.runtimeStatusPath,JSON.stringify(status),{mode:0o600});}catch{}
    return status;
  });
  // Activation is synchronous in OpenClaw; every security operation awaits readiness.
  health.catch(()=>{});
  async function request(operation,data={},timeout=6000){
    await health;
    const response=await raw({...base,operation,...data},timeout);
    if(response.error||response.schema_version!==1||response.core_version!==VERSION||response.core_fingerprint!==coreFingerprint||!response.result||typeof response.result!=='object')throw new Error('Invalid or changed Jataayu runtime; reload required');
    const r=response.result;
    if(operation==='authorize'&&!['allow','deny','needs_approval'].includes(r.decision))throw new Error('Invalid authorization verdict');
    if(['inbound','tool_return'].includes(operation)&&!['SAFE','LOW','MEDIUM','HIGH'].includes(r.status))throw new Error('Invalid screening verdict');
    if(operation==='outbound'&&!['SAFE','WARN','BLOCK'].includes(r.status))throw new Error('Invalid outbound verdict');
    if(operation==='recover'&&(!['send','withhold'].includes(r.action)||typeof r.text!=='string'||typeof r.changed!=='boolean'))throw new Error('Invalid recovery verdict');
    if(operation==='vet'&&!['SAFE','REVIEW','MALICIOUS'].includes(r.verdict))throw new Error('Invalid skill verdict');
    return r;
  }
  // Hooks keep origin metadata only. Effects, policy and screening live in Python.
  const origins=new Map(), results=new Map();
  function bounded(map,key,value){if(!key)return;map.set(key,value);while(map.size>512)map.delete(map.keys().next().value);}
  function external(key){bounded(origins,key,['external']);}
  let fleet={};
  if(config.fleetExtensionPath){
    try{fleet=require(config.fleetExtensionPath);fleet.activate?.(api);fleetReady=true;}
    catch{api.on('before_dispatch',event=>event.isGroup?{handled:true}:undefined);}
  }
  function record(kind,event){try{fleet.record?.(kind,event,config);}catch{/* telemetry cannot change a decision */}}
  function failed(kind,error){record('effect',{kind,decision:'error',error:error.message});}
  const trusted=config.ownerIdentifiers||config.trustedSenders||[];
  function owner(event){return event.senderIsOwner===true||trusted.some(id=>id&&[event.senderId,event.sender,event.from,event.userId].some(v=>identity(v)===identity(id)));}

  api.on('before_agent_run',async(event,ctx)=>{
    const key=keyOf(event,ctx), isOwner=owner(event);
    // Missing state after eviction/restart does not imply a fresh trusted context.
    if(!isOwner)external(key);
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
  },{priority:100});
  api.on('after_tool_call',async(event,ctx)=>{
    const key=keyOf(event,ctx);
    // Provenance is independent of detector outcome and remains across turns.
    if(!(config.trustedResultTools||[]).includes(event.toolName))external(key);
    if(modes.returns==='off')return;
    try{
      const r=await request('tool_return',{tool_name:event.toolName,content:textOf(event.result??event.output??event.content)},config.toolReturnTimeoutMs||6000);
      bounded(results,event.toolCallId,r.blocked||r.status==='HIGH');
      record('effect',{kind:'tool-return',mode:modes.returns,tool:event.toolName,...r});
    }catch(error){bounded(results,event.toolCallId,true);failed('tool-return',error);}
  });
  api.on('tool_result_persist',event=>{
    if(modes.returns!=='enforce')return;
    const verdict=results.get(event.toolCallId);results.delete(event.toolCallId);
    // Missing/late screening is not proof that a result is safe.
    if(verdict===false)return;
    return {message:{...event.message,content:[{type:'text',text:NOTICE}]}};
  });
  api.on('before_tool_call',async(event,ctx)=>{
    if(modes.effect==='off')return;
    try{
      const r=await request('authorize',{tool_name:event.toolName,params:event.params||{},origins:origins.get(keyOf(event,ctx))||[]},config.effectTimeoutMs||6000);
      record('effect',{kind:'effect_boundary',mode:modes.effect,tool:event.toolName,...r});
      if(modes.effect==='shadow'||r.decision==='allow')return;
      if(r.decision==='needs_approval'&&config.effectApprovalMode==='ask')return {requireApproval:{title:`Approve ${event.toolName}?`,description:r.reason,severity:'warning'}};
      return {block:true,blockReason:r.reason};
    }catch(error){failed('effect_boundary',error);if(modes.effect==='enforce')return {block:true,blockReason:'Jataayu authorization unavailable'};}
  });
  api.on('before_install',async event=>{
    if(modes.vet==='off')return;
    try{
      if(!event.sourcePath)throw new Error('Missing installation source');
      const r=await request('vet',{source_path:event.sourcePath,name:event.targetName},config.skillVetTimeoutMs||20000);
      record('effect',{kind:'skill_vet',mode:modes.vet,...r});
      if(modes.vet==='enforce'&&r.verdict!=='SAFE')return {block:true,blockReason:r.explanation};
      return {findings:[]};
    }catch(error){failed('skill_vet',error);return modes.vet==='enforce'?{block:true,blockReason:'Jataayu vetting unavailable'}:{findings:[]};}
  });
  api.on('message_sending',async event=>{
    if(config.enforceOutbound===false)return;
    const to=String(event.to||''),content=textOf(event.content),group=groupOf(to);
    if(!content)return;
    const recipients=config.ownerRecipients||config.trustedSenders||[];
    const ownerDM=!group&&recipients.some(id=>id&&identity(to)===identity(id));
    try{
      if(!fleetReady)return {content:NOTICE};
      const privateResult=fleet.beforeOutbound?.({content,to,ownerDM,group});
      if(privateResult)return privateResult;
      if(ownerDM)return;
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
  },{priority:100});
  for(const operation of ['inbound','outbound'])api.registerTool({
    name:`jataayu_check_${operation}`,description:`Advisory ${operation} security check`,
    parameters:{type:'object',properties:{content:{type:'string'},surface:{type:'string'}},required:['content']},
    async execute(_id,params){try{return toolResult(await request(operation,{content:params.content,surface:params.surface||'unknown'}));}catch{return toolResult({status:'ERROR',safe:false});}}
  });
  return {health,request};
}
module.exports={id:'jataayu',name:'Jataayu Security',register:activate,activate,ADAPTER_FINGERPRINT};

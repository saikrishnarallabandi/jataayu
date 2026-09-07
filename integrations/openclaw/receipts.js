'use strict';
// Host bookkeeping only: policy and detector decisions remain in the Python runtime.
const {AsyncLocalStorage}=require('node:async_hooks');
const {performance}=require('node:perf_hooks');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const digest=value=>crypto.createHash('sha256').update(String(value)).digest('hex');
const identifier=value=>typeof value==='string'&&value?digest(value):null;
const token=value=>typeof value==='string'&&/^[a-zA-Z0-9_.:/-]{1,100}$/.test(value)?value:null;
function createReceipts({config,version,fingerprint,sink,logger=console}){
  const storage=new AsyncLocalStorage();
  // Host configuration is fixed for this adapter instance; recreate it on reload.
  const policyId=digest(JSON.stringify({agent:config.agent,policyFile:config.policyFile,toolEffects:config.toolEffects,
    trustedResultTools:config.trustedResultTools,memoryTools:config.memoryTools}));
  let core=null;
  let directoryReady=false;
  const reportFailure=()=>{try{logger.error('[jataayu-receipt] write_failed; decision telemetry is incomplete');}catch{}};
  function write(row){
    try{
      if(sink){const pending=sink(row);if(pending?.catch)pending.catch(reportFailure);return;}
      if(!config.decisionLogPath)return;
      if(!directoryReady){
        fs.mkdirSync(path.dirname(config.decisionLogPath),{recursive:true,mode:0o700});
        directoryReady=true;
      }
      fs.appendFile(config.decisionLogPath,JSON.stringify(row)+'\n',{mode:0o600},error=>{
        if(error){
          // If an operator removes the directory, retry setup on the next event.
          // Report the failed append; never silently claim that receipt was saved.
          if(error.code==='ENOENT')directoryReady=false;
          reportFailure();
        }
      });
    }catch{reportFailure();}
  }
  function note(values){const state=storage.getStore();if(state)Object.assign(state.fields,values);}
  function wrap(hook,handler,mode){
    // An absent destination deliberately disables receipts, not a write failure.
    if(!sink&&!config.decisionLogPath)return handler;
    return function(event={},ctx={}){
      const start=performance.now();
      const state={fields:{}};
      function finish(result,error){
        let disposition='pass';
        if(result?.block||result?.outcome==='block'||result?.handled)disposition='block';
        else if(result?.requireApproval)disposition='request_approval';
        else if((result?.message&&hook==='tool_result_persist')||typeof result?.content==='string')disposition='replace';
        const call=event.toolCallId||ctx.toolCallId;
        const session=ctx.sessionKey||event.sessionKey||ctx.sessionId||event.sessionId;
        const run=ctx.runId||event.runId;
        const row={schema_version:1,kind:'decision_receipt',ts:new Date().toISOString(),decision_id:crypto.randomUUID(),
          host:'openclaw',traffic:config.receiptTraffic||'live',hook,mode,
          adapter_version:version,adapter_fingerprint:fingerprint,core_fingerprint:core,
          session_id:identifier(session),run_id:identifier(run),tool_call_id:identifier(call),
          correlation_status:!session?'missing_session':!call&&hook.includes('tool')?'missing_tool_call':'available',
          tool:token(event.toolName||ctx.toolName),duration_ms:Math.round((performance.now()-start)*1000)/1000,
          would_intervene:null,error_category:null,provenance_reason:null,
          policy_id:policyId,
          ...state.fields,adapter_disposition:disposition,host_acknowledgement:'unobserved'};
        if(error)row.error_category='hook_exception';
        write(row);return result;
      }
      return storage.run(state,()=>{
        try{const result=handler(event,ctx);
          // Preserve synchronous hook contracts; never wrap persistence in an async function.
          return result?.then?result.then(value=>finish(value),error=>{finish(undefined,error);throw error;}):finish(result);
        }catch(error){finish(undefined,error);throw error;}
      });
    };
  }
  function verdict(operation,result){
    const status=result.decision||result.status||result.verdict||result.action;
    const allowed=new Set(['allow','deny','needs_approval','SAFE','LOW','MEDIUM','HIGH','WARN','BLOCK','REVIEW','MALICIOUS','send','withhold']);
    note({operation,verdict:allowed.has(status)?status:'invalid',would_intervene:result.decision==='deny'||result.decision==='needs_approval'||result.changed===true||result.blocked===true||['HIGH','BLOCK','REVIEW','MALICIOUS','withhold'].includes(status),
      category:token(result.withheld_category),effect_class:token(result.effect_class),classification_source:token(result.classification_source),
      provenance:token(result.provenance),reason_code:token(result.reason_code),policy_fingerprint:token(result.policy_fingerprint)});
  }
  return {wrap,note,verdict,setCore:value=>{core=value;}};
}
module.exports={createReceipts};

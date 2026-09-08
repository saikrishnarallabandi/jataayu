'use strict';
const {spawn} = require('node:child_process');
const path = require('node:path');

function runtimeError(code,message){return Object.assign(new Error(message),{code});}
function createBridge(config) {
  return (request, timeoutMs=6000) => new Promise((resolve, reject) => {
    const env = {...process.env};
    if (config.jataayuPath) env.PYTHONPATH = [config.jataayuPath, env.PYTHONPATH].filter(Boolean).join(path.delimiter);
    if (config.llmInsecureTls === true && config.llmBackend === 'gateway' &&
        /^https:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/i.test(config.llmUrl || '')) env.JATAAYU_GATEWAY_INSECURE='1';
    const child = spawn(config.python || 'python3', ['-m', 'jataayu.runtime'], {env, stdio:['pipe','pipe','pipe']});
    let output='', done=false;
    const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(value);};
    const timer=setTimeout(()=>{child.kill('SIGKILL');finish(runtimeError('runtime_timeout','Jataayu runtime deadline exceeded'));},timeoutMs);
    child.on('error',()=>finish(runtimeError('runtime_unavailable','Jataayu runtime unavailable')));
    child.stdin.on('error',()=>finish(runtimeError('runtime_input_failed','Jataayu runtime input failed')));
    // Runtime diagnostics never become model-visible output or credential-bearing exceptions.
    child.stderr.resume();
    child.stdout.on('data',chunk=>{output+=chunk;if(Buffer.byteLength(output)>4*1024*1024){child.kill('SIGKILL');finish(runtimeError('runtime_response_too_large','Runtime response too large'));}});
    child.on('close',code=>{
      if(code!==0)return finish(runtimeError('runtime_exit_failed','Jataayu runtime failed'));
      try{finish(null,JSON.parse(output));}catch{finish(runtimeError('runtime_invalid_response','Invalid Jataayu runtime response'));}
    });
    child.stdin.end(JSON.stringify(request));
  });
}
module.exports={createBridge};

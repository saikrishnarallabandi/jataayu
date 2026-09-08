'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {createBridge}=require('./bridge');
(async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'jataayu-bridge-'));
 try{
  const executable=path.join(dir,'fixture');
  async function fixture(code,expected,timeout=1500){
   fs.writeFileSync(executable,`#!${process.execPath}\n${code}`,{mode:0o700});
   await assert.rejects(createBridge({python:executable})({},timeout),error=>error.code===expected);
  }
  await fixture('setTimeout(()=>{},10000);','runtime_timeout',100);
  await fixture('process.stdout.write("not-json");','runtime_invalid_response');
  await fixture('process.exit(3);','runtime_exit_failed');
  await assert.rejects(createBridge({python:path.join(dir,'missing')})({}),error=>['runtime_unavailable','runtime_input_failed'].includes(error.code));
  console.log('Bridge failure classification tests passed');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});

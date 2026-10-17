'use strict';
const decoder=new TextDecoder(),encoder=new TextEncoder();
function unbase64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
async function decryptReport(payload,password){
  if(payload.version!==1||payload.iterations!==600000||payload.algorithm!=='AES-256-GCM'||payload.kdf!=='PBKDF2-SHA256')throw new Error('unsupported');
  const salt=unbase64(payload.salt),iv=unbase64(payload.iv),cipher=unbase64(payload.ciphertext);
  if(salt.length!==16||iv.length!==12||cipher.length>5*1024*1024)throw new Error('invalid');
  const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:encoder.encode('fusion-dashboard:v1'),tagLength:128},key,cipher);
  return decoder.decode(clear);
}
if(typeof document!=='undefined'){
  const gate=document.getElementById('gate'),viewer=document.getElementById('viewer'),frame=document.getElementById('report'),form=document.getElementById('unlock'),error=document.getElementById('error'),button=document.getElementById('submit');
  form.addEventListener('submit',async e=>{
    e.preventDefault();button.disabled=true;button.textContent='正在解密…';error.textContent='';
    try{
      if(!globalThis.crypto?.subtle)throw new Error('crypto_unavailable');
      const response=await fetch('./payload.json',{cache:'no-store',credentials:'omit'});
      if(!response.ok)throw new Error('download_failed');
      const payload=await response.json();let text=await decryptReport(payload,document.getElementById('password').value);
      if(!/^<!doctype html>/i.test(text))throw new Error('invalid');
      frame.srcdoc=text;text='';form.reset();gate.hidden=true;viewer.hidden=false;
    }catch(err){error.textContent=err.message==='download_failed'?'报告暂时无法下载，请稍后重试。':err.message==='crypto_unavailable'?'请用支持加密功能的现代浏览器打开 HTTPS 页面。':'口令不正确，或报告文件已损坏。';}
    finally{button.disabled=false;button.textContent='解锁报告';}
  });
  document.getElementById('lock').addEventListener('click',()=>{frame.srcdoc='';viewer.hidden=true;gate.hidden=false;form.reset();document.getElementById('password').focus();});
}
if(typeof module!=='undefined')module.exports={decryptReport};

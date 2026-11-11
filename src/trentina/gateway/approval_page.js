(()=>{
const $=i=>document.getElementById(i);
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
// The one-time code rides in the link's #fragment, so it never reaches the
// server or a request log. On load, fill the form's code fields from the
// fragment (or this tab's remembered copy), store it, and strip it from the
// address bar. A reused tab that only changes its #fragment does not reload, so
// a freshly tapped link would sit unread — reload on hashchange, and on a
// back/forward (bfcache) restore, so the server-rendered load path always runs.
// On a page with no code field, forget the code so it cannot leak into a later
// formless view.
const CODE=/[#&]code=([A-Za-z0-9-]{1,64})/;
const KEY="tz-enrol-code";
// sessionStorage can throw (private mode, blocked storage); each helper says so
// by its return rather than swallowing it, and the caller carries on regardless.
const recall=()=>{try{return sessionStorage.getItem(KEY)||"";}catch(e){return "";}};
const remember=v=>{try{sessionStorage.setItem(KEY,v);}catch(e){return false;}return true;};
const forget=()=>{try{sessionStorage.removeItem(KEY);}catch(e){return false;}return true;};
const inputs=document.querySelectorAll("input[name=code]");
if(inputs.length){
const m=CODE.exec(location.hash);
const code=m?m[1]:recall();
if(m)remember(m[1]);
if(code)for(const e of inputs)e.value=code;
}else{forget();}
if(location.hash)history.replaceState(null,"",location.pathname+location.search);
addEventListener("hashchange",()=>{if(CODE.test(location.hash))location.reload();});
addEventListener("pageshow",e=>{if(e.persisted)location.reload();});
const t=$("ttl");
if(t){const deadline=Date.now()+(+t.dataset.seconds)*1000;const tick=()=>{const s=Math.round((deadline-Date.now())/1000);if(s<=0){location.reload();return;}t.textContent=Math.floor(s/60)+":"+String(s%60).padStart(2,"0");};tick();setInterval(tick,1000);}
const box=$("pk");if(!box)return;
const go=$("pk-go"),say=msg=>{$("pk-status").textContent=msg;};
if(!window.PublicKeyCredential||!window.isSecureContext){go.disabled=true;say("This browser cannot use a passkey here. Passkeys need https, or a gateway reached as localhost.");return;}
const post=(p,b)=>fetch(p,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}).then(r=>r.json().then(j=>({ok:r.ok,j})));
go.addEventListener("click",async()=>{
go.disabled=true;say("Waiting for your passkey…");
const d=box.dataset,c=$("pk-code"),n=$("pk-name");
const base={ceremony:d.ceremony,csrf:d.csrf||"",code:c?c.value.trim():"",next:d.next||""};
try{
const a=await post(d.begin,base);if(!a.ok)throw new Error(a.j.message);
const o=a.j;let body;
if(d.ceremony==="register"){
const k=await navigator.credentials.create({publicKey:{challenge:unb64(o.challenge),rp:{id:o.rpId,name:"Trentina"},user:{id:unb64(o.userId),name:o.userName,displayName:o.userName},pubKeyCredParams:o.algorithms.map(alg=>({type:"public-key",alg})),authenticatorSelection:{residentKey:"required",requireResidentKey:true,userVerification:"required"},attestation:"none",timeout:120000}});
const r=k.response,pk=r.getPublicKey?r.getPublicKey():null;
if(!pk)throw new Error("This browser did not hand over the passkey’s public key. Try a current browser.");
body={...base,challenge:o.challenge,id:b64(k.rawId),clientDataJSON:b64(r.clientDataJSON),authenticatorData:b64(r.getAuthenticatorData()),publicKey:b64(pk),publicKeyAlgorithm:r.getPublicKeyAlgorithm(),name:n?n.value:""};
}else{
const k=await navigator.credentials.get({publicKey:{challenge:unb64(o.challenge),rpId:o.rpId,userVerification:"required",timeout:120000,allowCredentials:[]}});
const r=k.response;
body={...base,challenge:o.challenge,id:b64(k.rawId),clientDataJSON:b64(r.clientDataJSON),authenticatorData:b64(r.authenticatorData),signature:b64(r.signature)};
}
const f=await post(d.finish,body);if(!f.ok)throw new Error(f.j.message);
location.assign(f.j.next);
}catch(e){say(e&&e.name==="NotAllowedError"?"Cancelled, or no passkey was available. Try again.":(e&&e.message)||"That did not work. Try again.");go.disabled=false;}
});
})();

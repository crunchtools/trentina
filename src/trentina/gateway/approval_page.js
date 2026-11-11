(()=>{
const $=i=>document.getElementById(i);
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
// The one-time code rides in the link's #fragment, so it never reaches the
// server or a request log. Read it on load AND on every later fragment change,
// so a freshly opened link refills the form even when a phone reuses a tab that
// is already open here (a fragment-only change does not reload). Remember it for
// this tab so a reload keeps it, and strip it from the address bar once read.
const readCode=()=>{
const m=/[#&]code=([A-Za-z0-9_-]{1,64})/.exec(location.hash);
try{
if(m){sessionStorage.setItem("tz-enrol-code",m[1]);return m[1];}
return sessionStorage.getItem("tz-enrol-code")||"";
}catch(e){
// sessionStorage can be unavailable (private mode, blocked storage); fall
// back to the code the fragment carried this time, or none.
return m?m[1]:"";
}
};
const takeCode=()=>{
const c=readCode();
if(c)for(const e of document.querySelectorAll("input[name=code]"))e.value=c;
if(location.hash)history.replaceState(null,"",location.pathname+location.search);
};
takeCode();
addEventListener("hashchange",takeCode);
const t=$("ttl");
if(t){let s=+t.dataset.seconds;const tick=()=>{if(s<=0){location.reload();return;}t.textContent=Math.floor(s/60)+":"+String(s%60).padStart(2,"0");s--;};tick();setInterval(tick,1000);}
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

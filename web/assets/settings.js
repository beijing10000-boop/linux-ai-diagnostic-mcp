"use strict";
(async()=>{
  try{
    const data=await Diag.api("settings");
    for(const key of ["app_id","admin_open_id","public_url"])
      document.getElementById(key).value=data[key]||"";
    document.getElementById("sshStatus").textContent=data.ssh_private_key_configured?
      "已配置加密 SSH 私钥":"尚未配置 SSH 私钥";
  }catch(e){Diag.message("status",e.message,true);}
})();
document.getElementById("saveSettings").addEventListener("click",async()=>{
  const data={};
  for(const key of ["app_id","admin_open_id","public_url"]){
    const value=document.getElementById(key).value.trim();
    if(value)data[key]=value;
  }
  const secret=document.getElementById("app_secret").value;
  if(secret)data.app_secret=secret;
  try{
    const result=await Diag.api("settings",{method:"PUT",body:data});
    document.getElementById("app_secret").value="";
    Diag.message("status",result.reauth_required?"设置已更新，请重新登录":"设置已保存");
    if(result.reauth_required)location.href="/login";
  }catch(e){Diag.message("status",e.message,true);}
});
document.getElementById("saveSSH").addEventListener("click",async()=>{
  const key=document.getElementById("ssh_key").value;
  const passphrase=document.getElementById("ssh_passphrase").value;
  if(!key){Diag.message("status","请先粘贴 Ed25519 私钥",true);return;}
  try{
    await Diag.api("settings/ssh",{method:"PUT",body:{private_key:key,passphrase}});
    document.getElementById("ssh_key").value="";
    document.getElementById("ssh_passphrase").value="";
    document.getElementById("sshStatus").textContent="已配置加密 SSH 私钥";
    Diag.message("status","SSH 私钥已加密保存，不会回显");
  }catch(e){Diag.message("status",e.message,true);}
});
document.getElementById("logout").addEventListener("click",async()=>{
  try{await Diag.api("logout",{method:"POST"});location.href="/login";}
  catch(e){Diag.message("status",e.message,true);}
});
(async()=>{try{const logs=await Diag.api("audit");const list=document.getElementById("audit");
  logs.slice(0,15).forEach(r=>{const tr=document.createElement("tr");
    for(const value of [new Date(r.time*1000).toLocaleString(),r.actor,r.action]){
      const td=document.createElement("td");td.textContent=String(value);tr.append(td);
    }list.append(tr);});
}catch(e){Diag.message("status",e.message,true);}})();

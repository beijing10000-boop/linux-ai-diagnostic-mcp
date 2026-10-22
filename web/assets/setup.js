"use strict";
document.getElementById("setupForm").addEventListener("submit",async e=>{
  e.preventDefault();
  const button=e.target.querySelector("button");button.disabled=true;
  try{
    const data=Object.fromEntries(new FormData(e.target));
    const response=await fetch("/setup",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify(data),credentials:"same-origin"});
    const result=await response.json();
    if(!response.ok)throw Error(result.detail||"初始化失败");
    document.getElementById("setupStatus").textContent=
      "初始化成功。请在飞书应用后台配置回调："+result.redirect_uri;
    e.target.reset();
    document.getElementById("loginLink").hidden=false;
  }catch(err){document.getElementById("setupStatus").textContent="初始化失败："+err.message}
  finally{button.disabled=false;}
});

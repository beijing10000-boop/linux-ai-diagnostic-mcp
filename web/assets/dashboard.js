"use strict";
(async()=>{
  try{
    const [hosts,groups,proxies]=await Promise.all(["hosts","groups","proxies"].map(x=>Diag.api(x)));
    document.getElementById("hostCount").textContent=hosts.length;
    document.getElementById("groupCount").textContent=groups.length;
    document.getElementById("proxyCount").textContent=proxies.length;
    const select=document.getElementById("host");
    hosts.forEach(h=>{
      const opt=document.createElement("option");opt.value=h.id;opt.textContent=h.name+" · "+h.address;
      select.append(opt);
    });
    document.getElementById("run").disabled=!hosts.length;
    if(!hosts.length)Diag.message("notice","尚未登记主机。请先前往资产管理添加并核对 SSH 主机公钥。");
  }catch(e){Diag.message("notice",e.message,true);}
})();
document.getElementById("run").addEventListener("click",async()=>{
  const output=document.getElementById("output");
  output.textContent="正在执行安全诊断...";
  const action=document.getElementById("action").value;
  try{
    const result=await Diag.api("diagnose",{method:"POST",body:{
      host_id:Number(document.getElementById("host").value),
      action,service:action==="service"?document.getElementById("service").value:null}});
    output.textContent=JSON.stringify(result,null,2);
  }catch(e){output.textContent="诊断未执行："+e.message;}
});

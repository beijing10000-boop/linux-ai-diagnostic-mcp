"use strict";
const Diag={
  csrf:"",
  async init(){
    const response=await fetch("/api/me",{credentials:"same-origin",cache:"no-store"});
    if(response.status===401||response.status===403){location.href="/login";throw Error("请使用飞书登录");}
    if(!response.ok)throw Error("无法验证管理员登录");
    const data=await response.json();this.csrf=data.csrf_token;
    for(const node of document.querySelectorAll("[data-version]"))node.textContent="v"+data.version;
    return data;
  },
  async api(path,options={}){
    await this.ready;
    const method=options.method||"GET";
    const headers={"Accept":"application/json"};
    if(options.body!==undefined)headers["Content-Type"]="application/json";
    if(method!=="GET"&&method!=="HEAD")headers["X-CSRF-Token"]=this.csrf;
    const response=await fetch("/api/"+path,{method,headers,
      body:options.body===undefined?undefined:JSON.stringify(options.body),
      credentials:"same-origin",cache:"no-store"});
    if(response.status===401){location.href="/login";throw Error("登录已过期");}
    const data=await response.json().catch(()=>({detail:"无法解析服务端响应"}));
    if(!response.ok)throw Error(typeof data.detail==="string"?data.detail:"请求失败："+response.status);
    return data;
  },
  message(id,value,error=false){
    const el=document.getElementById(id);
    if(el){el.textContent=value;el.classList.toggle("error",error);}
  }
};
window.Diag=Diag;
Diag.ready=Diag.init();

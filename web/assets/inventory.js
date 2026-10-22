"use strict";
const $=id=>document.getElementById(id);
function table(id,rows,fields,kind){
  const target=$(id);target.replaceChildren();
  const wrap=document.createElement("div");wrap.className="table-scroll";
  const table=document.createElement("table");const h=document.createElement("tr");
  fields.forEach(([field,label])=>{const th=document.createElement("th");th.textContent=label;h.append(th);});
  const th=document.createElement("th");th.textContent="操作";h.append(th);table.append(h);
  rows.forEach(item=>{
    const tr=document.createElement("tr");
    fields.forEach(([field])=>{const td=document.createElement("td");
      td.textContent=field==="host_key"?(item[field]?"已固定":"未配置"):String(item[field]??"—");tr.append(td);});
    const td=document.createElement("td");const b=document.createElement("button");
    b.className="danger";b.textContent="删除";
    b.addEventListener("click",async()=>{
      if(!confirm("确认删除 "+item.name+"？"))return;
      try{await Diag.api(kind+"/"+item.id,{method:"DELETE"});await refresh();}
      catch(e){Diag.message("status",e.message,true);}
    });td.append(b);tr.append(td);table.append(tr);
  });wrap.append(table);target.append(wrap);
}
function options(id,rows,label){
  const el=$(id);el.replaceChildren();
  const blank=document.createElement("option");blank.value="";blank.textContent=label;el.append(blank);
  rows.forEach(r=>{const o=document.createElement("option");o.value=r.id;o.textContent=r.name;el.append(o)});
}
async function refresh(){
  try{
    const [groups,proxies,hosts]=await Promise.all(["groups","proxies","hosts"].map(x=>Diag.api(x)));
    table("groups",groups,[["name","名称"],["description","描述"]],"groups");
    table("proxies",proxies,[["name","代理"],["status","状态"]],"proxies");
    table("hosts",hosts,[["name","主机"],["address","IP"],["group_id","主机组 ID"],["proxy_id","代理 ID"],["host_key","主机公钥"]],"hosts");
    options("groupSelect",groups,"不分组");
    options("proxySelect",proxies,"直连");
    Diag.message("status","已加载 "+hosts.length+" 台主机 · "+groups.length+" 个主机组");
  }catch(e){Diag.message("status",e.message,true);}
}
for(const [form,path] of [["groupForm","groups"],["proxyForm","proxies"],["hostForm","hosts"]]){
  $(form).addEventListener("submit",async e=>{
    e.preventDefault();
    const data=Object.fromEntries(new FormData(e.target));
    if(path==="hosts"){
      data.ssh_port=Number(data.ssh_port);
      for(const key of ["group_id","proxy_id"])data[key]=data[key]?Number(data[key]):null;
    }
    try{await Diag.api(path,{method:"POST",body:data});e.target.reset();await refresh();}
    catch(err){Diag.message("status",err.message,true);}
  });
}
$("refresh").addEventListener("click",refresh);
refresh();

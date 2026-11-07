const fs=require('fs'),path=require('path');
module.exports=function(){
  const www=path.join(__dirname,'../../runtime/www');
  const html=fs.readFileSync(path.join(www,'index.html'),'utf8');
  return [...html.matchAll(/<script src="([^"]+)"/g)]
    .map(m=>m[1]).filter(n=>n==='app.js'||n.startsWith('domains/'))
    .map(n=>fs.readFileSync(path.join(www,n),'utf8')).join('\n;\n');
};

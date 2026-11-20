(function(root){
'use strict';
const MAX_LENGTH=200000, MAX_FINDINGS=200, labels={high:'高',medium:'中',low:'低',info:'情報'};
const rules={
targetCheckout:['high','信頼できないPRコードを高権限でcheckout','pull_request_target / workflow_run は通常のPRより強い権限で動きます。PR headをcheckoutすると攻撃者のコードをその権限で実行する危険があります。','PR headを使う処理を権限のない別workflowへ分け、権限を最小化してください。通常のPR確認には pull_request を検討してください。'],
injection:['high','イベント由来の値をrunへ直接埋め込み','issue/PRのタイトルや本文、コメント、head_refなどは外部から制御できます。runへ直接展開するとシェルコマンドになるおそれがあります。','値をstep.envへ渡し、スクリプトでは引用した環境変数として読み取ってください。'],
noPermissions:['medium','permissionsの明示がない','GITHUB_TOKENの権限がリポジトリや組織の既定値に依存します。','permissions: {} を基本にし、必要な権限だけを個別に付与してください。'],
writeAll:['high','permissions: write-all','GITHUB_TOKENに広い書込み権限を与え、侵害時の影響が大きくなります。','permissions: {} を基本にし、必要な書込み権限だけを追加してください。'],
targetWrite:['high','危険なトリガーと書込み権限の併用','強いイベント権限とcontents: write等を組み合わせています。','書込み権限を削除するか、権限を持つ処理と外部入力の処理を別workflowに分けてください。'],
broadWrite:['medium','GITHUB_TOKENの広い書込み権限','contents: write等によりworkflow侵害時にリポジトリを書き換えられる可能性があります。','permissions: {} または必要なread権限に限定してください。'],
unpinnedMain:['medium','actionが可変ブランチ指定','@main / @master は参照先が変わり、レビュー後に実行コードが変わる可能性があります。','確認済みの40桁コミットSHAに固定してください。'],
unpinnedAction:['low','actionがコミットSHAに固定されていない','タグやブランチは後から参照先が変わる可能性があります。','確認済みの40桁コミットSHAに固定してください。'],
echoSecret:['high','secretをログへ出力する可能性','Actionsログから秘密値が漏れるおそれがあります。','secretを表示せず、必要なコマンドへ最小限で渡してください。'],
insecure:['high','危険なActionsコマンド設定','ACTIONS_ALLOW_UNSECURE_COMMANDSを有効にしています。','設定を削除し、GITHUB_OUTPUT / GITHUB_ENVを使用してください。'],
token:['high','トークン・キーらしい値の直書き','認証情報らしい値があります。値は表示しません。実在値なら漏えいした可能性があります。','値を削除し、実在する値なら失効・交換してください。'],
checkout:['low','checkout後も認証情報が残る設定','checkoutは既定で後続step向けに認証情報を保持します。','読み取りだけなら persist-credentials: false を設定してください。'],
selfHosted:['medium','pull_requestでself-hosted runnerを使用','外部PRのコードが永続的な認証情報やLAN接続権を持つrunner上で動く可能性があります。','外部PRではGitHub-hosted runnerを使い、self-hosted runnerは信頼できる入力に限定してください。'],
curlPipe:['medium','取得したスクリプトをそのまま実行','応答が置き換わると未レビューのコードを実行する可能性があります。','取得元を固定し、内容とハッシュを検証してから実行してください。'],
targetInfo:['info','pull_request_targetトリガーを使用','このイベントはbase側workflowと通常より強い権限で動くことがあります。','外部PRのコードを実行するだけなら pull_request を検討し、権限を最小化してください。'],
workflowInfo:['info','workflow_runトリガーを使用','先行workflowの成果物やPR情報を信頼境界を越えた入力として扱ってください。','未検証の成果物やコードを権限のある後続workflowで実行しないでください。']
};
const examples={
 targetCheckout:'on: pull_request\npermissions: {}\njobs:\n  check:\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
 injection:'- env:\n    TITLE: ${{ github.event.pull_request.title }}\n  run: printf \'%s\\n\' "$TITLE"',
 noPermissions:'permissions: {}\njobs:\n  build:\n    permissions:\n      contents: read',
 writeAll:'permissions: {}',
 targetWrite:'on: pull_request\npermissions:\n  contents: read',
 broadWrite:'permissions:\n  contents: read',
 unpinnedMain:'- uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
 echoSecret:'- env:\n    TOKEN: ${{ secrets.TOKEN }}\n  run: tool --token-env TOKEN',
 insecure:'jobs:\n  build:\n    steps:\n      - run: echo "result=$VALUE" >> "$GITHUB_OUTPUT"',
 selfHosted:'jobs:\n  test:\n    runs-on: ubuntu-latest',
 curlPipe:'- run: |\n    curl -o setup.sh https://example.invalid/setup.sh\n    echo "0123456789abcdef0123456789abcdef01234567  setup.sh" | sha256sum -c -\n    bash setup.sh'
};
const unsafeSample='name: 危険な例\non:\n  pull_request_target:\n    types: [opened, synchronize]\npermissions: write-all\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: vendor/scanner@main\n      - run: echo "${{ github.event.issue.title }}"\n      - run: |\n          echo "${{ github.event.comment.body }}"\n          curl https://example.invalid/install.sh | bash\n';
const safeSample='name: 通常の例\non: pull_request\npermissions: {}\njobs:\n  test:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n        with:\n          persist-credentials: false\n      - env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n        run: printf "%s" "$PR_TITLE"\n';
function stripComment(s){let q='',e=false;for(let i=0;i<s.length;i++){const c=s[i];if(e){e=false;continue;}if(q==='"'&&c==='\\'){e=true;continue;}if(q&&c===q){if(q==="'"&&s[i+1]==="'"){i++;continue;}q='';}else if(!q&&(c==='"'||c==="'"))q=c;else if(!q&&c==='#'&&(i===0||/\s/.test(s[i-1])))return s.slice(0,i);}return s;}
function split(s){let a=[],start=0,q='',d=0;for(let i=0;i<s.length;i++){const c=s[i];if(q&&c===q)q='';else if(!q&&(c==='"'||c==="'"))q=c;else if(!q&&(c==='['||c==='{'))d++;else if(!q&&(c===']'||c==='}'))d--;else if(!q&&!d&&c===','){a.push(s.slice(start,i).trim());start=i+1;}}a.push(s.slice(start).trim());return a.filter(Boolean);}
function pair(s){const m=/^(?:"([^"\n]+)"|'([^'\n]+)'|([\w.-]+))\s*:(?:\s*(.*))?$/.exec(s);return m?{key:m[1]||m[2]||m[3],value:m[4]||''}:null;}
function val(s){s=s.trim();if(s.length>1&&s[0]==='"'&&s.at(-1)==='"'){try{return JSON.parse(s)}catch(_){return s.slice(1,-1)}}if(s.length>1&&s[0]==="'"&&s.at(-1)==="'")return s.slice(1,-1).replace(/''/g,"'");return s;}
function node(kind,key,value,line,indent){return{kind,key,value,line,indent,children:[],blockLines:[]};}
function inline(s,key,line,indent){s=s.trim();if(s==='{}')return node('map',key,'',line,indent);if(s==='[]')return node('seq',key,'',line,indent);if(s[0]==='['&&s.at(-1)===']'){const n=node('seq',key,'',line,indent);split(s.slice(1,-1)).forEach(x=>n.children.push(node('scalar',null,val(x),line,indent+1)));return n;}if(s[0]==='{'&&s.at(-1)==='}'){const n=node('map',key,'',line,indent);for(const x of split(s.slice(1,-1))){const p=pair(x);if(!p)return null;const child=inline(p.value,p.key,line,indent+1);if(!child)return null;n.children.push(child);}return n;}if((s[0]==='['&&!s.endsWith(']'))||(s[0]==='{'&&!s.endsWith('}'))||(s[0]==='"'&&!s.endsWith('"'))||(s[0]==="'"&&!s.endsWith("'")))return null;return node('scalar',key,val(s),line,indent);}
function parse(text){
  const lines=text.split(/\r\n?|\n/),rootNode=node('map',null,'',1,-1),stack=[rootNode],errors=[];
  function block(start,indent,key,line,marker){
    const rows=[];let min=null,j=start;
    while(j<lines.length){const row=lines[j];if(!row.trim()){rows.push({text:'',line:j+1});j++;continue;}const ri=row.length-row.trimStart().length;if(ri<=indent)break;min=min===null?ri:Math.min(min,ri);rows.push({text:row,line:j+1});j++;}
    const n=node('scalar',key,'',line,indent);n.blockLines=rows.map(r=>({text:r.text.slice(Math.min(min||indent+1,r.text.length)),line:r.line}));n.value=marker==='>'?n.blockLines.map(r=>r.text.trim()).filter(Boolean).join(' '):n.blockLines.map(r=>r.text).join('\n');return{node:n,next:j};
  }
  for(let i=0;i<lines.length;i++){
    const raw=lines[i];if(!raw.trim())continue;if(/^\s*\t/.test(raw)){errors.push(i+1);continue;}
    const ind=raw.length-raw.trimStart().length,t=stripComment(raw).trim();if(!t||t==='---'||t==='...')continue;
    if(/^(?:%|<<\s*:)|(?:^|\s)[&*][\w-]+/.test(t)){errors.push(i+1);continue;}
    while(stack.length>1&&ind<=stack.at(-1).indent)stack.pop();const par=stack.at(-1);if(par.kind==='scalar'){errors.push(i+1);continue;}
    const li=/^-(?:\s+(.*)|\s*)$/.exec(t);
    if(li){
      if(par.kind===null)par.kind='seq';if(par.kind!=='seq'){errors.push(i+1);continue;}
      const rest=li[1]||'',p=pair(rest);let child;
      if(p){
        child=node('map',null,'',i+1,ind);let f;
        if(/^[|>][+-]?(?:\d+)?$/.test(p.value.trim())){const b=block(i+1,ind+2,p.key,i+1,p.value.trim()[0]);f=b.node;i=b.next-1;}
        else f=p.value===''?node(null,p.key,'',i+1,ind+2):inline(p.value,p.key,i+1,ind+2);
        if(!f){errors.push(i+1);continue;}child.children.push(f);par.children.push(child);stack.push(child);if(f.kind!=='scalar')stack.push(f);
      }else{child=inline(rest,null,i+1,ind);if(!child){errors.push(i+1);continue;}par.children.push(child);if(child.kind!=='scalar')stack.push(child);}
      continue;
    }
    if(par.kind===null)par.kind='map';if(par.kind!=='map'){errors.push(i+1);continue;}
    const p=pair(t);if(!p){errors.push(i+1);continue;}if(par.children.some(c=>c.key===p.key))errors.push(i+1);
    let child;
    if(/^[|>][+-]?(?:\d+)?$/.test(p.value.trim())){const b=block(i+1,ind,p.key,i+1,p.value.trim()[0]);child=b.node;i=b.next-1;}
    else child=p.value===''?node(null,p.key,'',i+1,ind):inline(p.value,p.key,i+1,ind);
    if(!child){errors.push(i+1);continue;}par.children.push(child);if(child.kind!=='scalar')stack.push(child);
  }
  return{root:rootNode,errors};
}
function field(n,k){return n&&n.children.find(x=>x.key===k)||null;}
function walk(n,a=[]){if(n){a.push(n);n.children.forEach(x=>walk(x,a));}return a;}
function values(n,a=[]){if(!n)return a;if(n.kind==='scalar')a.push(n.value);if(n.kind==='map')n.children.forEach(x=>{if(x.key)a.push(x.key);values(x,a)});if(n.kind==='seq')n.children.forEach(x=>values(x,a));return a;}
function add(a,seen,id,line){const k=id+':'+line;if(seen.has(k))return;seen.add(k);if(a.length>=MAX_FINDINGS){a.truncated=true;return;}const r=rules[id];a.push({id,severity:r[0],severityLabel:labels[r[0]],title:r[1],why:r[2],fix:r[3],yamlExample:examples[id]||null,line:Math.max(1,line||1)});}
function each(s,re,fn){re.lastIndex=0;let m;while((m=re.exec(s))!==null){fn(m);if(!m[0].length)re.lastIndex++;}}
const attacker=/\$\{\{\s*(?:github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|sha|label|repo\.default_branch))|comment\.body|review\.body|head_commit\.(?:message|author\.(?:name|email))|workflow_run\.(?:head_commit\.(?:message|author\.(?:name|email))|head_branch|display_title|pull_requests\[[^\]]+\]\.head\.ref)|discussion\.(?:title|body)|discussion_comment\.body|pages\[[^\]]+\]\.page_name)|github\.event\.commits\[[^\]]+\]\.(?:message|author\.(?:name|email)))\s*\}\}/gi;
const token=/(?:gh[pousr]_[A-Za-z0-9_]{4,}|github_pat_[A-Za-z0-9_]{4,}|AKIA[A-Z0-9]{4,}|sk-[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,})/g;
function analyze(input){if(typeof input!=='string')return{findings:[],error:'YAMLテキストを入力してください。',incomplete:false,truncated:false};if(input.length>MAX_LENGTH)return{findings:[],error:'入力は20万文字以内にしてください。',incomplete:false,truncated:false};const p=parse(input);if(p.errors.length||!field(p.root,'on')||!field(p.root,'jobs'))return{findings:[],error:'workflow YAMLとして解釈できません（'+(p.errors[0]||1)+'行目付近）。on/jobsを含む簡易形式へ直してください。',incomplete:false,truncated:false};const rootNode=p.root,all=walk(rootNode),out=[],seen=new Set(),on=field(rootNode,'on'),ts=new Set(values(on).map(x=>String(x).toLowerCase())),target=ts.has('pull_request_target'),workflow=ts.has('workflow_run'),pr=[...ts].some(x=>x==='pull_request'||x==='pull_request_target'||x.startsWith('pull_request.'));if(target)add(out,seen,'targetInfo',on.line);if(workflow)add(out,seen,'workflowInfo',on.line);const j=field(rootNode,'jobs'),jobs=j&&j.kind==='map'?j.children:[],perms=[field(rootNode,'permissions'),...jobs.map(x=>field(x,'permissions'))].filter(Boolean);if(!perms.length)add(out,seen,'noPermissions',1);for(const n of perms){if(String(n.value).toLowerCase()==='write-all'||values(n).includes('write-all'))add(out,seen,'writeAll',n.line);if(n.kind==='map'){const ws=n.children.filter(x=>/write/i.test(String(x.value))).map(x=>String(x.key).toLowerCase());if(ws.length){if(target||workflow)add(out,seen,'targetWrite',n.line);else if(ws.some(x=>['contents','actions','packages','issues','pull-requests','*'].includes(x)))add(out,seen,'broadWrite',n.line);}}}const prHead=/\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}/i,workflowHeadRef=/\$\{\{\s*github\.event\.workflow_run\.(?:head_sha|head_branch)\s*\}\}/i,workflowHeadRepo=/\$\{\{\s*github\.event\.workflow_run\.head_repository(?:\.(?:full_name|name))?\s*\}\}/i;for(const job of jobs){const sn=field(job,'steps'),steps=sn&&sn.kind==='seq'?sn.children:[],runner=field(job,'runs-on');if(pr&&runner&&values(runner).some(x=>String(x).toLowerCase()==='self-hosted'))add(out,seen,'selfHosted',runner.line);for(const step of steps){const uses=field(step,'uses');if(uses){const u=uses.value.trim();if(/^actions\/checkout@/i.test(u)){const checkoutWith=field(step,'with'),ref=field(checkoutWith,'ref'),repository=field(checkoutWith,'repository');if((target&&ref&&prHead.test(ref.value))||(workflow&&((ref&&(workflowHeadRef.test(ref.value)||prHead.test(ref.value)))||(repository&&workflowHeadRepo.test(repository.value)))))add(out,seen,'targetCheckout',(ref&&((target&&prHead.test(ref.value))||(workflow&&(workflowHeadRef.test(ref.value)||prHead.test(ref.value)))))?ref.line:repository.line);const persist=field(field(step,'with'),'persist-credentials');if(!persist||!/^(?:false|no|off)$/i.test(persist.value))add(out,seen,'checkout',uses.line);}const m=/^([^/@]+\/[^/@]+)@(.+)$/.exec(u);if(m&&!u.startsWith('./')&&!u.startsWith('docker://')&&!/^[0-9a-f]{40}$/i.test(m[2])){const main=/^(?:main|master)$/i.test(m[2]),official=/^(?:actions|github)\//i.test(m[1]);add(out,seen,main?'unpinnedMain':'unpinnedAction',uses.line);if(official&&!main){const f=out.find(x=>x.id==='unpinnedAction'&&x.line===uses.line);if(f){f.severity='info';f.severityLabel=labels.info;f.title='公式actionがSHA固定されていない';}}}}const run=field(step,'run');if(run){const source=run.blockLines.length?run.blockLines:[{text:run.value||'',line:run.line}];for(const row of source){each(row.text,attacker,()=>add(out,seen,'injection',row.line));each(row.text,/\b(?:echo|printf)\b[^\n]*\$\{\{\s*secrets\.[^}]+\}\}/gi,()=>add(out,seen,'echoSecret',row.line));each(row.text,/\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b/gi,()=>add(out,seen,'curlPipe',row.line));}}}}for(const n of all){if(n.key&&n.key.toLowerCase()==='actions_allow_unsecure_commands'&&/^(?:true|yes|on|1)$/i.test(n.value||''))add(out,seen,'insecure',n.line);if(n.kind==='scalar')each(n.value,token,()=>add(out,seen,'token',n.line));for(const r of n.blockLines||[])each(r.text,token,()=>add(out,seen,'token',r.line));}out.sort((a,b)=>a.line-b.line||a.id.localeCompare(b.id));return{findings:out,error:null,incomplete:false,truncated:out.truncated===true};}
const api={analyze,safeSample,unsafeSample,examples,MAX_LENGTH,MAX_FINDINGS};if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.GhaCheck=api;
}(typeof globalThis!=='undefined'?globalThis:this));

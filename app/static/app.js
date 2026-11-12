(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const fmt = n => new Intl.NumberFormat('en-US').format(n ?? 0);
  const fmtBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(2)} MB`;
  let currentMode = 'file';
  let currentTab = 'overview';
  let selectedFile = null;
  let report = null;
  const titles = {overview:['Answer desk','Evidence-backed candidates and an automatic investigation plan'],network:['Network traffic','DNS, TLS, HTTP and recovered TCP conversations'],decoders:['Decoder lab','Transform encoded tokens without leaving the workspace'],artifacts:['Recovered files','Extracted objects and known-password extraction'],assistant:['Local analyst','Use your own Ollama model for additional reasoning']};

  function status(text, error = false) {
    const bar = $('run-status');
    bar.classList.toggle('error', error);
    bar.lastChild.textContent = ' ' + text;
  }
  function switchMode(mode) {
    currentMode = mode;
    document.querySelectorAll('.mode').forEach(x => {
      const active = x.dataset.mode === mode;
      x.classList.toggle('active', active);
      x.setAttribute('aria-selected', String(active));
    });
    $('upload-zone').classList.toggle('hidden', mode !== 'file');
    $('text-zone').classList.toggle('hidden', mode !== 'text');
    $('tls-zone').classList.toggle('hidden', mode !== 'file');
  }
  function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.nav-link').forEach(x => x.classList.toggle('active', x.dataset.tab === tab));
    document.querySelectorAll('.view').forEach(x => x.classList.add('hidden'));
    if (report) $('view-' + tab).classList.remove('hidden');
    $('view-title').textContent = titles[tab][0];
    $('view-subtitle').textContent = titles[tab][1];
    if (tab === 'overview') $('result-content').classList.toggle('hidden', !report);
    $('results-panel').scrollIntoView({behavior:'smooth', block:'nearest'});
  }
  function chooseFile(file) {
    if (!file) return;
    selectedFile = file;
    $('drop-title').textContent = file.name;
    $('drop-description').textContent = `${fmtBytes(file.size)} · Ready to analyze`;
    status('File selected. Start analysis to inspect evidence.');
  }
  async function api(path, options) {
    const res = await fetch(path, options);
    let body = null;
    try { body = await res.json(); } catch {}
    if (!res.ok) throw new Error(typeof body?.detail === 'string' ? body.detail : `Request failed (${res.status}).`);
    return body;
  }
  function empty(message) { return `<div class="faint-empty">${escape(message)}</div>`; }
  function table(headers, rows) {
    if (!rows.length) return empty('No matching records recovered from this evidence.');
    return `<table class="data-table"><thead><tr>${headers.map(h => `<th>${escape(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(v => `<td>${v}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  }
  function renderOverview() {
    const inv = report.investigation || {};
    const summary = report.flags.length ? `Found ${report.flags.length} possible flag${report.flags.length===1?'':'s'}. The highest-ranked candidate is <strong>${escape(report.flags[0].value)}</strong>.` : 'No flag-format match recovered in this pass. Follow the targeted investigation plan below.';
    $('investigation-summary').innerHTML = `<span class="section-kicker">AUTOMATED VERDICT / ${report.flags.length ? 'CANDIDATE FOUND' : 'INVESTIGATION REQUIRED'}</span><p>${summary}</p>${inv.question ? `<small>QUESTION: ${escape(inv.question.slice(0,260))}</small>` : '<small>TIP: Adding the challenge question helps prioritize the right evidence.</small>'}`;
    $('flag-count').textContent = report.flags.length;
    $('flag-list').innerHTML = report.flags.length ? report.flags.map((f,i) => `<div class="finding"><div class="finding-main"><span class="confidence">RANK ${i+1} · EVIDENCE SCORE ${f.score ?? '—'}/99 · ${escape(f.method.toUpperCase())}</span><div class="flag-code">${escape(f.value)}</div><div class="finding-source">${escape(f.source)}${f.sources?.length>1 ? ` · ${f.sources.length} sources` : ''}${f.chain.length ? ` · ${escape(f.chain.join(' → '))}` : ''}</div>${f.reasons?.length ? `<p class="flag-reasons">${escape(f.reasons.join(' · '))}</p>` : ''}</div><button class="copy" data-copy-index="${i}">COPY ↗</button></div>`).join('') : `<div class="faint-empty">No matching flag tokens recovered. Check the prefix, inspect DNS reconstructions, and review decode trails. This is not proof that no flag exists.</div>`;
    $('plan-list').innerHTML = (inv.steps || []).map((s,i)=>`<div class="plan-step"><span class="plan-index">${String(i+1).padStart(2,'0')}</span><div><b>${escape(s.title)}</b><p>${escape(s.detail)}</p></div><span class="priority ${escape(s.priority)}">${escape(s.priority)}</span></div>`).join('') || empty('No automatic follow-up plan available.');
    $('evidence-list').innerHTML = (report.evidence.length ? report.evidence : ['Source file signature and metadata inspected.']).map(x=>`<div class="note">${escape(x)}</div>`).join('');
    $('hint-list').innerHTML = (report.hints.length ? report.hints : ['Inspect streams and decoded traces for more leads.']).map(x=>`<div class="note">${escape(x)}</div>`).join('');
    const data = report.metadata;
    const entries = [['FILENAME',data.filename],['DETECTED TYPE',data.kind],['SOURCE SIZE',fmtBytes(data.size)],['SHA-256',data.sha256],['SHA-1',data.sha1],['MD5',data.md5]];
    $('identity').innerHTML = entries.map(([a,b]) => `<div class="identity-row"><label>${a}</label><code>${escape(b)}</code></div>`).join('');
  }
  function renderNetwork() {
    const c = report.pcap;
    if (!c) { $('network-body').innerHTML = empty('This file is not a PCAP/PCAPNG capture. Try a packet capture to examine protocol conversations.'); return; }
    const max = Math.max(1, ...c.protocols.map(x=>x.count));
    let out = `<div class="section-row"><h3>Protocol distribution</h3><span class="fine-text">${fmt(c.packets)} parsed packets</span></div>`;
    out += c.protocols.map(p=>`<div class="bar"><span>${escape(p.name)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2,p.count/max*100)}%"></div></div><b>${fmt(p.count)}</b></div>`).join('');
    out += '<div class="section-row"><h3>Top conversations</h3></div>' + table(['PATH','PACKETS'], c.conversations.slice(0,18).map(x=>[escape(x.path),fmt(x.packets)]));
    out += '<div class="section-row"><h3>DNS records</h3></div>' + table(['TYPE','HOSTNAME / VALUE'], c.dns.slice(0,60).map(x=>[escape(x.kind === 'TXT' ? 'TXT' : 'QTYPE '+x.type),escape(x.name+(x.value?' → '+x.value:''))]));
    out += '<div class="section-row"><h3>Reconstructed DNS payloads</h3><span class="fine-text">CONCATENATION IS A HYPOTHESIS</span></div>' + (c.dns_reassembled?.length ? c.dns_reassembled.map(x=>`<div class="decode-item"><b>${escape(x.source)} / ${fmtBytes(x.length)}</b><code>${escape(x.preview)}</code></div>`).join('') : empty('No multi-query domain/TXT reconstruction heuristics triggered.'));
    out += '<div class="section-row"><h3>ICMP / IP covert hypotheses</h3><span class="fine-text">CANDIDATES, NOT PROOF</span></div>' + (c.covert?.length ? c.covert.map(x=>`<div class="decode-item"><b>${escape(x.source)} · ${x.frames} packets</b><code>${escape(x.preview)}</code></div>`).join('') : empty('No multi-packet ICMP or printable IPv4 ID patterns detected.'));
    out += '<div class="section-row"><h3>Zeek cross-check logs</h3></div>' + (c.zeek?.length ? table(['LOG','RECORDS'],c.zeek.map(x=>[escape(x.log+'.log'),fmt(x.records)])) : empty('Optional Zeek engine not available or no logs generated.'));
    out += '<div class="section-row"><h3>TLS handshake clues</h3></div>' + (c.tls?.length ? c.tls.map(x=>`<span class="file-pill">SNI · ${escape(x.sni)}</span>`).join('') : empty('No cleartext TLS SNI recovered. This does not imply that HTTPS was decrypted.'));
    out += '<div class="section-row"><h3>HTTP requests and responses</h3></div>' + table(['REQUEST / RESPONSE','CONTENT TYPE','BODY'], c.http.slice(0,35).map(x=>[escape(x.line),escape(x.content_type||'—'),fmtBytes(x.body_size)]));
    out += '<div class="section-row"><h3>Recovered TCP streams</h3><span class="fine-text">DIRECTIONAL / GAPS ANNOTATED</span></div><input id="stream-filter" class="filter-input" placeholder="Filter by IP, port, contents, flag fragment…" aria-label="Filter network streams">';
    out += c.streams.length ? `<div id="stream-list">`+c.streams.slice(0,45).map(s=>`<div class="stream-card"><header><strong>${escape(s.path)}</strong>${s.artifact_id ? `<a class="copy" href="/api/artifact/${report.job_id}/${escape(s.artifact_id)}">↓ Save</a>` : ''}</header><small>${fmtBytes(s.size)} · ${s.fragments} fragment(s) · ${s.gaps} gap(s)</small><pre>${escape(s.preview || '(No readable text)')}</pre></div>`).join('')+'</div>' : empty('No TCP payload streams recovered.');
    out += '<div class="section-row"><h3>Packet ledger</h3><span class="fine-text">FIRST 250 PARSED IP PACKETS</span></div>' + table(['#','FROM','TO','PROTOCOL','LENGTH'],(c.packet_rows||[]).slice(0,250).map(r=>[fmt(r.number),escape(r.src)+(r.sport?':'+r.sport:''),escape(r.dst)+(r.dport?':'+r.dport:''),escape(r.protocol),fmtBytes(r.size)]));
    $('network-body').innerHTML = out;
    $('stream-filter')?.addEventListener('input', e=>{
      const key=e.target.value.toLowerCase();
      document.querySelectorAll('#stream-list .stream-card').forEach(node=>node.classList.toggle('hidden',!node.textContent.toLowerCase().includes(key)));
    });
  }
  function renderDecoders() {
    let out = '<div class="section-row"><h3>Decoder traces</h3><span class="fine-text">Auto-discovered transformations</span></div>';
    out += report.decodes.length ? report.decodes.slice(0,50).map(d=>`<div class="decode-item"><b>${escape(d.method)} · ${escape(d.source)}</b><code>${escape(d.preview)}</code></div>`).join('') : empty('No high-legibility transformation traces recovered. Direct raw flag matches may already appear in Overview.');
    out += '<div class="section-row"><h3>Printable strings</h3><span class="fine-text">ASCII / UTF-16LE hints</span></div>';
    out += report.metadata.strings?.length ? report.metadata.strings.slice(0,60).map(s=>`<div class="decode-item"><code>${escape(s)}</code></div>`).join('') : empty('No long printable strings found in the root input.');
    $('decoding-body').innerHTML = out;
  }
  function renderArtifacts() {
    let out = table(['EXTRACTED ARTIFACT','SOURCE','SIZE','ACTION'], report.artifacts.map(a=>[
      escape(a.name),escape(a.source),fmtBytes(a.size),`<a href="/api/artifact/${report.job_id}/${escape(a.id)}" download>↓ Download</a>`]));
    out += '<h3 class="minor-head">Detected file inventory</h3>';
    out += report.files.map(f=>`<span class="file-pill" title="${escape(f.source)}">${escape(f.name)} · ${escape(f.kind)}</span>`).join('');
    $('artifact-body').innerHTML = out;
  }
  function render(result) {
    report = result;
    $('empty-results').classList.add('hidden');
    $('result-content').classList.remove('hidden');
    $('job-badge').textContent = 'ANALYSIS COMPLETE';
    $('metric-flags').textContent = fmt(result.stats.flags);
    $('metric-packets').textContent = fmt(result.stats.packets);
    $('metric-files').textContent = fmt(result.stats.files);
    $('metric-artifacts').textContent = fmt(result.stats.artifacts);
    $('export-button').disabled = false;
    $('bundle-button').disabled = false;
    $('writeup-button').disabled = false;
    renderOverview(); renderNetwork(); renderDecoders(); renderArtifacts();
    switchTab(currentTab);
  }
  async function analyze() {
    if (currentMode === 'file' && !selectedFile) { status('Choose a file, or switch to Paste text.', true); return; }
    if (currentMode === 'text' && !$('paste-text').value.trim()) { status('Paste challenge text to analyze.', true); return; }
    const data = new FormData();
    if (currentMode === 'file') {
      data.append('file',selectedFile);
      if ($('tlskey-input').files[0]) data.append('tls_keylog',$('tlskey-input').files[0]);
    }
    else data.append('text',$('paste-text').value);
    data.append('prefix',$('flag-prefix').value.trim());
    data.append('question',$('challenge-question').value.trim());
    $('analyze-button').disabled = true;
    $('analyze-button').textContent = 'ANALYZING…';
    status('Parsing file structures, testing encodings and extracting evidence…');
    try {
      const started = performance.now();
      const result = await api('/api/analyze',{method:'POST',body:data});
      render(result);
      status(`Analysis complete in ${((performance.now()-started)/1000).toFixed(1)}s. ${result.stats.flags} candidate flag(s) found.`);
    } catch (err) { status(err.message,true); }
    finally { $('analyze-button').disabled=false; $('analyze-button').innerHTML='RUN AUTO-INVESTIGATION <span>↗</span>'; }
  }
  async function unlock(which) {
    if (!report) return;
    const password = $('unlock-pass').value;
    if (which === 'zip' && !password) { $('unlock-result').textContent = 'Enter a known ZIP password first.'; return; }
    $('unlock-result').textContent = 'Attempting extraction locally…';
    try {
      let result;
      if (which === 'zip') result=await api('/api/unlock-zip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:report.job_id,password})});
      else result=await api('/api/steghide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:report.job_id,passphrase:password})});
      const fresh = await api(`/api/report/${report.job_id}`);
      render(fresh);
      switchTab('artifacts');
      $('unlock-result').textContent = `Extraction succeeded. ${result.flags.length} candidate(s) recovered; inspect files and flags.`;
    } catch(err) { $('unlock-result').textContent=err.message; }
    finally { $('unlock-pass').value = ''; }
  }
  async function askAI() {
    if (!report) return;
    $('ask-ai').disabled=true;
    $('ai-answer').textContent='Consulting local Ollama model…';
    try {
      const result = await api('/api/ai',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({job_id:report.job_id,question:$('ai-question').value,model:$('ai-model').value.trim()})});
      $('ai-answer').textContent=result.answer || '(No response from model)';
    } catch (err) { $('ai-answer').textContent=err.message; }
    finally { $('ask-ai').disabled=false; }
  }
  async function getHealth() {
    try {
      const health = await api('/api/health');
      $('api-status').textContent = 'Ready · version ' + health.version;
      $('tool-list').innerHTML = health.tools.map(x=>`<div class="tool-item"><span class="tool-name">${escape(x.name)}</span><span class="tool-state ${x.available?'yes':'no'}">${x.available?'READY':'OPTIONAL'}</span></div>`).join('');
    } catch {
      $('api-status').textContent = 'Unavailable';
      $('tool-list').textContent='Engine is offline. Restart run.sh.';
    }
  }
  document.querySelectorAll('.mode').forEach(x=>x.addEventListener('click',()=>switchMode(x.dataset.mode)));
  document.querySelectorAll('.nav-link').forEach(x=>x.addEventListener('click',()=>switchTab(x.dataset.tab)));
  const zone = $('upload-zone');
  zone.addEventListener('click',()=> $('file-input').click());
  zone.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file-input').click();}});
  $('file-input').addEventListener('change',e=>chooseFile(e.target.files[0]));
  ['dragover','dragenter'].forEach(x=>zone.addEventListener(x,e=>{e.preventDefault();zone.classList.add('dragging');}));
  ['dragleave','dragend'].forEach(x=>zone.addEventListener(x,e=>{e.preventDefault();zone.classList.remove('dragging');}));
  zone.addEventListener('drop',e=>{e.preventDefault();zone.classList.remove('dragging');chooseFile(e.dataTransfer.files[0]);});
  $('analyze-button').addEventListener('click',analyze);
  $('export-button').addEventListener('click',()=>{if(report) location.href='/api/report/'+report.job_id;});
  $('writeup-button').addEventListener('click',()=>{if(report) location.href='/api/writeup/'+report.job_id;});
  $('bundle-button').addEventListener('click',()=>{if(report) location.href='/api/bundle/'+report.job_id;});
  $('zip-unlock').addEventListener('click',()=>unlock('zip'));
  $('stego-unlock').addEventListener('click',()=>unlock('stego'));
  $('ask-ai').addEventListener('click',askAI);
  $('flag-list').addEventListener('click',async e=>{
    const button=e.target.closest('[data-copy-index]');
    if (!button||!report) return;
    try {await navigator.clipboard.writeText(report.flags[Number(button.dataset.copyIndex)].value);button.textContent='Copied';setTimeout(()=>button.textContent='Copy',1200);} catch {button.textContent='Unable to copy';}
  });
  $('sample-button').addEventListener('click',async()=>{
    try {
      status('Loading the synthetic sample capture…');
      const response=await fetch('/api/sample/pcap');
      if(!response.ok) throw new Error('Bundled PCAP sample could not be found.');
      const blob=await response.blob();
      chooseFile(new File([blob],'demo-capture.pcap',{type:'application/octet-stream'}));
      switchMode('file');
      $('challenge-question').value='Find the flag hidden in this example packet capture.';
      status('Demo PCAP loaded. Click Run auto-investigation.');
    } catch(err) { status(err.message,true); }
  });
  $('decode-button').addEventListener('click',async()=>{
    const value=$('decode-input').value.trim();
    if(!value){$('decode-status').textContent='Paste a clue to decode.';return;}
    $('decode-button').disabled=true;$('decode-status').textContent='Exploring transformations…';
    try {
      const r=await api('/api/decode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:value,prefix:$('flag-prefix').value.trim()})});
      $('decode-output').innerHTML=r.flags.length ? r.flags.map(f=>`<div class="decode-item"><b>POSSIBLE FLAG</b><code>${escape(f)}</code></div>`).join('') : empty('No flag-format match found in explored decoding chains.');
      $('decode-output').innerHTML+=r.traces.slice(0,18).map(t=>`<div class="decode-item"><b>${escape(t.method)}</b><code>${escape(t.preview)}</code></div>`).join('');
      $('decode-status').textContent=`${r.flags.length} candidate(s), ${r.traces.length} transformation(s).`;
    } catch(err){$('decode-status').textContent=err.message;}
    finally{$('decode-button').disabled=false;}
  });
  getHealth();
})();

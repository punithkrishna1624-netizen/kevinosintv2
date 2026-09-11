const typeEl = document.getElementById("type");
const targetEl = document.getElementById("target");
const resultsEl = document.getElementById("results");
const messageEl = document.getElementById("message");
const navButtons = document.querySelectorAll(".nav[data-type]");

navButtons.forEach(btn => {
  btn.addEventListener("click", () => {
    navButtons.forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    typeEl.value = btn.dataset.type;
    targetEl.focus();
  });
});

async function investigate(){
  const target = targetEl.value.trim();
  if(!target){
    messageEl.textContent = "Enter a target first.";
    return;
  }

  messageEl.textContent = "Running public-source checks...";
  resultsEl.innerHTML = `<div class="empty"><div class="crosshair">◌</div><h3>Investigating</h3><p>Collecting authorized public intelligence…</p></div>`;

  try{
    const response = await fetch("/api/investigate", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({target, type:typeEl.value})
    });
    const data = await response.json();
    if(!response.ok) throw new Error(data.error || "Investigation failed");

    renderResults(data);
    messageEl.textContent = "Investigation complete.";
  }catch(err){
    messageEl.textContent = err.message;
    resultsEl.innerHTML = `<div class="empty"><h3>Request failed</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

function renderFindingsGrid(findings){
  const rows = (findings || []).map(f => `
    <div class="finding">
      <label>${escapeHtml(f.label)}${f.hint ? `<span class="hint">${escapeHtml(f.hint)}</span>` : ""}</label>
      <value class="${f.status || "info"}">${f.url ? `<a href="${escapeAttr(f.url)}" target="_blank" rel="noopener">${escapeHtml(f.value)}</a>` : escapeHtml(f.value)}</value>
    </div>
  `).join("");
  return `<div class="findings">${rows}</div>`;
}

function renderSection(section){
  const hasChips = Array.isArray(section.items);
  let body = "";

  if(section.error){
    body = `<div class="section-error">⚠ ${escapeHtml(section.error)}</div>`;
  } else if(hasChips){
    if(section.items.length){
      body = `<div class="chip-list">${section.items.map(i => `<span class="chip">${escapeHtml(i)}</span>`).join("")}</div>`;
      if(section.truncated){
        body += `<div class="chip-empty">Showing first ${section.items.length} of ${section.count} found.</div>`;
      }
    } else {
      body = `<div class="chip-empty">None found.</div>`;
    }
  } else if(section.findings && section.findings.length){
    body = renderFindingsGrid(section.findings);
  } else {
    body = `<div class="chip-empty">No data returned.</div>`;
  }

  const notice = section.notice ? `<div class="section-notice">⚠ ${escapeHtml(section.notice)}</div>` : "";

  return `
    <div class="section-block">
      <div class="section-head">
        <h4>${escapeHtml(section.title || "Section")}</h4>
        <span class="section-source">${escapeHtml(section.source || "")}</span>
      </div>
      ${body}
      ${notice}
    </div>
  `;
}

function renderResults(data){
  const header = `
    <div class="result-head" style="padding:0 0 18px">
      <h3>${escapeHtml(data.summary || "Investigation")}</h3>
      <code>${escapeHtml(data.type || "OSINT").toUpperCase()}</code>
    </div>`;

  let body;
  if(Array.isArray(data.sections)){
    body = data.sections.map(renderSection).join("");
  } else {
    body = `
      <div class="result-card">
        <div class="findings">${renderFindingsGrid(data.findings)}</div>
      </div>`;
  }

  const topNotice = data.notice ? `<div class="section-notice" style="border-radius:0 0 14px 14px;margin-top:-4px">⚠ ${escapeHtml(data.notice)}</div>` : "";

  resultsEl.innerHTML = `${header}${body}${topNotice}`;
}

function escapeHtml(value){
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}
function escapeAttr(value){ return escapeHtml(value); }

document.getElementById("investigate").addEventListener("click", investigate);
targetEl.addEventListener("keydown", e => {
  if(e.key === "Enter") investigate();
});

/* ---- Breach check modal ---- */
const breachModal = document.getElementById("breach-modal");
const breachNav = document.getElementById("nav-breach");
const breachCancel = document.getElementById("breach-cancel");
const breachRun = document.getElementById("breach-run");
const breachResult = document.getElementById("breach-result");

if(breachNav){
  breachNav.addEventListener("click", () => {
    breachModal.classList.remove("hidden");
    breachResult.innerHTML = "";
  });
}
if(breachCancel){
  breachCancel.addEventListener("click", () => breachModal.classList.add("hidden"));
}
if(breachRun){
  breachRun.addEventListener("click", async () => {
    const email = document.getElementById("breach-email").value.trim();
    const authorized = document.getElementById("breach-auth").checked;
    if(!email){ breachResult.innerHTML = `<div class="section-error">Enter an email.</div>`; return; }
    if(!authorized){ breachResult.innerHTML = `<div class="section-error">Confirm authorization first.</div>`; return; }

    breachResult.innerHTML = `<div class="chip-empty">Checking…</div>`;
    try{
      const resp = await fetch("/api/breach-check", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({email, authorized})
      });
      const data = await resp.json();
      if(!resp.ok) throw new Error(data.error || "Check failed");
      breachResult.innerHTML = renderFindingsGrid(data.findings) + (data.notice ? `<div class="section-notice">⚠ ${escapeHtml(data.notice)}</div>` : "");
    }catch(err){
      breachResult.innerHTML = `<div class="section-error">${escapeHtml(err.message)}</div>`;
    }
  });
}

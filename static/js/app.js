(function () {
  const form = document.getElementById("check-form");
  const resultPanel = document.getElementById("result-panel");
  const statusPill = document.getElementById("status-pill");
  const logEl = document.getElementById("result-log");
  const sourcesEl = document.getElementById("result-sources");
  const strengthEl = document.getElementById("strength-block");
  const previewEl = document.getElementById("result-preview");
  const submitBtn = document.getElementById("submit-btn");
  const apiDot = document.getElementById("api-status-dot");

  function gatherOptions() {
    const opts = {};
    document.querySelectorAll("[data-option]").forEach((el) => {
      opts[el.dataset.option] = el.type === "checkbox" ? el.checked : el.value;
    });
    return opts;
  }

  function setLoading(on) {
    submitBtn.disabled = on;
    submitBtn.innerHTML = on
      ? '<span class="spinner"></span> Controleren…'
      : "Controleren";
  }

  function renderStrength(strength) {
    if (!strength) {
      strengthEl.classList.add("hidden");
      return;
    }
    strengthEl.classList.remove("hidden");
    const pct = Math.min(100, ((strength.score + 1) / 5) * 100);
    strengthEl.innerHTML = `
      <p><strong>Sterkte:</strong> ${escapeHtml(strength.label)}</p>
      <div class="strength-bar"><div style="width:${pct}%"></div></div>
      <p class="hint">Entropy: ${strength.entropy} · Lengte: ${strength.length}</p>
      ${
        strength.feedback?.length
          ? "<ul>" + strength.feedback.map((f) => `<li>${escapeHtml(f)}</li>`).join("") + "</ul>"
          : ""
      }
    `;
  }

  function renderSources(sources) {
    if (!sources?.length) {
      sourcesEl.innerHTML = "";
      return;
    }
    sourcesEl.innerHTML = sources
      .map((s) => `<span class="source-tag">${escapeHtml(s.type || "?")}</span>`)
      .join("");
  }

  function renderPreview(preview) {
    if (!preview) {
      previewEl.innerHTML = "";
      return;
    }
    previewEl.innerHTML = `<div class="preview"><h3>Context</h3>${preview}</div>`;
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function showResult(data) {
    resultPanel.classList.add("visible");
    const found = data.found;
    statusPill.textContent = data.status || (found ? "GEVONDEN" : "NIET GEVONDEN");
    statusPill.className = "status-pill " + (found ? "found" : "safe");
    logEl.textContent = (data.messages || []).join("\n");
    renderSources(data.sources);
    renderStrength(data.strength);
    renderPreview(data.preview_html || "");
    resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function pingApi() {
    try {
      const r = await fetch("/api/status");
      const j = await r.json();
      if (apiDot) {
        apiDot.textContent = j.ok ? "API live" : "API offline";
        apiDot.className = "badge " + (j.ok ? "" : "offline");
      }
    } catch {
      if (apiDot) apiDot.textContent = "API offline";
    }
  }

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const password = document.getElementById("password").value.trim();
      if (!password) return;

      setLoading(true);
      try {
        const res = await fetch("/api/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password, ...gatherOptions() }),
        });
        const data = await res.json();
        if (!res.ok) {
          showResult({
            found: false,
            status: "FOUT",
            messages: [data.error || "Request failed"],
          });
        } else {
          showResult(data);
        }
      } catch (err) {
        showResult({
          found: false,
          status: "FOUT",
          messages: ["Netwerkfout: " + err.message],
        });
      } finally {
        setLoading(false);
      }
    });
  }

  document.querySelectorAll(".nav-tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-tabs button").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.panel).classList.add("active");
      if (btn.dataset.panel === "status-panel") loadStatus();
    });
  });

  async function loadStatus() {
    const el = document.getElementById("status-content");
    if (!el) return;
    try {
      const r = await fetch("/api/status");
      const j = await r.json();
      el.innerHTML = `
        <div class="stats-grid">
          <div class="stat"><strong>${j.version}</strong><span>Versie</span></div>
          <div class="stat"><strong>${j.lists_count}</strong><span>Lijsten</span></div>
          <div class="stat"><strong>${j.hashes_count}</strong><span>Hash-bestanden</span></div>
          <div class="stat"><strong>${j.cache_mb} MB</strong><span>Cache</span></div>
          <div class="stat"><strong>${j.ripgrep ? "Ja" : "Nee"}</strong><span>ripgrep</span></div>
        </div>
        <pre class="log" style="margin-top:1rem">${escapeHtml(JSON.stringify(j.recent_checks || [], null, 2))}</pre>
      `;
    } catch {
      el.textContent = "Kon status niet laden.";
    }
  }

  const pwdToggle = document.getElementById("toggle-pwd");
  if (pwdToggle) {
    pwdToggle.addEventListener("click", () => {
      const inp = document.getElementById("password");
      inp.type = inp.type === "password" ? "text" : "password";
      pwdToggle.textContent = inp.type === "password" ? "Toon" : "Verberg";
    });
  }

  pingApi();
  setInterval(pingApi, 30000);
})();

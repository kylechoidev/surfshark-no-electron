"use strict";

(function () {
  let currentStatus = null;
  let allClusters = [];
  let pendingChallengeId = null;

  function $(id) {
    return document.getElementById(id);
  }

  function formatBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + " MiB";
    return (n / (1024 * 1024 * 1024)).toFixed(2) + " GiB";
  }

  async function apiCall(method, path, body) {
    const opts = {
      method: method,
      headers: {
        "Accept": "application/json",
        "X-SSUL": "1"
      }
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const msg = (data.error && data.error.message) ? data.error.message : ("HTTP " + resp.status);
      throw new Error(msg);
    }
    return data;
  }

  function showError(msg) {
    const el = $("error-banner");
    if (!msg) {
      el.hidden = true;
      el.textContent = "";
      return;
    }
    el.textContent = msg;
    el.hidden = false;
  }

  function renderStatus(st) {
    currentStatus = st;
    $("version-label").textContent = "v" + (st.version || "2.0.0") + " · Zero-Electron Native WireGuard";
    $("driver-label").textContent = "DRIVER: " + String(st.driver || "auto").toUpperCase();

    const connState = st.connection_state || "DISCONNECTED";
    $("conn-state").textContent = connState;

    const telem = st.telemetry || {};
    const verdict = telem.verdict || "EXPOSED";
    const vBadge = $("verdict-badge");
    vBadge.textContent = verdict;
    vBadge.className = "badge " + (
      verdict === "PROTECTED" ? "badge-ok" :
      (verdict === "HANDSHAKE_PENDING" || verdict === "UNVERIFIED") ? "badge-warn" : "badge-danger"
    );
    $("verdict-reason").textContent = telem.reason || "";

    const auth = st.auth || {};
    const aBadge = $("auth-badge");
    const aState = auth.state || "logged_out";
    aBadge.textContent = auth.account_hint ? (aState + " · " + auth.account_hint) : aState;
    aBadge.className = "badge " + (aState === "authenticated" ? "badge-ok" : (aState === "degraded" ? "badge-warn" : "badge-danger"));
    $("account-status-line").textContent = "Status: " + aState.toUpperCase() + (auth.account_hint ? (" (" + auth.account_hint + ")") : "");

    const btnToggle = $("btn-connect-toggle");
    const btnRec = $("btn-reconnect");
    if (connState === "CONNECTED" || connState === "CONNECTING" || connState === "SWITCHING") {
      btnToggle.textContent = "Disconnect";
      btnToggle.className = "btn btn-danger";
      btnRec.hidden = false;
    } else {
      btnToggle.textContent = "Connect Fastest";
      btnToggle.className = "btn btn-primary";
      btnRec.hidden = true;
    }

    const active = st.active_cluster;
    if (active) {
      $("metric-server").textContent = (active.flag ? active.flag + " " : "") + active.label;
      $("metric-hostname").textContent = active.hostname;
      $("metric-load").textContent = "Server Load: " + (active.load !== null ? active.load + "%" : "—") +
        (active.latency_ms !== null ? (" · " + active.latency_ms + " ms") : "");
    } else {
      $("metric-server").textContent = "—";
      $("metric-hostname").textContent = "Not connected";
      $("metric-load").textContent = "Server Load: —";
    }

    const eg = telem.egress;
    if (eg && eg.ip) {
      $("metric-ip").textContent = eg.ip;
      const locParts = [eg.city, eg.country_code].filter(Boolean).join(", ");
      $("metric-isp").textContent = [locParts, eg.isp].filter(Boolean).join(" · ") || eg.provider;
    } else {
      $("metric-ip").textContent = "—";
      $("metric-isp").textContent = telem.baseline_ip ? ("Baseline: " + telem.baseline_ip) : "Unverified";
    }

    if (telem.handshake_age_s !== null && telem.handshake_age_s !== undefined) {
      $("metric-handshake").textContent = Math.round(telem.handshake_age_s) + "s ago";
    } else {
      $("metric-handshake").textContent = telem.tunnel_up ? "Active" : "—";
    }
    $("metric-iface").textContent = "Interface: " + (telem.iface || "—");
    $("metric-traffic").textContent = formatBytes(telem.rx_bytes) + " ↓ / " + formatBytes(telem.tx_bytes) + " ↑";

    const reqRec = st.requires_reconnect || [];
    $("reconnect-banner").hidden = reqRec.length === 0;

    if (st.last_error && st.last_error.message) {
      showError(st.last_error.message);
    }
  }

  function renderServersTable() {
    const tbody = $("servers-tbody");
    const q = ($("server-search").value || "").trim().toLowerCase();
    const cc = $("server-country").value;
    const kind = $("server-kind").value;

    const filtered = allClusters.filter((c) => {
      if (cc && c.country_code !== cc) return false;
      if (kind && c.kind !== kind) return false;
      if (q) {
        const hay = (c.location + " " + c.country + " " + c.country_code + " " + c.hostname).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    }).slice(0, 120);

    tbody.textContent = "";
    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "empty-cell";
      td.textContent = "No matching WireGuard servers.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const c of filtered) {
      const tr = document.createElement("tr");

      const tdLoc = document.createElement("td");
      tdLoc.textContent = (c.flag ? c.flag + " " : "") + c.location + ", " + c.country;
      tr.appendChild(tdLoc);

      const tdHost = document.createElement("td");
      tdHost.className = "mono";
      tdHost.textContent = c.hostname;
      tr.appendChild(tdHost);

      const tdKind = document.createElement("td");
      tdKind.textContent = c.kind + (c.virtual ? " (virtual)" : "");
      tr.appendChild(tdKind);

      const tdLoad = document.createElement("td");
      tdLoad.textContent = c.load !== null ? (c.load + "%") : "—";
      tr.appendChild(tdLoad);

      const tdRtt = document.createElement("td");
      tdRtt.className = "mono";
      tdRtt.textContent = c.latency_ms !== null ? (c.latency_ms + " ms") : "—";
      tr.appendChild(tdRtt);

      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-secondary btn-small";
      btn.textContent = "Connect";
      btn.addEventListener("click", async () => {
        showError("");
        btn.disabled = true;
        try {
          const st = await apiCall("POST", "/api/v1/connect", { target: c.hostname });
          renderStatus(st);
        } catch (err) {
          showError(err.message);
        } finally {
          btn.disabled = false;
        }
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    }
  }

  async function loadServers(refresh) {
    try {
      const data = await apiCall("GET", "/api/v1/servers" + (refresh ? "?refresh=1" : ""));
      allClusters = data.clusters || [];
      const sel = $("server-country");
      const curVal = sel.value;
      sel.textContent = "";
      const optAll = document.createElement("option");
      optAll.value = "";
      optAll.textContent = "All Countries (" + (data.countries ? data.countries.length : 0) + ")";
      sel.appendChild(optAll);
      for (const cnt of (data.countries || [])) {
        const opt = document.createElement("option");
        opt.value = cnt.country_code;
        opt.textContent = (cnt.flag ? cnt.flag + " " : "") + cnt.country + " (" + cnt.cluster_count + ")";
        sel.appendChild(opt);
      }
      sel.value = curVal;
      renderServersTable();
    } catch (err) {
      showError(err.message);
    }
  }

  async function loadKeys() {
    try {
      const k = await apiCall("GET", "/api/v1/keys");
      $("wg-pubkey").textContent = k.public_key || "Not generated yet";
      $("wg-registered").textContent = k.registered_at || "—";
      $("wg-expires").textContent = k.expires_at || "—";
      $("wg-validated").textContent = k.last_validated_at || "—";
    } catch (_e) {}
  }

  async function loadSettings() {
    try {
      const res = await apiCall("GET", "/api/v1/settings");
      const s = res.settings || {};
      $("set-cleanweb").checked = Boolean(s.cleanweb);
      $("set-ipv6-guard").checked = Boolean(s.ipv6_guard);
      $("set-autoconnect").checked = Boolean(s.autoconnect);
      $("set-watchdog").checked = Boolean(s.watchdog && s.watchdog.enabled);
      $("set-lan-bypass").value = s.lan_bypass || "lan";
      $("set-driver").value = s.driver || "auto";
    } catch (_e) {}
  }

  async function runDoctor() {
    const box = $("doctor-results");
    box.textContent = "Running checks…";
    try {
      const res = await apiCall("GET", "/api/v1/doctor");
      box.textContent = "";
      for (const c of (res.checks || [])) {
        const div = document.createElement("div");
        div.className = "doctor-item";
        const badge = document.createElement("span");
        badge.className = "badge " + (c.ok ? "badge-ok" : "badge-danger");
        badge.textContent = c.ok ? "PASS" : "FAIL";
        div.appendChild(badge);
        const txt = document.createElement("span");
        txt.textContent = " " + c.title + " — " + c.detail + (c.remediation ? (" [Fix: " + c.remediation + "]") : "");
        div.appendChild(txt);
        box.appendChild(div);
      }
    } catch (err) {
      box.textContent = "Doctor error: " + err.message;
    }
  }

  async function loadLogs() {
    try {
      const res = await apiCall("GET", "/api/v1/logs?limit=150");
      const lines = (res.entries || []).map((e) => e.t + " [" + String(e.level).toUpperCase() + "] " + e.logger + ": " + e.msg);
      $("logs-output").textContent = lines.join("\n") || "No log entries.";
    } catch (err) {
      $("logs-output").textContent = "Failed to load logs: " + err.message;
    }
  }

  function setupEvents() {
    // Tabs
    document.querySelectorAll(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => {
          p.classList.remove("active");
          p.hidden = true;
        });
        btn.classList.add("active");
        const target = $("panel-" + btn.dataset.tab);
        if (target) {
          target.classList.add("active");
          target.hidden = false;
        }
        if (btn.dataset.tab === "account") loadKeys();
        if (btn.dataset.tab === "settings") loadSettings();
        if (btn.dataset.tab === "doctor") {
          runDoctor();
          loadLogs();
        }
      });
    });

    $("btn-connect-toggle").addEventListener("click", async () => {
      showError("");
      const conn = currentStatus && currentStatus.connection_state;
      try {
        if (conn === "CONNECTED" || conn === "CONNECTING" || conn === "SWITCHING") {
          renderStatus(await apiCall("POST", "/api/v1/disconnect", {}));
        } else {
          renderStatus(await apiCall("POST", "/api/v1/connect", { target: "fastest" }));
        }
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-reconnect").addEventListener("click", async () => {
      showError("");
      try {
        renderStatus(await apiCall("POST", "/api/v1/reconnect", {}));
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-banner-reconnect").addEventListener("click", async () => {
      try {
        renderStatus(await apiCall("POST", "/api/v1/reconnect", {}));
      } catch (err) {
        showError(err.message);
      }
    });

    $("quick-connect-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      showError("");
      const q = ($("quick-target-input").value || "").trim() || "fastest";
      try {
        renderStatus(await apiCall("POST", "/api/v1/connect", { target: q }));
      } catch (err) {
        showError(err.message);
      }
    });

    $("server-search").addEventListener("input", renderServersTable);
    $("server-country").addEventListener("change", renderServersTable);
    $("server-kind").addEventListener("change", renderServersTable);

    $("btn-refresh-servers").addEventListener("click", () => loadServers(true));
    $("btn-probe-rtt").addEventListener("click", async () => {
      const btn = $("btn-probe-rtt");
      btn.disabled = true;
      btn.textContent = "Probing…";
      try {
        const cc = $("server-country").value;
        await apiCall("POST", "/api/v1/servers/probe", { scope: cc ? ("country:" + cc) : "nearest" });
        await loadServers(false);
      } catch (err) {
        showError(err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = "Probe RTT";
      }
    });

    $("login-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      showError("");
      const email = $("login-email").value.trim();
      const password = $("login-password").value;
      try {
        const res = await apiCall("POST", "/api/v1/auth/login", { email, password });
        $("login-password").value = "";
        if (res.status === "otp_required") {
          pendingChallengeId = res.challenge_id;
          $("login-form").hidden = true;
          $("otp-form").hidden = false;
          $("otp-code").focus();
        } else {
          renderStatus(await apiCall("GET", "/api/v1/status"));
          loadKeys();
        }
      } catch (err) {
        showError(err.message);
      }
    });

    $("otp-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      showError("");
      const code = $("otp-code").value.trim();
      try {
        await apiCall("POST", "/api/v1/auth/otp", { challenge_id: pendingChallengeId, code });
        pendingChallengeId = null;
        $("otp-code").value = "";
        $("otp-form").hidden = true;
        $("login-form").hidden = false;
        renderStatus(await apiCall("GET", "/api/v1/status"));
        loadKeys();
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-cancel-otp").addEventListener("click", () => {
      pendingChallengeId = null;
      $("otp-form").hidden = true;
      $("login-form").hidden = false;
    });

    $("btn-import-official").addEventListener("click", async () => {
      showError("");
      try {
        await apiCall("POST", "/api/v1/auth/import-official", {});
        renderStatus(await apiCall("GET", "/api/v1/status"));
        loadKeys();
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-logout").addEventListener("click", async () => {
      showError("");
      try {
        await apiCall("POST", "/api/v1/auth/logout", {});
        renderStatus(await apiCall("GET", "/api/v1/status"));
        loadKeys();
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-rotate-key").addEventListener("click", async () => {
      showError("");
      try {
        await apiCall("POST", "/api/v1/keys/rotate", {});
        await loadKeys();
      } catch (err) {
        showError(err.message);
      }
    });

    $("settings-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      showError("");
      try {
        await apiCall("PATCH", "/api/v1/settings", {
          cleanweb: $("set-cleanweb").checked,
          ipv6_guard: $("set-ipv6-guard").checked,
          autoconnect: $("set-autoconnect").checked,
          lan_bypass: $("set-lan-bypass").value,
          driver: $("set-driver").value,
          watchdog: { enabled: $("set-watchdog").checked }
        });
        renderStatus(await apiCall("GET", "/api/v1/status"));
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-check-ip").addEventListener("click", async () => {
      showError("");
      try {
        await apiCall("GET", "/api/v1/ip");
        renderStatus(await apiCall("GET", "/api/v1/status"));
      } catch (err) {
        showError(err.message);
      }
    });

    $("btn-run-doctor").addEventListener("click", runDoctor);
    $("btn-refresh-logs").addEventListener("click", loadLogs);

    // SSE live updates
    const es = new EventSource("/api/v1/events");
    es.addEventListener("state", (ev) => {
      try {
        renderStatus(JSON.parse(ev.data));
      } catch (_e) {}
    });
  }

  document.addEventListener("DOMContentLoaded", async () => {
    setupEvents();
    try {
      const st = await apiCall("GET", "/api/v1/status");
      renderStatus(st);
    } catch (err) {
      showError(err.message);
    }
    loadServers(false);
  });
})();


    let currentUser = null;
    let entries = [];
    let groups = [];
    let codeState = {};
    let scanStream = null;
    let scanTimer = null;

    async function api(path, opts = {}) {
      const res = await fetch(path, {
        ...opts,
        headers: { "content-type": "application/json", ...(opts.headers || {}) },
        credentials: "include"
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ? data.error + ": " + data.detail : (data.error || ("HTTP " + res.status)));
      return data;
    }

    function msg(id, text, err) {
      const el = document.getElementById(id);
      el.textContent = text || "";
      el.className = err ? "error" : "muted";
    }

    async function init() {
      try {
        const status = await api("/api/status");
        if (!status.initialized) {
          document.getElementById("state").textContent = "System not initialized yet.";
          document.getElementById("bootstrap").style.display = "block";
          return;
        }
        const me = await api("/api/me").catch(() => null);
        if (!me) {
          document.getElementById("state").textContent = "Please login.";
          document.getElementById("login").style.display = "block";
          return;
        }
        currentUser = me.user;
        document.getElementById("state").textContent = "Ready";
        document.getElementById("whoami").textContent = me.user.username + " (" + me.user.role + ")";
        document.getElementById("app").style.display = "block";
        if (me.user.role === "admin") document.getElementById("adminPanel").style.display = "block";
        await refreshAll();
        if (me.user.role === "admin") await refreshUsers();
      } catch (e) {
        document.getElementById("state").textContent = e.message;
      }
    }

    async function bootstrap() {
      try {
        await api("/api/bootstrap", {
          method: "POST",
          body: JSON.stringify({ username: v("bsUser"), password: v("bsPass") })
        });
        location.reload();
      } catch (e) { msg("bsMsg", e.message, true); }
    }

    async function login() {
      try {
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username: v("loginUser"), password: v("loginPass") })
        });
        location.reload();
      } catch (e) { msg("loginMsg", e.message, true); }
    }

    async function logout() {
      await api("/api/logout", { method: "POST", body: "{}" });
      location.reload();
    }

    function v(id) { return document.getElementById(id).value; }

    async function refreshAll() {
      const [e, g] = await Promise.all([api("/api/entries"), api("/api/groups")]);
      entries = e.entries || [];
      groups = g.groups || [];
      hydrateGroupSelects();
      renderGroups();
      renderEntries();
      await refreshVisibleCodes();
    }

    function hydrateGroupSelects() {
      const opts = ['<option value="">No group</option>'];
      const filter = ['<option value="">All groups</option>'];
      groups.forEach(function(g) {
        opts.push('<option value="' + g.id + '">' + esc(g.name) + '</option>');
        filter.push('<option value="' + g.id + '">' + esc(g.name) + '</option>');
      });
      document.getElementById("eGroup").innerHTML = opts.join("");
      document.getElementById("groupFilter").innerHTML = filter.join("");
    }

    function renderGroups() {
      const box = document.getElementById("groupsList");
      if (!groups.length) { box.innerHTML = '<div class="muted">No groups yet.</div>'; return; }
      box.innerHTML = groups.map(function(g) {
        return '<div class="row" style="justify-content:space-between;align-items:center;border:1px solid var(--line);border-radius:10px;padding:7px;">'
          + '<span class="chip"><i style="display:inline-block;width:8px;height:8px;border-radius:999px;background:' + esc(g.color || "#0f766e") + ';"></i>' + esc(g.name) + '</span>'
          + '<button class="warn" onclick="deleteGroup(' + g.id + ')">Delete</button>'
          + '</div>';
      }).join("");
    }

    function renderEntries() {
      const q = v("search").trim().toLowerCase();
      const gf = v("groupFilter");
      const list = entries.filter(function(e) {
        const text = (e.label + " " + (e.issuer || "")).toLowerCase();
        if (q && !text.includes(q)) return false;
        if (gf && String(e.group_id || "") !== gf) return false;
        return true;
      });
      const out = document.getElementById("entries");
      if (!list.length) { out.innerHTML = '<div class="muted">No entries match current filters.</div>'; return; }
      out.innerHTML = list.map(function(e) {
        const state = codeState[e.id] || {};
        const code = state.code || "------";
        const ex = state.expiresIn || "";
        const progress = state.progress || 0;
        const group = e.group_name ? '<span class="chip"><i style="display:inline-block;width:8px;height:8px;border-radius:999px;background:' + esc(e.group_color || "#0f766e") + ';"></i>' + esc(e.group_name) + '</span>' : '';
        const otpTag = '<span class="chip">' + esc((e.otp_type || "totp").toUpperCase()) + '</span>';
        const counter = (e.otp_type === "hotp") ? ('<span class="chip">counter ' + Number(e.hotp_counter || 0) + '</span>') : '';
        return '<article class="entry">'
          + '<div class="title">' + esc(e.label) + '</div>'
          + '<div class="meta">' + esc(e.issuer || "No issuer") + '</div>'
          + '<div class="row">' + otpTag + group + counter + '</div>'
          + '<div class="code" id="c-' + e.id + '">' + esc(code) + '</div>'
          + '<div class="muted" id="x-' + e.id + '">' + (ex ? (ex + "s left") : (e.otp_type === "hotp" ? "Click Generate" : "")) + '</div>'
          + '<div class="bar"><i id="p-' + e.id + '" style="width:' + progress + '%;"></i></div>'
          + '<div class="row" style="margin-top:8px;">'
          + (e.otp_type === "hotp"
            ? '<button onclick="genHotp(' + e.id + ')">Generate HOTP</button>'
            : '<button class="ghost" onclick="copyCode(' + e.id + ')">Copy Code</button>')
          + '<button class="ghost" onclick="editEntry(' + e.id + ')">Edit</button>'
          + '<button class="warn" onclick="deleteEntry(' + e.id + ')">Delete</button>'
          + '</div></article>';
      }).join("");
    }

    async function refreshVisibleCodes() {
      const current = entries.filter(function(e) { return e.otp_type !== "hotp"; });
      await Promise.all(current.map(function(e) { return refreshCode(e.id, true); }));
    }

    async function refreshCode(id, silent) {
      try {
        const r = await api("/api/entries/" + id + "/code");
        const entry = entries.find(function(x){ return x.id === id; });
        const period = Math.max(1, Number((entry && entry.period) || 30));
        const progress = Math.max(0, Math.min(100, ((period - r.expiresIn) / period) * 100));
        codeState[id] = { code: r.code, expiresIn: r.expiresIn, progress: progress };
        const codeEl = document.getElementById("c-" + id);
        const exEl = document.getElementById("x-" + id);
        const pEl = document.getElementById("p-" + id);
        if (codeEl) codeEl.textContent = r.code;
        if (exEl) exEl.textContent = r.expiresIn + "s left";
        if (pEl) pEl.style.width = progress + "%";
      } catch (e) {
        if (!silent) alert(e.message);
      }
    }

    async function copyCode(id) {
      try {
        let code = (codeState[id] && codeState[id].code) || "";
        if (!code || code === "------") {
          await refreshCode(id, true);
          code = (codeState[id] && codeState[id].code) || "";
        }
        if (!code || code === "------") {
          alert("No code available to copy.");
          return;
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(code);
          alert("Code copied to clipboard.");
        } else {
          prompt("Copy code:", code);
        }
      } catch (e) {
        alert(e.message);
      }
    }

    async function genHotp(id) {
      try {
        const r = await api("/api/entries/" + id + "/hotp", { method: "POST", body: "{}" });
        codeState[id] = { code: r.code, expiresIn: 0, progress: 100 };
        await refreshAll();
      } catch (e) { alert(e.message); }
    }

    async function createEntry() {
      try {
        await api("/api/entries", {
          method: "POST",
          body: JSON.stringify({
            label: v("eLabel"),
            issuer: v("eIssuer"),
            secret: v("eSecret"),
            otpauthUri: v("eUri"),
            otpType: v("eOtpType"),
            algorithm: v("eAlgo"),
            digits: Number(v("eDigits") || 6),
            period: Number(v("ePeriod") || 30),
            hotpCounter: Number(v("eCounter") || 0),
            groupId: v("eGroup") ? Number(v("eGroup")) : null
          })
        });
        msg("entryMsg", "Saved");
        ["eLabel","eIssuer","eSecret","eUri"].forEach(function(id){ document.getElementById(id).value = ""; });
        await refreshAll();
      } catch (e) { msg("entryMsg", e.message, true); }
    }

    async function editEntry(id) {
      const e = entries.find(function(x){ return x.id === id; });
      if (!e) return;
      const label = prompt("Label", e.label); if (label === null) return;
      const issuer = prompt("Issuer", e.issuer || ""); if (issuer === null) return;
      const groupIdRaw = prompt("Group ID (empty for none)", e.group_id || "");
      const groupId = groupIdRaw ? Number(groupIdRaw) : null;
      await api("/api/entries/" + id, {
        method: "PATCH",
        body: JSON.stringify({ label: label, issuer: issuer, groupId: groupId })
      });
      await refreshAll();
    }

    async function deleteEntry(id) {
      if (!confirm("Delete this entry?")) return;
      await api("/api/entries/" + id, { method: "DELETE" });
      await refreshAll();
    }

    async function createGroup() {
      try {
        await api("/api/groups", {
          method: "POST",
          body: JSON.stringify({ name: v("gName"), color: v("gColor") })
        });
        document.getElementById("gName").value = "";
        await refreshAll();
      } catch (e) { alert(e.message); }
    }

    async function deleteGroup(id) {
      if (!confirm("Delete group? Entries will be ungrouped.")) return;
      await api("/api/groups/" + id, { method: "DELETE" });
      await refreshAll();
    }

    async function createUser() {
      try {
        await api("/api/users", {
          method: "POST",
          body: JSON.stringify({ username: v("uName"), password: v("uPass"), role: v("uRole") })
        });
        msg("userMsg", "User created");
        await refreshUsers();
      } catch (e) { msg("userMsg", e.message, true); }
    }

    async function refreshUsers() {
      const d = await api("/api/users");
      const table = document.getElementById("usersTable");
      table.innerHTML = "<tr><th>ID</th><th>Username</th><th>Role</th><th>Action</th></tr>";
      (d.users || []).forEach(function(u) {
        const next = u.role === "admin" ? "user" : "admin";
        table.innerHTML += "<tr><td>" + u.id + "</td><td>" + esc(u.username) + "</td><td>" + u.role + "</td><td><button class='ghost' onclick='switchRole(" + u.id + ",\"" + next + "\")'>Set " + next + "</button> <button class='warn' onclick='deleteUser(" + u.id + ")'>Delete</button></td></tr>";
      });
    }

    async function switchRole(id, role) {
      await api("/api/users/" + id + "/role", { method: "PATCH", body: JSON.stringify({ role: role }) });
      await refreshUsers();
    }

    async function deleteUser(id) {
      if (!confirm("Delete user?")) return;
      await api("/api/users/" + id, { method: "DELETE" });
      await refreshUsers();
    }

    function toggleImport() {
      const el = document.getElementById("importPanel");
      el.style.display = el.style.display === "none" ? "block" : "none";
    }

    async function exportData() {
      const d = await api("/api/export");
      const text = JSON.stringify(d, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        alert("Backup JSON copied to clipboard.");
      } else {
        prompt("Copy export JSON:", text);
      }
    }

    async function exportDataEncrypted() {
      const passphrase = prompt("Set backup passphrase (>=10 chars):");
      if (!passphrase) return;
      const d = await api("/api/export/encrypted", {
        method: "POST",
        body: JSON.stringify({ passphrase: passphrase })
      });
      const text = JSON.stringify(d.encrypted, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        alert("Encrypted backup JSON copied to clipboard.");
      } else {
        prompt("Copy encrypted export JSON:", text);
      }
    }

    async function importData() {
      try {
        const payload = JSON.parse(v("importText") || "{}");
        const d = await api("/api/import", { method: "POST", body: JSON.stringify(payload) });
        msg("importMsg", "Imported groups=" + d.imported.groups + ", entries=" + d.imported.entries);
        await refreshAll();
      } catch (e) { msg("importMsg", e.message, true); }
    }

    async function importDataEncrypted() {
      try {
        const encrypted = JSON.parse(v("importText") || "{}");
        const passphrase = v("importPassphrase");
        const d = await api("/api/import/encrypted", {
          method: "POST",
          body: JSON.stringify({ encrypted: encrypted, passphrase: passphrase })
        });
        msg("importMsg", "Encrypted import done: groups=" + d.imported.groups + ", entries=" + d.imported.entries);
        await refreshAll();
      } catch (e) { msg("importMsg", e.message, true); }
    }

    async function startScan() {
      if (!("BarcodeDetector" in window)) {
        msg("scanMsg", "BarcodeDetector is not supported by this browser.", true);
        return;
      }
      try {
        const video = document.getElementById("scanVideo");
        scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        video.srcObject = scanStream;
        video.style.display = "block";
        msg("scanMsg", "Camera scanning started...");
        const detector = new BarcodeDetector({ formats: ["qr_code"] });
        clearInterval(scanTimer);
        scanTimer = setInterval(async function() {
          try {
            const barcodes = await detector.detect(video);
            if (barcodes && barcodes.length) {
              const raw = String(barcodes[0].rawValue || "");
              if (raw) {
                document.getElementById("eUri").value = raw;
                msg("scanMsg", "QR detected. URI filled in form.");
                stopScan();
              }
            }
          } catch {}
        }, 600);
      } catch (e) {
        msg("scanMsg", "Camera access denied or unavailable: " + e.message, true);
      }
    }

    function stopScan() {
      if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
      if (scanStream) {
        scanStream.getTracks().forEach(function(t) { t.stop(); });
        scanStream = null;
      }
      const video = document.getElementById("scanVideo");
      if (video) {
        video.srcObject = null;
        video.style.display = "none";
      }
    }

    async function scanImageFile(ev) {
      if (!("BarcodeDetector" in window)) {
        msg("scanMsg", "BarcodeDetector is not supported by this browser.", true);
        return;
      }
      try {
        const file = ev && ev.target && ev.target.files && ev.target.files[0];
        if (!file) return;
        const bmp = await createImageBitmap(file);
        const detector = new BarcodeDetector({ formats: ["qr_code"] });
        const barcodes = await detector.detect(bmp);
        if (!barcodes.length) {
          msg("scanMsg", "No QR code found in image.", true);
          return;
        }
        const raw = String(barcodes[0].rawValue || "");
        document.getElementById("eUri").value = raw;
        msg("scanMsg", "QR detected from image.");
      } catch (e) {
        msg("scanMsg", "Failed to scan image: " + e.message, true);
      }
    }

    function esc(s) {
      return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    setInterval(function() {
      entries.forEach(function(e) {
        if (e.otp_type !== "hotp") refreshCode(e.id, true);
      });
    }, 5000);

    init();
  

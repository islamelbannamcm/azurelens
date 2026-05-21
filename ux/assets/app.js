// AzureLens — Phase 11 Enterprise UX shell
// Pure vanilla, no build step. All data is seeded mock data.

(function () {
  // Theme toggle with persistence.
  const root = document.documentElement;
  const saved = localStorage.getItem("azurelens.theme");
  if (saved) root.setAttribute("data-theme", saved);

  function toggleTheme() {
    const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    if (next === "dark") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", "light");
    localStorage.setItem("azurelens.theme", next);
  }

  // Keyboard shortcuts.
  // g e -> Executive, g m -> MITRE, g c -> Compliance, / -> focus search, t -> theme
  let chord = null;
  let chordTimer = null;
  document.addEventListener("keydown", (e) => {
    const tag = (e.target && e.target.tagName) || "";
    const typing = tag === "INPUT" || tag === "TEXTAREA" || (e.target && e.target.isContentEditable);
    if (typing) return;

    if (e.key === "/") {
      e.preventDefault();
      const s = document.querySelector(".topbar .search");
      if (s) s.focus();
      return;
    }
    if (e.key === "t" && !e.metaKey && !e.ctrlKey) { toggleTheme(); return; }

    if (chord === "g") {
      if (e.key === "e") location.href = relativeTo("index.html");
      if (e.key === "m") location.href = relativeTo("views/mitre.html");
      if (e.key === "c") location.href = relativeTo("views/compliance.html");
      chord = null;
      return;
    }
    if (e.key === "g") {
      chord = "g";
      clearTimeout(chordTimer);
      chordTimer = setTimeout(() => (chord = null), 900);
    }
  });

  function relativeTo(target) {
    // Resolve a target path relative to the /ux/ root regardless of current view depth.
    const path = location.pathname;
    const uxIdx = path.lastIndexOf("/ux/");
    if (uxIdx >= 0) return path.slice(0, uxIdx + 4) + target;
    return target; // fallback
  }

  // Expose helpers.
  window.AzureLens = { toggleTheme };

  // Wire up theme button if present.
  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("theme-toggle");
    if (btn) btn.addEventListener("click", toggleTheme);

    // Active rail link based on current path.
    const links = document.querySelectorAll(".rail a[data-route]");
    const here = location.pathname.replace(/\/$/, "");
    links.forEach((a) => {
      const route = a.getAttribute("data-route");
      if (here.endsWith(route)) a.classList.add("active");
    });

    // Render MITRE heatmap if container present.
    const mitre = document.getElementById("mitre-grid");
    if (mitre) renderMitre(mitre);

    // Wire compliance tab switching.
    document.querySelectorAll(".tabs .tab").forEach((t) => {
      t.addEventListener("click", () => {
        document.querySelectorAll(".tabs .tab").forEach((x) => x.classList.remove("active"));
        t.classList.add("active");
        const fw = t.getAttribute("data-fw");
        renderControls(fw);
      });
    });
    if (document.getElementById("controls-body")) renderControls("ISO27001");

    // Wire MITRE overlays.
    document.querySelectorAll(".mitre-controls .toggle").forEach((tg) => {
      tg.addEventListener("click", () => {
        tg.classList.toggle("active");
        if (mitre) renderMitre(mitre);
      });
    });
  });

  // ── Mock data ─────────────────────────────────────────────
  const TACTICS = [
    { id: "TA0043", name: "Reconnaissance" },
    { id: "TA0042", name: "Resource Dev" },
    { id: "TA0001", name: "Initial Access" },
    { id: "TA0002", name: "Execution" },
    { id: "TA0003", name: "Persistence" },
    { id: "TA0004", name: "Priv. Esc." },
    { id: "TA0005", name: "Defense Evasion" },
    { id: "TA0006", name: "Credential Access" },
    { id: "TA0007", name: "Discovery" },
    { id: "TA0008", name: "Lateral Movement" },
    { id: "TA0009", name: "Collection" },
    { id: "TA0040", name: "Impact" },
  ];

  // Lightweight per-tactic technique sets with seeded exposure.
  const TECHS = {
    TA0043: [["T1595","Active Scan",1],["T1592","Victim Host",0]],
    TA0042: [["T1583","Acquire Infra",0],["T1587","Develop Cap.",0]],
    TA0001: [["T1566","Phishing",3],["T1078","Valid Accts",3],["T1133","Ext. Services",3]],
    TA0002: [["T1059","Cmd Interp.",2],["T1204","User Exec.",2]],
    TA0003: [["T1098","Account Manip.",2],["T1136","Create Acct",1]],
    TA0004: [["T1078.004","Cloud Accts",3],["T1484","Domain Policy",1]],
    TA0005: [["T1562","Impair Defenses",2],["T1070","Indicator Rm.",1]],
    TA0006: [["T1110","Brute Force",2],["T1556","Mod. Auth Proc.",1]],
    TA0007: [["T1087","Account Disc.",1],["T1069","Group Disc.",1]],
    TA0008: [["T1021.001","RDP",3],["T1550","Alt. Material",1]],
    TA0009: [["T1530","Cloud Storage",2],["T1114","Email Coll.",2]],
    TA0040: [["T1486","Ransomware",2],["T1485","Data Destr.",1]],
  };

  // No-detect overlay: techniques with no Sentinel rule.
  const NO_DETECT = new Set(["T1566", "T1133", "T1486", "T1078.004"]);

  function renderMitre(container) {
    const overlays = {};
    document.querySelectorAll(".mitre-controls .toggle").forEach((t) => {
      overlays[t.dataset.overlay] = t.classList.contains("active");
    });

    container.innerHTML = "";
    TACTICS.forEach((tac) => {
      const col = document.createElement("div");
      col.className = "col";
      const h = document.createElement("h4");
      h.textContent = tac.name;
      col.appendChild(h);

      (TECHS[tac.id] || []).forEach(([tid, name, exp]) => {
        const cell = document.createElement("div");
        let cls = "cell exp-" + exp;
        if (overlays.detect && NO_DETECT.has(tid)) cls += " no-detect";
        cell.className = cls;
        cell.innerHTML =
          '<div>' + name + '</div><div class="tid">' + tid + '</div>';
        cell.title = `${tid} — ${name} — exposure ${exp}/3`;
        col.appendChild(cell);
      });
      container.appendChild(col);
    });
  }

  // ── Compliance mock ────────────────────────────────────────
  const CONTROLS = {
    ISO27001: [
      ["A.5.17", "Authentication information",         "fail", "3 GAs without MFA",                    "2 min ago"],
      ["A.8.5",  "Secure authentication",              "fail", "Legacy auth enabled",                  "2 min ago"],
      ["A.8.20", "Network security",                   "fail", "Public RDP on 2 VMs",                  "2 min ago"],
      ["A.8.7",  "Protection against malware",         "pass", "Defender for Endpoint on 412 devices", "2 min ago"],
      ["A.5.15", "Access control",                     "warn", "Stale guest accounts (14)",            "2 min ago"],
    ],
    SOC2: [
      ["CC6.1",  "Logical access — restriction",       "fail", "No CA on privileged users",            "2 min ago"],
      ["CC6.6",  "Boundary protection",                "fail", "Public NSG rules on prod VMs",         "2 min ago"],
      ["CC7.2",  "System monitoring",                  "warn", "12 analytics rules disabled",          "2 min ago"],
      ["CC8.1",  "Change management",                  "pass", "PIM elevation logged for 100% admins", "2 min ago"],
    ],
    "CIS-Azure": [
      ["1.1.1",  "MFA for Global Admins",              "fail", "3/7 GAs missing MFA",                  "2 min ago"],
      ["6.2",    "RDP/SSH not exposed",                "fail", "vm-app-03, vm-app-07",                 "2 min ago"],
      ["3.1",    "Secure transfer for storage",        "pass", "402/402 storage accounts",             "2 min ago"],
      ["4.3.1",  "Auditing for SQL servers",           "warn", "1 SQL server without auditing",        "2 min ago"],
    ],
    "NIST-CSF": [
      ["PR.AA-01", "Identity & credential mgmt",       "fail", "Permanent GA assignments (5)",         "2 min ago"],
      ["PR.AC-05", "Network integrity protected",      "fail", "Public RDP exposure",                  "2 min ago"],
      ["DE.CM-01", "Network monitored",                "pass", "Sentinel ingesting all subs",          "2 min ago"],
    ],
    "MCSB-v3": [
      ["IM-1",   "Standardize identity",               "fail", "Legacy auth enabled in 2 domains",     "2 min ago"],
      ["NS-1",   "Network segmentation",               "fail", "Flat NSG on rg-prod-eu",               "2 min ago"],
      ["LT-3",   "Logging for investigations",         "pass", "Diagnostic settings on 100% PaaS",     "2 min ago"],
    ],
  };

  function renderControls(fw) {
    const tbody = document.getElementById("controls-body");
    if (!tbody) return;
    const rows = CONTROLS[fw] || [];
    tbody.innerHTML = rows.map(([id, title, status, evidence, when]) => {
      const pillCls = status === "pass" ? "ok" : status === "warn" ? "warn" : "crit";
      const pillTxt = status === "pass" ? "Pass" : status === "warn" ? "Attention" : "Fail";
      return `<tr>
        <td class="code">${id}</td>
        <td>${title}</td>
        <td><span class="pill ${pillCls}">${pillTxt}</span></td>
        <td>${evidence}</td>
        <td style="color:var(--text-3)">${when}</td>
        <td><a href="#evidence-${id}">view</a></td>
      </tr>`;
    }).join("");
  }
})();

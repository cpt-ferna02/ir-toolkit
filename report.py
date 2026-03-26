"""
=============================================================
  Incident Response Toolkit — report.py
  Generates a full HTML forensic report from collected data.
  Dark terminal aesthetic — looks like a real analyst tool.
=============================================================
"""


def generate_report(data, output_file):
    si     = data.get("system_info", {})
    procs  = data.get("processes", [])
    conns  = data.get("network_connections", [])
    users  = data.get("user_accounts", "")
    starts = data.get("startup_programs", "")
    files  = data.get("recent_files", [])

    established = sum(1 for c in conns if c.get("status") == "ESTABLISHED")
    external    = sum(1 for c in conns
                      if c.get("remote_address", "N/A") not in ("N/A", "")
                      and not c.get("remote_address", "").startswith(("127.", "0.0.0.0")))

    # ── Processes table rows ─────────────────────────────
    def proc_rows():
        rows = ""
        for p in procs[:60]:
            mem = p.get("memory_percent") or 0
            cpu = p.get("cpu_percent") or 0
            flag = ""
            if mem > 5:
                flag += '<span class="badge danger">HIGH MEM</span>'
            if cpu > 50:
                flag += '<span class="badge warn">HIGH CPU</span>'
            rows += f"""
            <tr>
              <td class="mono">{p.get('pid', '')}</td>
              <td><strong>{p.get('name', '')}</strong> {flag}</td>
              <td>{p.get('username') or '—'}</td>
              <td><span class="status-{p.get('status','').lower()}">{p.get('status','')}</span></td>
              <td>{round(cpu, 1)}%</td>
              <td>{round(mem, 2)}%</td>
            </tr>"""
        return rows

    # ── Network connections table rows ───────────────────
    def net_rows():
        rows = ""
        for c in conns:
            status = c.get("status", "")
            remote = c.get("remote_address", "N/A")
            flag = ""
            if status == "ESTABLISHED" and remote not in ("N/A", ""):
                flag = '<span class="badge warn">ACTIVE</span>'
            rows += f"""
            <tr>
              <td class="mono">{c.get('pid', '')}</td>
              <td class="mono">{c.get('local_address', '')}</td>
              <td class="mono">{remote} {flag}</td>
              <td><span class="status-{status.lower()}">{status}</span></td>
            </tr>"""
        return rows

    # ── Recent files table rows ──────────────────────────
    def file_rows():
        rows = ""
        for f in files:
            rows += f"""
            <tr>
              <td class="mono small">{f.get('file', '')}</td>
              <td>{f.get('modified', '')}</td>
            </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IR Report — {si.get('hostname','Unknown')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

  :root {{
    --bg:      #080b0f;
    --panel:   #0d1117;
    --card:    #111820;
    --border:  #1c2a38;
    --accent:  #00c8f0;
    --green:   #00e896;
    --warn:    #f0a500;
    --danger:  #f04040;
    --text:    #b8ccd8;
    --heading: #e2eef8;
    --muted:   #3d5265;
    --mono:    'Share Tech Mono', monospace;
    --sans:    'IBM Plex Sans', sans-serif;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 13.5px;
    line-height: 1.6;
  }}

  /* scanline texture */
  body::after {{
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 9999;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 3px,
      rgba(0,200,240,.018) 3px, rgba(0,200,240,.018) 4px
    );
  }}

  /* ── HEADER ──────────────────────────────────── */
  header {{
    background: linear-gradient(135deg, #05090e 0%, #0a1520 100%);
    border-bottom: 2px solid var(--accent);
    padding: 32px 48px;
    display: flex; justify-content: space-between; align-items: flex-start;
    gap: 32px;
    animation: fadeDown .5s ease both;
  }}
  @keyframes fadeDown {{
    from {{ opacity:0; transform:translateY(-10px); }}
    to   {{ opacity:1; transform:translateY(0); }}
  }}
  .brand {{ display:flex; flex-direction:column; gap:6px; }}
  .brand-label {{
    font-family: var(--mono); font-size:10px; letter-spacing:4px;
    text-transform:uppercase; color:var(--muted);
  }}
  .brand h1 {{
    font-family: var(--mono); font-size:24px;
    color:var(--accent); letter-spacing:2px; text-transform:uppercase;
  }}
  .brand h1 em {{ color:var(--green); font-style:normal; }}
  .brand-sub {{ font-size:12px; color:var(--muted); margin-top:2px; }}

  .header-meta {{
    text-align:right; font-size:12px;
    color:var(--muted); line-height:2;
    font-family: var(--mono);
  }}
  .header-meta span {{ color:var(--heading); }}

  .pulse {{
    display:inline-block; width:8px; height:8px;
    background:var(--green); border-radius:50%; margin-right:6px;
    animation: glow 1.6s ease-in-out infinite;
  }}
  @keyframes glow {{
    0%,100% {{ box-shadow:0 0 0 0 rgba(0,232,150,.6); }}
    50%      {{ box-shadow:0 0 0 5px rgba(0,232,150,0); }}
  }}

  /* ── STAT BAR ────────────────────────────────── */
  .stat-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
    animation: fadeUp .6s .1s ease both;
  }}
  @keyframes fadeUp {{
    from {{ opacity:0; transform:translateY(8px); }}
    to   {{ opacity:1; transform:translateY(0); }}
  }}
  .stat {{
    background: var(--panel);
    padding: 20px 28px;
    border-top: 3px solid var(--border);
    transition: border-color .2s;
  }}
  .stat:hover {{ border-top-color: var(--accent); }}
  .stat.ok    {{ border-top-color: var(--green); }}
  .stat.warn  {{ border-top-color: var(--warn); }}
  .stat.info  {{ border-top-color: var(--accent); }}
  .stat .num  {{ font-size:30px; font-weight:600; color:var(--heading); line-height:1; font-family:var(--mono); }}
  .stat .lbl  {{ font-size:10px; letter-spacing:2px; text-transform:uppercase; color:var(--muted); margin-top:4px; }}

  /* ── MAIN LAYOUT ─────────────────────────────── */
  main {{ padding: 40px 48px; display:flex; flex-direction:column; gap:36px; }}

  /* ── SECTION ─────────────────────────────────── */
  .section {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    animation: fadeUp .5s ease both;
  }}
  .section:nth-child(1) {{ animation-delay:.1s; }}
  .section:nth-child(2) {{ animation-delay:.15s; }}
  .section:nth-child(3) {{ animation-delay:.2s; }}
  .section:nth-child(4) {{ animation-delay:.25s; }}
  .section:nth-child(5) {{ animation-delay:.3s; }}
  .section:nth-child(6) {{ animation-delay:.35s; }}

  .section-head {{
    display: flex; align-items: center; gap: 10px;
    padding: 14px 20px;
    background: #0c1219;
    border-bottom: 1px solid var(--border);
  }}
  .section-head h2 {{
    font-family: var(--mono); font-size:12px;
    letter-spacing:3px; text-transform:uppercase; color:var(--accent);
  }}
  .section-head .icon {{ font-size:16px; }}
  .pill {{
    margin-left:auto; background:var(--border); color:var(--muted);
    font-size:11px; padding:2px 10px; border-radius:20px;
    font-family:var(--mono);
  }}

  /* ── SYSTEM INFO GRID ────────────────────────── */
  .info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 1px; background: var(--border); padding: 0;
  }}
  .info-item {{
    background: var(--card); padding: 14px 20px;
  }}
  .info-item .k {{ font-size:10px; letter-spacing:2px; text-transform:uppercase; color:var(--muted); }}
  .info-item .v {{ font-family:var(--mono); color:var(--heading); font-size:13px; margin-top:3px; }}

  /* ── TABLE ───────────────────────────────────── */
  .tbl-wrap {{ overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  th {{
    background:#09111a; color:var(--muted);
    font-size:10px; letter-spacing:2px; text-transform:uppercase;
    padding:10px 16px; text-align:left;
    border-bottom:1px solid var(--border); white-space:nowrap;
  }}
  td {{
    padding:9px 16px; border-bottom:1px solid rgba(28,42,56,.7);
    color:var(--text); vertical-align:middle;
  }}
  tr:last-child td {{ border-bottom:none; }}
  tr:hover td {{ background:rgba(0,200,240,.03); }}

  /* ── PRE BLOCK (users / startup raw output) ──── */
  .raw-output {{
    padding:20px; font-family:var(--mono);
    font-size:12px; color:var(--text);
    white-space:pre-wrap; word-break:break-all;
    line-height:1.8;
  }}

  /* ── HELPERS ─────────────────────────────────── */
  .mono  {{ font-family:var(--mono); font-size:11.5px; }}
  .small {{ font-size:11px; }}

  .badge {{
    display:inline-block; font-size:9px; letter-spacing:1px;
    text-transform:uppercase; padding:2px 7px; border-radius:3px;
    font-weight:700; margin-left:5px; color:#fff;
  }}
  .badge.danger  {{ background:var(--danger); }}
  .badge.warn    {{ background:var(--warn); color:#000; }}
  .badge.ok      {{ background:var(--green); color:#000; }}

  .status-running    {{ color:var(--green); }}
  .status-sleeping   {{ color:var(--muted); }}
  .status-established{{ color:var(--accent); }}
  .status-listen     {{ color:var(--warn); }}
  .status-close_wait {{ color:var(--danger); }}

  /* ── FOOTER ──────────────────────────────────── */
  footer {{
    margin: 0 48px 40px;
    padding-top:20px; border-top:1px solid var(--border);
    font-family:var(--mono); font-size:11px; color:var(--muted);
    letter-spacing:1px;
  }}
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="brand">
    <div class="brand-label"><span class="pulse"></span>FORENSIC TRIAGE REPORT</div>
    <h1>INCIDENT RESPONSE <em>TOOLKIT</em></h1>
    <div class="brand-sub">Automated First-Responder Evidence Collection</div>
  </div>
  <div class="header-meta">
    <div>HOSTNAME &nbsp;<span>{si.get('hostname','—')}</span></div>
    <div>OS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span>{si.get('os','—')} {si.get('os_version','')[:30]}</span></div>
    <div>ARCH &nbsp;&nbsp;&nbsp;&nbsp;<span>{si.get('architecture','—')}</span></div>
    <div>COLLECTED <span>{si.get('collected_at','—')}</span></div>
  </div>
</header>

<!-- STAT BAR -->
<div class="stat-bar">
  <div class="stat info">
    <div class="num">{len(procs)}</div>
    <div class="lbl">Running Processes</div>
  </div>
  <div class="stat {'warn' if established > 15 else 'ok'}">
    <div class="num">{established}</div>
    <div class="lbl">Established Connections</div>
  </div>
  <div class="stat {'warn' if external > 5 else 'ok'}">
    <div class="num">{external}</div>
    <div class="lbl">External Connections</div>
  </div>
  <div class="stat info">
    <div class="num">{len(conns)}</div>
    <div class="lbl">Total Network Sockets</div>
  </div>
  <div class="stat info">
    <div class="num">{len(files)}</div>
    <div class="lbl">Recently Modified Files</div>
  </div>
  <div class="stat {'warn' if len(starts.strip()) > 200 else 'ok'}">
    <div class="num">{len([l for l in starts.splitlines() if 'REG_' in l])}</div>
    <div class="lbl">Startup Entries</div>
  </div>
</div>

<main>

  <!-- SYSTEM INFO -->
  <div class="section">
    <div class="section-head">
      <span class="icon">🖥️</span>
      <h2>System Information</h2>
    </div>
    <div class="info-grid">
      <div class="info-item"><div class="k">Hostname</div><div class="v">{si.get('hostname','—')}</div></div>
      <div class="info-item"><div class="k">Operating System</div><div class="v">{si.get('os','—')}</div></div>
      <div class="info-item"><div class="k">OS Version</div><div class="v">{si.get('os_version','—')[:60]}</div></div>
      <div class="info-item"><div class="k">Architecture</div><div class="v">{si.get('architecture','—')}</div></div>
      <div class="info-item"><div class="k">Processor</div><div class="v">{si.get('processor','—')[:50]}</div></div>
      <div class="info-item"><div class="k">Collected At</div><div class="v">{si.get('collected_at','—')}</div></div>
    </div>
  </div>

  <!-- PROCESSES -->
  <div class="section">
    <div class="section-head">
      <span class="icon">⚙️</span>
      <h2>Running Processes</h2>
      <span class="pill">{len(procs)} total · showing top 60 by memory</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>PID</th><th>Name</th><th>User</th>
            <th>Status</th><th>CPU %</th><th>Mem %</th>
          </tr>
        </thead>
        <tbody>
          {proc_rows()}
        </tbody>
      </table>
    </div>
  </div>

  <!-- NETWORK CONNECTIONS -->
  <div class="section">
    <div class="section-head">
      <span class="icon">🌐</span>
      <h2>Network Connections</h2>
      <span class="pill">{len(conns)} sockets · {established} established</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>PID</th><th>Local Address</th><th>Remote Address</th><th>Status</th></tr>
        </thead>
        <tbody>
          {net_rows()}
        </tbody>
      </table>
    </div>
  </div>

  <!-- USER ACCOUNTS -->
  <div class="section">
    <div class="section-head">
      <span class="icon">👤</span>
      <h2>User Accounts</h2>
    </div>
    <div class="raw-output">{users}</div>
  </div>

  <!-- STARTUP PROGRAMS -->
  <div class="section">
    <div class="section-head">
      <span class="icon">🔑</span>
      <h2>Startup Programs</h2>
      <span class="pill">HKLM Run key</span>
    </div>
    <div class="raw-output">{starts if starts.strip() else "No startup entries found or access denied."}</div>
  </div>

  <!-- RECENTLY MODIFIED FILES -->
  <div class="section">
    <div class="section-head">
      <span class="icon">📁</span>
      <h2>Recently Modified Files</h2>
      <span class="pill">Last 24 hours · top {len(files)}</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>File Path</th><th>Last Modified</th></tr>
        </thead>
        <tbody>
          {file_rows()}
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>
  IR TOOLKIT &nbsp;·&nbsp; Report generated {si.get('collected_at','—')} &nbsp;·&nbsp;
  Host: {si.get('hostname','—')} &nbsp;·&nbsp; {si.get('os','—')} {si.get('architecture','')}
</footer>

</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] HTML report written: {output_file}")
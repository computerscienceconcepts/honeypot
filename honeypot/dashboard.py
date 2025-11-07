from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional

from aiohttp import web


def create_app(log_path: str) -> web.Application:
    app = web.Application()
    app["log_path"] = Path(log_path)    
    # Serve static assets
    project_root = Path(__file__).resolve().parents[1]
    assets_dir = project_root / "assets"
    if assets_dir.exists():
        app.router.add_static("/assets", str(assets_dir), name="assets")
    
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/logs", handle_api_logs)
    app.router.add_post("/api/delete_logs", handle_api_delete_logs)
    return app


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _filter_events(
    events: Iterable[Dict[str, Any]],
    port: Optional[int],
    ip_substr: Optional[str],
    protocol: Optional[str],
    limit: int,
) -> List[Dict[str, Any]]:
    out: Deque[Dict[str, Any]] = deque(maxlen=limit)
    prot = (protocol or "").strip().upper() or None
    ipq = (ip_substr or "").strip() or None

    for ev in events:
        if port is not None and ev.get("dst_port") != port:
            continue
        if prot is not None and (ev.get("protocol") or "").upper() != prot:
            continue
        if ipq is not None:
            sip = str(ev.get("src_ip", ""))
            if ipq not in sip:
                continue
        out.append(ev)

    return list(out)


async def handle_api_logs(request: web.Request) -> web.Response:
    log_path: Path = request.app["log_path"]
    qp = request.rel_url.query
    port = int(qp.get("port", "0")) if qp.get("port") else None
    ip_substr = qp.get("ip", None)
    protocol = qp.get("protocol", None)
    limit = min(max(int(qp.get("limit", "200")), 1), 5000)

    events = _iter_jsonl(log_path)
    filtered = _filter_events(events, port, ip_substr, protocol, limit)
    return web.json_response(filtered)


async def handle_api_delete_logs(request: web.Request) -> web.Response:
    """Delete all event logs. Only app.log will remain accessible."""
    log_path: Path = request.app["log_path"]
    try:
        if log_path.exists():
            log_path.write_text("", encoding="utf-8")
        return web.json_response({"status": "ok", "message": "All logs deleted"})
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _format_ts(value: str) -> str:
    """Normalize timestamps to 'YYYY-MM-DD HH:MM:SS UTC' for display.

    Accepts ISO 8601 or already-formatted values.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    txt = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        # Fallback: return as-is
        return raw


def _render_table(rows: List[Dict[str, Any]]) -> str:
    cells = []
    for ev in rows:
        cells.append(
            "<tr>"
            f"<td>{_html_escape(_format_ts(str(ev.get('timestamp', ''))))}</td>"
            f"<td>{_html_escape(str(ev.get('src_ip', '')))}</td>"
            f"<td>{_html_escape(str(ev.get('src_port', '')))}</td>"
            f"<td>{_html_escape(str(ev.get('dst_port', '')))}</td>"
            f"<td>{_html_escape(str(ev.get('protocol', '')))}</td>"
            f"<td>{_html_escape(str((ev.get('user_agent') or '')[:120]))}</td>"
            f"<td><code style='white-space:pre-wrap'>{_html_escape(str((ev.get('raw_payload') or '')[:200]))}</code></td>"
            f"<td>{_html_escape(str(ev.get('notes', '')))}</td>"
            "</tr>"
        )
    return "\n".join(cells)


async def handle_index(request: web.Request) -> web.Response:
    log_path: Path = request.app["log_path"]
    qp = request.rel_url.query
    port = int(qp.get("port", "0")) if qp.get("port") else None
    ip_substr = qp.get("ip", None)
    protocol = qp.get("protocol", None)
    limit = min(max(int(qp.get("limit", "200")), 1), 2000)

    events = _iter_jsonl(log_path)
    filtered = _filter_events(events, port, ip_substr, protocol, limit)

    if filtered:
        table_rows = _render_table(filtered[-200:])
    else:
        table_rows = '<tr><td colspan="8" class="no-logs-message">No logs can be shown</td></tr>'
    
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Honeypot</title>
    <link rel="icon" href="/assets/honeypot_logo.png" />
    <style>
      :root {{
        --bg: #0d0d0d;
        --panel: #151515;
        --muted: #9e9e9e;
        --text: #eaeaea;
        --accent: #ff9800; /* orange */
        --border: #2a2a2a;
      }}
      html, body {{ background: var(--bg); color: var(--text); }}
      body {{ font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset; }}
      .header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }}
      .logo {{
        width: 32px;
        height: 32px;
        max-width: 32px;
        max-height: 32px;
        vertical-align: middle;
        cursor: pointer;
        transition: transform 0.2s;
        object-fit: contain;
        object-position: center;
      }}
      .logo:hover {{ transform: scale(1.1); }}
      h1 {{ font-size: 22px; margin: 0; letter-spacing: 0.3px; }}
      .filters form {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }}
      input {{ background: #111; color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; }}
      button {{ background: var(--accent); color: #000; border: none; border-radius: 6px; padding: 8px 12px; font-weight: 600; cursor: pointer; }}
      button:hover {{ filter: brightness(1.1); }}
      button.secondary {{ background: #444; color: var(--text); }}
      button.secondary:hover {{ background: #555; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid var(--border); padding: 8px; font-size: 13px; vertical-align: top; }}
      th {{ background: #101010; color: var(--muted); text-align: left; position: sticky; top: 0; }}
      code {{ font-family: ui-monospace, Menlo, Consolas, monospace; }}
      .api-tip {{ color: var(--muted); margin-top: 10px; }}
      .no-logs-message {{
        text-align: center;
        padding: 40px 20px;
        color: var(--muted);
        font-style: italic;
        font-size: 14px;
      }}
      .api-tip-container {{
        display: flex;
        align-items: center;
        gap: 8px;
        margin-top: 10px;
      }}
      .api-tip {{
        color: var(--muted);
        transition: opacity 0.3s, filter 0.3s;
        margin: 0;
        line-height: 1.5;
      }}
      .api-tip.hidden {{
        opacity: 0.3;
        filter: blur(4px);
        user-select: none;
        pointer-events: none;
      }}
      .eye-toggle {{
        width: 20px;
        height: 20px;
        cursor: pointer;
        transition: transform 0.2s;
        flex-shrink: 0;
        color: var(--muted);
        margin-top: 0;
        align-self: center;
      }}
      .eye-toggle:hover {{
        transform: scale(1.1);
        color: var(--accent);
      }}
      .eye-icon {{
        width: 100%;
        height: 100%;
        transition: opacity 0.3s;
      }}
      #eyePupil {{
        transition: opacity 0.3s;
      }}
      #eyeCross1 {{
        transition: opacity 0.3s, transform 0.3s;
        opacity: 0;
        transform: scale(0.8);
      }}
      #eyeCross1.show {{
        opacity: 1;
        transform: scale(1);
      }}
      /* Modal styles */
      .modal-overlay {{
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        z-index: 1000;
        align-items: center;
        justify-content: center;
      }}
      .modal-overlay.show {{
        display: flex;
      }}
      .modal-box {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 24px;
        max-width: 500px;
        width: 90%;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
      }}
      .modal-title {{
        font-size: 18px;
        font-weight: 600;
        margin-bottom: 12px;
        color: var(--text);
      }}
      .modal-message {{
        color: var(--muted);
        margin-bottom: 20px;
        line-height: 1.5;
      }}
      .modal-buttons {{
        display: flex;
        gap: 10px;
        justify-content: flex-end;
      }}
      .modal-btn {{
        padding: 8px 16px;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        cursor: pointer;
        transition: filter 0.2s;
      }}
      .modal-btn:hover {{
        filter: brightness(1.1);
      }}
      .modal-btn-cancel {{
        background: #444;
        color: var(--text);
      }}
      .modal-btn-confirm {{
        background: #d32f2f;
        color: #fff;
      }}
      .modal-btn-ok {{
        background: var(--accent);
        color: #000;
      }}
    </style>
  </head>
  <body>
    <div class="header">
      <a href="/" title="Refresh page" onclick="event.preventDefault(); location.reload();">
        <img src="/assets/honeypot_logo.png" alt="Honeypot Logo" class="logo" />
      </a>
      <h1>Honeypot</h1>
    </div>
    <div class="card">
    <div class="filters">
      <form id="filterForm" onsubmit="event.preventDefault(); return false;">
        <label>Port: <input type="number" name="port" id="portFilter" value="{_html_escape(qp.get('port',''))}" oninput="refreshTable()"></label>
        <label>IP contains: <input type="text" name="ip" id="ipFilter" value="{_html_escape(qp.get('ip',''))}" oninput="refreshTable()"></label>
        <label>Protocol: <input type="text" name="protocol" id="protocolFilter" value="{_html_escape(qp.get('protocol',''))}" placeholder="SSH/HTTP/HTTPS" oninput="refreshTable()"></label>
        <label>Limit: <input type="number" name="limit" id="limitFilter" value="{_html_escape(qp.get('limit','200'))}" oninput="refreshTable()"></label>
        <button type="button" class="secondary" onclick="clearAll()">Clear</button>
        <button type="button" class="secondary" onclick="deleteAllLogs()" style="background: #d32f2f; color: #fff;">Delete All Logs</button>
        <a href="/">Reset</a>
      </form>
    </div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Source IP</th>
          <th>Source Port</th>
          <th>Destination Port</th>
          <th>Protocol</th>
          <th>User-Agent</th>
          <th>Raw Payload</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {table_rows}
      </tbody>
    </table>
    <div class="api-tip-container">
      <p class="api-tip hidden" id="apiTip">API: <code>/api/logs?limit=200&port=80&ip=1.2.3&protocol=HTTP</code></p>
      <svg class="eye-toggle" id="eyeToggle" onclick="toggleApiTip()" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path class="eye-icon" id="eyeIcon" d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" style="opacity: 0.5;"/>
        <circle class="eye-pupil" id="eyePupil" cx="12" cy="12" r="3" style="display: none;"/>
        <line id="eyeCross1" x1="1" y1="1" x2="23" y2="23" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" class="show"/>
      </svg>
    </div>
    </div>
    
    <!-- Modal for confirmations and alerts -->
    <div id="modalOverlay" class="modal-overlay">
      <div class="modal-box">
        <div class="modal-title" id="modalTitle">Confirm</div>
        <div class="modal-message" id="modalMessage"></div>
        <div class="modal-buttons" id="modalButtons"></div>
      </div>
    </div>
    
    <script>
      function esc(s) {{
        return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
      }}
      function formatTimestamp(ts) {{
        if (!ts) return '';
        try {{
          const dt = new Date(ts.replace(' UTC', 'Z'));
          if (isNaN(dt.getTime())) return ts;
          return dt.toISOString().replace('T', ' ').replace(/\.\\d{{3}}Z/, ' UTC');
        }} catch {{ return ts; }}
      }}
      function renderRow(ev) {{
        return '<tr>' +
          '<td>' + esc(formatTimestamp(ev.timestamp)) + '</td>' +
          '<td>' + esc(ev.src_ip || '') + '</td>' +
          '<td>' + esc(ev.src_port || '') + '</td>' +
          '<td>' + esc(ev.dst_port || '') + '</td>' +
          '<td>' + esc(ev.protocol || '') + '</td>' +
          '<td>' + esc((ev.user_agent || '').substring(0, 120)) + '</td>' +
          '<td><code style="white-space:pre-wrap">' + esc(String(ev.raw_payload || '').substring(0, 200)) + '</code></td>' +
          '<td>' + esc(ev.notes || '') + '</td>' +
        '</tr>';
      }}
      function clearAll() {{
        // Clear all filter fields
        document.getElementById('portFilter').value = '';
        document.getElementById('ipFilter').value = '';
        document.getElementById('protocolFilter').value = '';
        document.getElementById('limitFilter').value = '200';
        // Clear table
        document.getElementById('tableBody').innerHTML = '';
        // Refresh to show all results
        refreshTable();
      }}
      function showModal(title, message, buttons) {{
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('modalMessage').textContent = message;
        const buttonsContainer = document.getElementById('modalButtons');
        buttonsContainer.innerHTML = '';
        buttons.forEach(btn => {{
          const button = document.createElement('button');
          button.className = 'modal-btn ' + btn.className;
          button.textContent = btn.text;
          button.onclick = () => {{
            document.getElementById('modalOverlay').classList.remove('show');
            if (btn.onclick) btn.onclick();
          }};
          buttonsContainer.appendChild(button);
        }});
        document.getElementById('modalOverlay').classList.add('show');
      }}
      function showAlert(title, message) {{
        showModal(title, message, [
          {{text: 'OK', className: 'modal-btn-ok'}}
        ]);
      }}
      function showConfirm(title, message, onConfirm, onCancel) {{
        showModal(title, message, [
          {{text: 'Cancel', className: 'modal-btn-cancel', onclick: onCancel || (() => {{}})}},
          {{text: 'Confirm', className: 'modal-btn-confirm', onclick: onConfirm}}
        ]);
      }}
      // Close modal when clicking overlay (but not the modal box itself)
      document.getElementById('modalOverlay').addEventListener('click', function(e) {{
        if (e.target === this) {{
          this.classList.remove('show');
        }}
      }});
      async function deleteAllLogs() {{
        showConfirm(
          'Delete All Logs',
          'Are you sure you want to clear all the logs? This action cannot be undone. You will only be able to find the logs through app.log',
          async () => {{
            try {{
              const res = await fetch('/api/delete_logs', {{method: 'POST'}});
              const data = await res.json();
              if (data.status === 'ok') {{
                document.getElementById('tableBody').innerHTML = '';
                // Stop auto-refresh and prevent future updates
                if (window.refreshInterval) clearInterval(window.refreshInterval);
                window.refreshInterval = null;
                showAlert('Success', 'All logs deleted successfully. Dashboard will no longer show any logs.');
              }} else {{
                showAlert('Error', 'Error: ' + (data.message || 'Failed to delete logs'));
              }}
            }} catch (e) {{
              showAlert('Error', 'Failed to delete logs');
              console.error(e);
            }}
          }}
        );
      }}
      async function refreshTable() {{
        const params = new URLSearchParams();
        const port = document.getElementById('portFilter').value.trim();
        const ip = document.getElementById('ipFilter').value.trim();
        const protocol = document.getElementById('protocolFilter').value.trim();
        const limit = document.getElementById('limitFilter').value.trim() || '200';
        if (port) params.set('port', port);
        if (ip) params.set('ip', ip);
        if (protocol) params.set('protocol', protocol);
        params.set('limit', limit);
        try {{
          const res = await fetch('/api/logs?' + params.toString(), {{cache: 'no-store'}});
          const data = await res.json();
          const tbody = document.getElementById('tableBody');
          if (data.length === 0) {{
            tbody.innerHTML = '<tr><td colspan="8" class="no-logs-message">No logs can be shown</td></tr>';
          }} else {{
            tbody.innerHTML = data.slice(-200).map(renderRow).join('');
          }}
        }} catch (e) {{
          console.error('Refresh failed:', e);
        }}
      }}
      // API tip visibility toggle (default: hidden/closed)
      let apiTipVisible = false;
      
      function toggleApiTip() {{
        apiTipVisible = !apiTipVisible;
        const tip = document.getElementById('apiTip');
        const cross1 = document.getElementById('eyeCross1');
        const pupil = document.getElementById('eyePupil');
        const icon = document.getElementById('eyeIcon');
        
        if (apiTipVisible) {{
          tip.classList.remove('hidden');
          cross1.classList.remove('show');
          setTimeout(() => {{
            cross1.style.display = 'none';
            pupil.style.display = 'block';
            icon.style.opacity = '1';
          }}, 150);
        }} else {{
          tip.classList.add('hidden');
          pupil.style.display = 'none';
          icon.style.opacity = '0.5';
          cross1.style.display = 'block';
          setTimeout(() => {{
            cross1.classList.add('show');
          }}, 10);
        }}
      }}
      
      // Auto-refresh every 1 second (only if interval not stopped)
      window.refreshInterval = setInterval(refreshTable, 1000);
    </script>
  </body>
 </html>
"""

    return web.Response(text=html, content_type="text/html")



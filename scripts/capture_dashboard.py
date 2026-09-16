"""Screenshot the SOC_OVERVIEW Kibana dashboard via Chrome DevTools Protocol.

Why CDP instead of `chrome --screenshot`: we need to (a) dismiss Kibana's
"Your data is not secure" toast, (b) wait for every visualization to finish
rendering, and (c) capture the FULL page height so all 7 panels are visible
(--screenshot only grabs the viewport).

Usage:
    python scripts/capture_dashboard.py [output.png]
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 9222
DASH = "soc-overview-dashboard"
URL = (
    "http://localhost:8081/app/dashboards#/view/" + DASH +
    "?_g=(refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"
)
OUT = sys.argv[1] if len(sys.argv) > 1 else "assets/kibana-dashboard.png"


def cdp(ws_url, method, params=None, _id=[0]):
    """One-shot CDP call over a fresh websocket (stdlib only)."""
    import socket, struct, hashlib, ssl
    from urllib.parse import urlparse

    u = urlparse(ws_url)
    s = socket.create_connection((u.hostname, u.port), timeout=30)
    if u.scheme == "wss":
        s = ssl.wrap_socket(s)
    key = base64.b64encode(os.urandom(16)).decode()
    path = u.path + ("?" + u.query if u.query else "")
    s.sendall((
        f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)

    def send(payload):
        data = json.dumps(payload).encode()
        hdr = b"\x81"
        n = len(data)
        mask = os.urandom(4)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        hdr += mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        s.sendall(hdr)

    def recv():
        h = s.recv(2)
        if len(h) < 2:
            return None
        ln = h[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", s.recv(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", s.recv(8))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode(errors="replace"))

    _id[0] += 1
    send({"id": _id[0], "method": method, "params": params or {}})
    while True:
        msg = recv()
        if msg is None:
            return None
        if msg.get("id") == _id[0]:
            return msg


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    proc = subprocess.Popen([
        CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
        "--hide-scrollbars", f"--remote-debugging-port={PORT}",
        "--window-size=1920,1200", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws = None
        for _ in range(40):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=2) as r:
                    tabs = json.load(r)
                page = [t for t in tabs if t.get("type") == "page"]
                if page:
                    ws = page[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not ws:
            print("ERROR: could not reach Chrome DevTools endpoint")
            return 1

        cdp(ws, "Page.enable")
        cdp(ws, "Runtime.enable")
        cdp(ws, "Page.navigate", {"url": URL})
        print("navigating, waiting for panels to render...")
        time.sleep(30)

        # Dismiss the "Your data is not secure" toast + any modal close buttons.
        dismiss = """
        (() => {
          const kill = ['Dismiss', 'Don\\'t show again'];
          let n = 0;
          document.querySelectorAll('button, a, span').forEach(el => {
            const t = (el.textContent || '').trim();
            if (kill.includes(t)) { try { el.click(); n++; } catch (e) {} }
          });
          document.querySelectorAll('[data-test-subj*="toast"] button').forEach(b => {
            try { b.click(); n++; } catch (e) {}
          });
          return n;
        })()
        """
        r = cdp(ws, "Runtime.evaluate", {"expression": dismiss, "returnByValue": True})
        print("dismissed elements:", r.get("result", {}).get("result", {}).get("value"))
        time.sleep(3)

        # Measure full page height for a full-page capture.
        h = cdp(ws, "Runtime.evaluate", {
            "expression": "Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)",
            "returnByValue": True,
        })
        height = h.get("result", {}).get("result", {}).get("value") or 1400
        height = max(int(height), 1200)
        height = min(height + 60, 4000)
        cdp(ws, "Emulation.setDeviceMetricsOverride", {
            "width": 1920, "height": height, "deviceScaleFactor": 1, "mobile": False,
        })
        time.sleep(5)

        shot = cdp(ws, "Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
        data = shot.get("result", {}).get("data")
        if not data:
            print("ERROR: no screenshot data:", json.dumps(shot)[:400])
            return 1
        with open(OUT, "wb") as f:
            f.write(base64.b64decode(data))
        print(f"OK wrote {OUT} ({os.path.getsize(OUT)} bytes, {1920}x{height})")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

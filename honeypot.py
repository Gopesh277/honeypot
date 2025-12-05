#!/usr/bin/env python3
# server.py - pure Python honeypot that serves login + fake dashboard and logs actions
import socket, threading, json, os, requests
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote_plus

HOST = "0.0.0.0"
PORT = 8080
LOGFILE = "honeypot.log"
MAX_READ = 16_384

def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
        if r.get("status") == "success":
            return {
                "country": r.get("country") or "Unknown",
                "city":    r.get("city") or "Unknown",
                "isp":     r.get("isp") or "Unknown",
                "org":     r.get("org") or "Unknown"
            }
    except Exception:
        pass
    return {"country":"Unknown","city":"Unknown","isp":"Unknown","org":"Unknown"}
def write_log(obj):
    try:
        # attach geo if we have an ip
        ip = obj.get("src_ip") or obj.get("ip")
        if ip:
            try:
                obj["geolocation"] = get_geo(ip)
            except Exception:
                obj["geolocation"] = {"country":"Unknown","city":"Unknown","isp":"Unknown","org":"Unknown"}

        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, default=str) + "\n")
    except Exception as e:
        print("Log write error:", e)


def read_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def parse_request(data_bytes):
    text = data_bytes.decode("utf-8", errors="ignore")
    head, sep, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if len(lines) == 0:
        return None, None, {}, ""
    request_line = lines[0].split()
    method = request_line[0] if len(request_line) > 0 else "GET"
    path = request_line[1] if len(request_line) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k,v = line.split(":",1)
            headers[k.strip()] = v.strip()
    return method, path, headers, body

def handle_client(conn, addr):
    ip, port = addr
    ts = datetime.now(timezone.utc).isoformat()
    try:
        data = conn.recv(MAX_READ)
        if not data:
            conn.close(); return
        method, path, headers, body = parse_request(data)
        if method is None:
            conn.close(); return

        base_event = {"time": ts, "src_ip": ip, "src_port": port, "method": method, "path": path, "ua": headers.get("User-Agent","")}

        # LOGIN POST -> show dashboard (always) but log credentials
        if method.upper() == "POST" and path == "/":
            # body may be form encoded; attempt to parse posted fields
            posted = {}
            try:
                posted = parse_qs(body)
                posted = {k: (v[0] if isinstance(v, list) else v) for k,v in posted.items()}
                # decode any percent encoding
                posted = {k: unquote_plus(v) if isinstance(v,str) else v for k,v in posted.items()}
            except Exception:
                posted = {"raw_body": body}
            ev = dict(base_event)
            ev["event"] = "login_attempt"
            ev["posted"] = posted
            write_log(ev)

            # serve dashboard (engaging)
            html = read_file("dashboard.html")
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(html)}\r\n\r\n{html}"
            conn.sendall(response.encode("utf-8", errors="ignore"))
            conn.close()
            return

        # ACTIONS from dashboard (buttons/forms POST to /action)
        if method.upper() == "POST" and path == "/action":
            posted = {}
            try:
                posted = parse_qs(body)
                posted = {k: (v[0] if isinstance(v, list) else v) for k,v in posted.items()}
                posted = {k: unquote_plus(v) if isinstance(v,str) else v for k,v in posted.items()}
            except Exception:
                posted = {"raw_body": body}
            ev = dict(base_event)
            ev["event"] = "dashboard_action"
            ev["posted"] = posted
            write_log(ev)

            # send a small ack page so attacker sees something
            resp_body = "<html><body><h3>Action received</h3><a href='/'>Back</a></body></html>"
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(resp_body)}\r\n\r\n{resp_body}"
            conn.sendall(response.encode("utf-8", errors="ignore"))
            conn.close()
            return

        # GET / or other GET -> serve login page
        if method.upper() == "GET":
            if os.path.exists("login.html"):
                html = read_file("login.html")
            else:
                html = "<html><body><h3>Login</h3></body></html>"
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(html)}\r\n\r\n{html}"
            conn.sendall(response.encode("utf-8", errors="ignore"))
            # log GET
            ev = dict(base_event)
            ev["event"] = "page_visit"
            write_log(ev)
            conn.close()
            return

        # default: close
        conn.close()

    except Exception as e:
        write_log({"time": ts, "src_ip": ip, "error": str(e)})
        try: conn.close()
        except: pass

def start():
    print(f"[*] Honeypot dashboard running on http://localhost:{PORT}/")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[+] Exiting.")
    finally:
        s.close()

if __name__ == "__main__":
    start()

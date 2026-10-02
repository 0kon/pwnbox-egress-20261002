#!/usr/bin/env python3
"""Temporary authenticated command queue for controlled lab race calibration."""
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = os.environ["CTRL_TOKEN"]
LOCK = threading.Lock()
QUEUES = {}
RESULTS = []
REGISTERED = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def authorize(self):
        value = self.headers.get("Authorization", "")
        if hmac.compare_digest(value, "Bearer " + TOKEN):
            return True
        self.send_json(403, {"error":"forbidden"})
        return False

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 100_000:
            raise ValueError("oversized")
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if not self.authorize(): return
        parsed = urlsplit(self.path)
        if parsed.path == "/poll":
            worker = parse_qs(parsed.query).get("worker",[""])[0]
            with LOCK:
                task = QUEUES.get(worker,[]).pop(0) if QUEUES.get(worker) else None
            self.send_json(200,{"task":task})
        elif parsed.path == "/admin/state":
            with LOCK:
                queues={k:[{"tag":t.get("tag"),"release_at":t.get("release_at"),"count":t.get("count")}
                           for t in v] for k,v in QUEUES.items()}
                snapshot={"registered":REGISTERED.copy(),"queues":queues,"results":RESULTS.copy()}
            self.send_json(200,snapshot)
        else:
            self.send_json(404,{"error":"not found"})

    def do_POST(self):
        if not self.authorize(): return
        try: item = self.read_json()
        except Exception:
            self.send_json(400,{"error":"invalid JSON"});return
        if self.path == "/register":
            worker = str(item.get("worker",""))
            with LOCK:
                REGISTERED[worker]={"egress_ip":item.get("egress_ip"),
                                    "ntp_offset_ms":item.get("ntp_offset_ms"),
                                    "registered_at":time.time()}
            self.send_json(200,{"ok":True})
        elif self.path == "/result":
            item.pop("cookie",None)
            with LOCK: RESULTS.append(item)
            print(json.dumps(item),flush=True)
            self.send_json(200,{"ok":True})
        elif self.path == "/admin/queue":
            workers=item.get("workers",[])
            task=item.get("task")
            if not isinstance(workers,list) or not isinstance(task,dict):
                self.send_json(400,{"error":"invalid task"});return
            with LOCK:
                for worker in workers:
                    QUEUES.setdefault(worker,[]).append(task)
            self.send_json(200,{"queued":workers,"tag":task.get("tag")})
        else:
            self.send_json(404,{"error":"not found"})


if __name__ == "__main__":
    server=ThreadingHTTPServer(("127.0.0.1",8765),Handler)
    print("coordinator-ready 127.0.0.1:8765",flush=True)
    server.serve_forever()

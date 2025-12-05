#!/usr/bin/env python3
# analyze_logs.py
# Produces: attacks_per_hour.png, top_ips.png, top_usernames.png
import json
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

LOGFILE = "honeypot.log"

# --- read JSON lines ---
events = []
with open(LOGFILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            obj = json.loads(line)
            events.append(obj)
        except:
            pass

if not events:
    print("No events found in", LOGFILE)
    raise SystemExit(0)

# --- attacks per hour ---
# parse timestamps and bucket by hour
hours = []
for e in events:
    t = e.get("time") or e.get("ts") or e.get("time")
    if not t: continue
    try:
        dt = datetime.fromisoformat(t.replace("Z","+00:00"))
        hours.append(dt.replace(minute=0, second=0, microsecond=0))
    except:
        continue

if hours:
    hr_counts = Counter(hours)
    hr_items = sorted(hr_counts.items())
    xs = [x[0] for x in hr_items]
    ys = [x[1] for x in hr_items]

    plt.figure(figsize=(10,4))
    plt.plot(xs, ys)
    plt.title("Events per hour")
    plt.xlabel("Hour")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.xticks(rotation=30)
    plt.savefig("attacks_per_hour.png")
    plt.close()
    print("Saved attacks_per_hour.png")

# --- top IPs ---
ips = [e.get("src_ip") or e.get("src") or e.get("ip") for e in events]
ips = [i for i in ips if i]
ip_counts = Counter(ips)
top_ips = ip_counts.most_common(10)
if top_ips:
    df = pd.DataFrame(top_ips, columns=["ip","count"]).sort_values("count", ascending=True)
    plt.figure(figsize=(6,4))
    plt.barh(df["ip"], df["count"])
    plt.title("Top IPs")
    plt.tight_layout()
    plt.savefig("top_ips.png")
    plt.close()
    print("Saved top_ips.png")

# --- top usernames attempted (from login attempts)
usernames = []
for e in events:
    if e.get("event") == "login_attempt" or e.get("method") == "POST":
        posted = e.get("posted") or {}
        if isinstance(posted, dict):
            if "username" in posted:
                usernames.append(posted.get("username"))
            elif "user" in posted:
                usernames.append(posted.get("user"))
# filter empty and count
usernames = [u for u in usernames if u]
uname_counts = Counter(usernames)
top_unames = uname_counts.most_common(15)
if top_unames:
    df = pd.DataFrame(top_unames, columns=["username","count"]).sort_values("count", ascending=True)
    plt.figure(figsize=(6,4))
    plt.barh(df["username"], df["count"])
    plt.title("Top Usernames Tried")
    plt.tight_layout()
    plt.savefig("top_usernames.png")
    plt.close()
    print("Saved top_usernames.png")

print("Done.")

# --- top countries (from geolocation) ---
countries = []
for e in events:
    geo = e.get("geolocation", {})
    if isinstance(geo, dict):
        country = geo.get("country")
        if country:
            countries.append(country)

if countries:
    from collections import Counter
    c_counts = Counter(countries)
    top_countries = c_counts.most_common(10)

    df = pd.DataFrame(top_countries, columns=["country", "count"]).sort_values("count", ascending=True)

    plt.figure(figsize=(6,4))
    plt.barh(df["country"], df["count"])
    plt.title("Top Countries Attacking")
    plt.tight_layout()
    plt.savefig("top_countries.png")
    plt.close()

    print("Saved top_countries.png")

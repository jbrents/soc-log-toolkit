from parser import parse_auth_log
from detection import detect_brute_force

events = parse_auth_log("../sample_data/auth.log.sample2")
print(f"Parsed {len(events)} events")

detections = detect_brute_force(events)
print(f"{len(detections)} detection(s)\n")
for d in detections:
    print(f"[{d.severity.upper()}] {d.technique} ({d.mitre_id})")
    print(f"  {d.first_seen} -> {d.last_seen}")
    print(f"  ip={d.source_ip} user={d.user}")
    print(f"  {d.description}\n")

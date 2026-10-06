import parser
from parser import AuthEvent
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class AuthDetection:
    """ These fields will assist in defining detection"""


    technique: str                #Technique is the attack type ex. Brute Force
    mitre_id: str                 #Mitre_Id is the publicly catalogged ID for the attack type
    severity: str                 # Severity shows is how severe the attack is low/medium/high
    first_seen: datetime          #When the attack was first seen
    last_seen: datetime           #When the attack was last seen
    user: Optional[str]           #The user name if there is one
    source_ip: Optional[str]      #Source ip if there is one
    evidence: list[AuthEvent]     #Raw line evidence for the attack
    description: str              #Short description of the attack

def group_failed_attempts_by_ip(events: list[AuthEvent]) -> dict[str, list[AuthEvent]]:
    """ Here I'll be grouping failed password attempts, auth failures, and invalid users by the source ip"""

    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.event_type in ("failed_password", "auth_failure", "invalid_user") and e.source_ip:
            by_ip[e.source_ip].append(e)
    return by_ip

def find_bursts(events: list[AuthEvent], window_minutes: int = 5, threshold: int = 5) -> list[list[AuthEvent]]:
    ordered = sorted(events, key = lambda e: e.timestamp)
    window = timedelta(minutes = window_minutes)

    bursts: list[list[AuthEvent]] = []
    i = 0
    n = len(ordered)
    while i < n:
        window_end = ordered[i].timestamp + window
        j = i
        while j < n and ordered[j].timestamp <= window_end:
            j += 1           # ordered[i:j] are all events within window_minutes of ordered[i]
        if(j - i) >= threshold:
            bursts.append(ordered[i:j])
            i = j            #jump past this burst
        else:
            i += 1           #no burst starting here
    return bursts

def _severity_for(count: int) -> str:
    """5-9 attempts in the window = medium, 10+ = high (ceiling)."""
    if count >= 10:
        return "high"
    return "medium"

def detect_brute_force(events: list[AuthEvent], window_minutes: int = 5, threshold: int = 5) -> list[AuthDetection]:
    """Flag bursts of failed logins from a single IP as T1110 Brute Force."""
    detections: list[AuthDetection] = []

    for ip, attempts in group_failed_attempts_by_ip(events).items():
        for burst in find_bursts(attempts, window_minutes, threshold):
            usernames = sorted({e.user for e in burst if e.user})

            # One username = targeted guessing; many (or none parsed) = None
            user = usernames[0] if len(usernames) == 1 else None

            if user:
                target = f"user '{user}'"
            elif usernames:
                target = f"{len(usernames)} usernames ({', '.join(usernames)})"
            else:
                target = "unknown usernames"

            detections.append(AuthDetection(
                technique="Brute Force",
                mitre_id="T1110",
                severity=_severity_for(len(burst)),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                user=user,
                source_ip=ip,
                evidence=burst,
                description=(f"{len(burst)} failed login attempts from {ip} "
                             f"within {window_minutes} min targeting {target}"),
            ))

    return detections



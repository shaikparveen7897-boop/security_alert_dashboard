import random
import uuid
from datetime import datetime, timedelta, timezone

# Pools for normal activity
KNOWN_USERS = [
    "alex.morgan", "sarah.dev", "admin.james", "dev.team", 
    "ops.user", "chen.lead", "taylor.sec", "sam.user",
    "mira.patel", "david.k"
]

FAMILIAR_IPS = [
    {"ip": "192.168.1.45", "country": "US - Internal LAN"},
    {"ip": "10.0.4.12", "country": "US - HQ Network"},
    {"ip": "172.16.0.88", "country": "US - VPN Gateway"},
    {"ip": "203.0.113.15", "country": "United States"},
    {"ip": "198.51.100.42", "country": "United States"},
    {"ip": "81.2.234.11", "country": "United Kingdom"},
    {"ip": "194.12.1.90", "country": "Germany"}
]

FAIL_REASONS = ["invalid_password", "unknown_user", "account_locked", "mfa_timeout"]

# Attack profiles for initial clusters and live simulations
ATTACK_PROFILES = [
    {"ip": "185.220.101.5", "country": "Russia", "target": "admin.james"},
    {"ip": "193.56.29.18", "country": "China", "target": "sarah.dev"},
    {"ip": "45.142.212.61", "country": "Netherlands", "target": "chen.lead"},
    {"ip": "103.251.16.89", "country": "Vietnam", "target": "ops.user"},
    {"ip": "185.191.171.3", "country": "Romania", "target": "admin.james"},
    {"ip": "91.240.118.122", "country": "Ukraine", "target": "taylor.sec"},
    {"ip": "190.14.89.21", "country": "Brazil", "target": "dev.team"}
]

# Track used attack profiles so simulation gets fresh IPs
_used_attack_index = 3


def generate_initial_events():
    """
    Generates ~250-260 login events across the last 24 hours:
    - ~220 normal events (mostly success, few scattered typos)
    - 3 brute-force attack clusters (bursts of failed attempts)
    """
    now = datetime.now(timezone.utc)
    events = []

    # 1. Normal traffic generation across 24 hours (~220 events)
    for _ in range(220):
        # Random time within the last 24 hours
        minutes_ago = random.randint(1, 24 * 60)
        event_time = now - timedelta(minutes=minutes_ago)
        
        user = random.choice(KNOWN_USERS)
        ip_info = random.choice(FAMILIAR_IPS)
        
        # 92% success rate for normal traffic
        if random.random() < 0.92:
            status = "success"
            reason = "ok"
        else:
            status = "failed"
            reason = random.choice(["invalid_password", "invalid_password", "unknown_user"])
            
        events.append({
            "id": str(uuid.uuid4())[:8],
            "timestamp": event_time.isoformat(),
            "username": user,
            "ip": ip_info["ip"],
            "country": ip_info["country"],
            "status": status,
            "reason": reason
        })

    # 2. Add 3 Brute-Force Clusters
    # Cluster 1: Russia IP targeting admin.james ~ 14 attempts, 6 hours ago
    events.extend(_generate_cluster(
        profile=ATTACK_PROFILES[0],
        count=14,
        start_time=now - timedelta(hours=6, minutes=15),
        window_minutes=4
    ))

    # Cluster 2: China IP targeting sarah.dev ~ 10 attempts, 3 hours ago
    events.extend(_generate_cluster(
        profile=ATTACK_PROFILES[1],
        count=10,
        start_time=now - timedelta(hours=3, minutes=40),
        window_minutes=3
    ))

    # Cluster 3: Netherlands IP targeting chen.lead ~ 12 attempts, 45 minutes ago
    events.extend(_generate_cluster(
        profile=ATTACK_PROFILES[2],
        count=12,
        start_time=now - timedelta(minutes=45),
        window_minutes=5
    ))

    # Sort all events chronologically (oldest to newest)
    events.sort(key=lambda x: x["timestamp"])
    return events


def _generate_cluster(profile, count, start_time, window_minutes):
    """Helper to generate a rapid cluster of failed login attempts."""
    cluster_events = []
    for i in range(count):
        # Spread attempts closely within the window
        offset_seconds = random.randint(0, window_minutes * 60)
        event_time = start_time + timedelta(seconds=offset_seconds)
        
        reason = "invalid_password" if i < count - 2 else random.choice(["invalid_password", "account_locked"])
        
        cluster_events.append({
            "id": str(uuid.uuid4())[:8],
            "timestamp": event_time.isoformat(),
            "username": profile["target"],
            "ip": profile["ip"],
            "country": profile["country"],
            "status": "failed",
            "reason": reason
        })
    return cluster_events


def simulate_attack():
    """
    Simulates a fresh live attack burst (10-15 failed attempts) from a new IP
    occurring right now (in the last 1-2 minutes).
    """
    global _used_attack_index
    now = datetime.now(timezone.utc)
    
    # Pick profile, wrap around if needed
    profile = ATTACK_PROFILES[_used_attack_index % len(ATTACK_PROFILES)]
    _used_attack_index += 1
    
    # Generate 10 to 15 rapid failed attempts in the last 2 minutes
    attack_count = random.randint(10, 15)
    new_events = _generate_cluster(
        profile=profile,
        count=attack_count,
        start_time=now - timedelta(minutes=1, seconds=30),
        window_minutes=1
    )
    
    # Sort new events chronologically
    new_events.sort(key=lambda x: x["timestamp"])
    return new_events


# --------------------------------------------------------------------
# Live demo: the "monitored system" login form.
# This is a separate, unprotected page representing the target system
# being watched by Sentry (not the Sentry dashboard itself). Every real
# attempt made there - success or intentional failure - is logged as a
# genuine event so it shows up on the dashboard immediately, for a live
# presentation demo.
# --------------------------------------------------------------------

# Fixed demo password for every known user, so presenters can log in
# "correctly" as well as intentionally get it wrong.
DEMO_SYSTEM_PASSWORD = "Demo@123"


def record_manual_login(username, password, ip_address):
    """
    Validates a manually-submitted login attempt against the demo system
    and builds the corresponding event. Returns (event_dict, success_bool).
    """
    username = (username or "").strip()
    now = datetime.now(timezone.utc)

    if username in KNOWN_USERS and password == DEMO_SYSTEM_PASSWORD:
        status = "success"
        reason = "ok"
    elif username in KNOWN_USERS:
        status = "failed"
        reason = "invalid_password"
    else:
        status = "failed"
        reason = "unknown_user"

    event = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": now.isoformat(),
        "username": username or "(blank)",
        "ip": ip_address or "127.0.0.1",
        "country": "Local Network",
        "status": status,
        "reason": reason,
    }
    return event, status == "success"

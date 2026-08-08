from datetime import datetime, timedelta, timezone


def _parse_dt(ts_str):
    """Helper to convert ISO format timestamp string to datetime with UTC timezone."""
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def detect_suspicious_ips(events):
    """
    Detects IPs with 5 or more failed login attempts within a 15-minute sliding window.
    Returns a list of flagged IP objects sorted by risk level and failed count (highest first).
    """
    # Group failed events by IP
    failed_by_ip = {}
    ip_countries = {}

    for event in events:
        ip = event["ip"]
        ip_countries[ip] = event["country"]
        
        if event["status"] == "failed":
            if ip not in failed_by_ip:
                failed_by_ip[ip] = []
            failed_by_ip[ip].append(event)

    flagged_ips = []

    for ip, failed_events in failed_by_ip.items():
        # Sort failed events by timestamp
        failed_events.sort(key=lambda x: _parse_dt(x["timestamp"]))
        
        # Check for 5+ failures within a 15-minute sliding window
        is_suspicious = False
        max_window_count = 0
        
        for i in range(len(failed_events)):
            start_dt = _parse_dt(failed_events[i]["timestamp"])
            window_end = start_dt + timedelta(minutes=15)
            
            count_in_window = sum(
                1 for e in failed_events[i:] 
                if _parse_dt(e["timestamp"]) <= window_end
            )
            
            if count_in_window > max_window_count:
                max_window_count = count_in_window
                
            if count_in_window >= 5:
                is_suspicious = True

        if is_suspicious:
            total_failed = len(failed_events)
            usernames = sorted(list(set(e["username"] for e in failed_events)))
            first_ts = failed_events[0]["timestamp"]
            last_ts = failed_events[-1]["timestamp"]
            
            risk_level = "critical" if total_failed >= 12 else "high"
            
            flagged_ips.append({
                "ip": ip,
                "country": ip_countries.get(ip, "Unknown"),
                "failed_count": total_failed,
                "window_burst_count": max_window_count,
                "usernames_targeted": usernames,
                "first_attempt": first_ts,
                "last_attempt": last_ts,
                "risk_level": risk_level
            })

    # Sort flagged IPs by risk ("critical" first), then by failed count descending
    flagged_ips.sort(key=lambda x: (0 if x["risk_level"] == "critical" else 1, -x["failed_count"]))
    return flagged_ips


def summary(events):
    """
    Calculates overall metrics summary:
    - total events
    - failed count
    - success count
    - unique users
    - unique IPs
    - count of suspicious IPs
    """
    total = len(events)
    failed = sum(1 for e in events if e["status"] == "failed")
    success = total - failed
    
    unique_users = len(set(e["username"] for e in events))
    unique_ips = len(set(e["ip"] for e in events))
    
    suspicious_ips = detect_suspicious_ips(events)
    suspicious_count = len(suspicious_ips)

    return {
        "total_events": total,
        "failed_count": failed,
        "success_count": success,
        "unique_users": unique_users,
        "unique_ips": unique_ips,
        "suspicious_ip_count": suspicious_count,
        "failed_percentage": round((failed / total * 100), 1) if total > 0 else 0
    }


def hourly_timeline(events, hours=24):
    """
    Groups events into hourly buckets for the last 24 hours.
    Returns:
    {
        "labels": ["14:00", "15:00", ...],
        "success": [10, 12, ...],
        "failed": [2, 14, ...]
    }
    """
    now = datetime.now(timezone.utc)
    # Align current hour boundary
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    
    # Create hourly buckets for last 24 hours
    buckets = []
    labels = []
    
    for i in range(hours - 1, -1, -1):
        bucket_start = current_hour - timedelta(hours=i)
        bucket_end = bucket_start + timedelta(hours=1)
        buckets.append({
            "start": bucket_start,
            "end": bucket_end,
            "label": bucket_start.strftime("%H:00"),
            "success": 0,
            "failed": 0
        })
        labels.append(bucket_start.strftime("%H:00"))

    # Map events into buckets
    for event in events:
        event_dt = _parse_dt(event["timestamp"])
        for bucket in buckets:
            if bucket["start"] <= event_dt < bucket["end"]:
                if event["status"] == "success":
                    bucket["success"] += 1
                else:
                    bucket["failed"] += 1
                break

    return {
        "labels": labels,
        "success": [b["success"] for b in buckets],
        "failed": [b["failed"] for b in buckets]
    }


def filter_events_by_range(events, start_iso=None, end_iso=None):
    """
    Returns only the events whose timestamp falls within [start_iso, end_iso].
    Either bound can be omitted to leave that side open. Used by the report
    export endpoints so a user can download results for a specific window
    instead of the entire dataset.
    """
    if not start_iso and not end_iso:
        return events

    start_dt = _parse_dt(start_iso) if start_iso else None
    end_dt = _parse_dt(end_iso) if end_iso else None

    filtered = []
    for e in events:
        e_dt = _parse_dt(e["timestamp"])
        if start_dt and e_dt < start_dt:
            continue
        if end_dt and e_dt > end_dt:
            continue
        filtered.append(e)
    return filtered


def recent_alerts(events, limit=25):
    """
    Returns a time-ordered feed (newest first) of individual failed-login events
    belonging to any currently-flagged suspicious IP.
    """
    flagged_ips_data = detect_suspicious_ips(events)
    flagged_ip_map = {item["ip"]: item["risk_level"] for item in flagged_ips_data}

    # Filter failed events belonging to flagged IPs
    alerts = []
    for event in events:
        if event["status"] == "failed" and event["ip"] in flagged_ip_map:
            alert_entry = dict(event)
            alert_entry["risk_level"] = flagged_ip_map[event["ip"]]
            alerts.append(alert_entry)

    # Sort newest first
    alerts.sort(key=lambda x: _parse_dt(x["timestamp"]), reverse=True)
    return alerts[:limit]

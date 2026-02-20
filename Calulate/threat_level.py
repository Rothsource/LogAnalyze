from datetime import datetime

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]

def parse_timestamp(ts_str):
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None

def get_status(score):
    if score >= 0.6:
        return "CRITICAL"
    elif score >= 0.3:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def analyze_bruteforce(normalized_data):
    extracted, reverse_map = normalized_data

    ip_col        = reverse_map.get('ip')
    status_col    = reverse_map.get('status')
    timestamp_col = reverse_map.get('timestamp')
    username_col  = reverse_map.get('username')

    if not ip_col or not status_col:
        print("Could not find IP or status column")
        return {}

    # Group by IP
    ip_data = {}
    for entry in extracted:
        ip        = entry.get(ip_col,     'Unknown').strip()
        status    = entry.get(status_col, 'Unknown').strip().upper()
        timestamp = entry.get(timestamp_col, None) if timestamp_col else None
        username  = entry.get(username_col,  None) if username_col  else None

        if ip not in ip_data:
            ip_data[ip] = {
                'total'     : 0,
                'failed'    : 0,
                'success'   : 0,
                'timestamps': [],
                'timeline'  : []
            }

        ip_data[ip]['total'] += 1

        if status == 'SUCCESS':
            ip_data[ip]['success'] += 1
        elif status == 'FAILED':
            ip_data[ip]['failed']  += 1

        if timestamp:
            parsed = parse_timestamp(str(timestamp))
            if parsed:
                ip_data[ip]['timestamps'].append(parsed)

            # Build timeline entry
            timeline_entry = {"timestamp": str(timestamp), "status": status}
            if username:
                timeline_entry["username"] = username
            ip_data[ip]['timeline'].append(timeline_entry)

    # Calculate score and build result
    result = {}
    for ip, data in ip_data.items():
        total   = data['total']
        failed  = data['failed']
        success = data['success']
        times   = sorted(data['timestamps'])

        # Factor 1 - Failed Rate
        failed_rate = failed / total if total > 0 else 0.0

        # Factor 2 - Frequency per minute
        frequency = 0.0
        if len(times) >= 2:
            duration_minutes = (times[-1] - times[0]).total_seconds() / 60
            frequency = total / duration_minutes if duration_minutes > 0 else float(total)

        frequency_normalized = min(frequency / 10, 1.0)

        # Factor 3 - Success after many fails
        success_after_fail = 1.0 if (failed >= 5 and success >= 1) else 0.0

        score = (
            failed_rate          * 0.4 +
            frequency_normalized * 0.4 +
            success_after_fail   * 0.2
        )

        result[ip] = {
            "first_seen"        : str(times[0])  if times else 'Unknown',
            "last_seen"         : str(times[-1]) if times else 'Unknown',
            "threat_level"      : get_status(score),
            "likelihood"        : str(round(score * 100, 1)),
            "attempts_timeline" : data['timeline']
        }

    return result  
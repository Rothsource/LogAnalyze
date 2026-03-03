"""
Brute-Force Attack Analysis Module
Analyzes login patterns to detect potential brute-force attacks
"""

from datetime import datetime

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",  # Microseconds support
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]

def parse_timestamp(ts_str):
    """Parse timestamp string to datetime object"""
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def get_status(likelihood):
    """
    Determine threat level based on likelihood percentage
    
    Args:
        likelihood: Brute-force likelihood (0-100)
    
    Returns:
        'CRITICAL', 'SUSPICIOUS', or 'NORMAL'
    """
    if likelihood >= 70:
        return "CRITICAL"
    elif likelihood >= 40:
        return "SUSPICIOUS"
    else:
        return "NORMAL"


def analyze_bruteforce(normalized_data):
    """
    Analyze login attempts to detect brute-force attacks
    
    Args:
        normalized_data: Tuple of (extracted_data, reverse_map)
    
    Returns:
        Dictionary with IP addresses as keys and analysis results as values
    """
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

    # Calculate likelihood and build result
    result = {}
    for ip, data in ip_data.items():
        total   = data['total']
        failed  = data['failed']
        success = data['success']
        times   = sorted(data['timestamps'])

        # ========================================
        # CALCULATE ATTEMPTS PER SECOND
        # ========================================
        
        attempts_per_second = 0.0
        
        if len(times) >= 2:
            duration_seconds = (times[-1] - times[0]).total_seconds()
            
            if duration_seconds > 0:
                # Normal case: Calculate rate
                attempts_per_second = total / duration_seconds
            else:
                # All attempts in same second (duration = 0)
                attempts_per_second = float(total)
        
        # Round to 2 decimal places
        attempts_per_second = round(attempts_per_second, 2)

        # ========================================
        # LIKELIHOOD CALCULATION
        # ========================================
        
        likelihood = 0
        
        # Factor 1: Failed Attempts Count (40% weight)
        if failed >= 15:
            failed_score = 100
        elif failed >= 10:
            failed_score = 85
        elif failed >= 5:
            failed_score = 60
        elif failed >= 3:
            failed_score = 35
        elif failed >= 2:
            failed_score = 15
        else:
            failed_score = 5
        
        # Factor 2: Failure Rate (30% weight)
        failure_rate = (failed / total * 100) if total > 0 else 0
        
        if failure_rate >= 90:
            rate_score = 100
        elif failure_rate >= 70:
            rate_score = 75
        elif failure_rate >= 50:
            rate_score = 50
        else:
            rate_score = failure_rate / 2
        
        # Factor 3: Attempt Frequency (20% weight)
        frequency_score = 0
        if len(times) >= 2:
            duration_seconds = (times[-1] - times[0]).total_seconds()
            if duration_seconds > 0:
                calc_attempts_per_second = total / duration_seconds
                
                if calc_attempts_per_second >= 1:
                    frequency_score = 100
                elif calc_attempts_per_second >= 0.5:
                    frequency_score = 80
                elif calc_attempts_per_second >= 0.1:
                    frequency_score = 50
                else:
                    frequency_score = 20
            else:
                frequency_score = 100
        
        # Factor 4: Success After Failures (10% weight)
        success_after_fail_score = 0
        if failed >= 5 and success >= 1:
            success_after_fail_score = 100
        elif failed >= 3 and success >= 1:
            success_after_fail_score = 50
        
        # Weighted calculation
        likelihood = (
            failed_score              * 0.40 +
            rate_score                * 0.30 +
            frequency_score           * 0.20 +
            success_after_fail_score  * 0.10
        )
        
        # Round to 1 decimal place
        likelihood = round(likelihood, 1)
        
        # Ensure within bounds
        likelihood = min(max(likelihood, 0), 100)

        # ========================================
        # BUILD RESULT
        # ========================================

        result[ip] = {
            "first_seen"         : str(times[0])  if times else 'Unknown',
            "last_seen"          : str(times[-1]) if times else 'Unknown',
            "threat_level"       : get_status(likelihood),
            "likelihood"         : str(likelihood),
            "attempts_per_second": attempts_per_second,  # ← NEW FIELD
            "attempts_timeline"  : data['timeline']
        }

    return result
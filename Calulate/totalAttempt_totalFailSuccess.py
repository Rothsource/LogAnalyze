def summarize_logs(normalized_data):
    extracted, reverse_map = normalized_data

    status_col = reverse_map.get('status')
    ip_col     = reverse_map.get('ip')

    if not status_col or not ip_col:
        print("⚠️  Could not find status or IP column")
        return {}

    ip_summary = {}
    for entry in extracted:
        ip     = entry.get(ip_col,     'Unknown').strip()
        status = entry.get(status_col, 'Unknown').strip().upper()

        if ip not in ip_summary:
            ip_summary[ip] = {'total': 0, 'success': 0, 'failed': 0}

        ip_summary[ip]['total'] += 1
        if status == 'SUCCESS':
            ip_summary[ip]['success'] += 1
        elif status == 'FAILED':
            ip_summary[ip]['failed']  += 1

    return ip_summary  
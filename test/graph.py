import matplotlib.pyplot as plt
from datetime import datetime
from collections import defaultdict
import matplotlib.dates as mdates

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",     
    "%Y-%m-%dT%H:%M:%S.%fZ",     
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]

def parse_timestamp(ts_str):
    """Parse timestamp string into datetime object"""
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None

def create_line_graph(normalized_data, output_filename="attempts_timeline.png"):
    
    extracted, reverse_map = normalized_data
    
    ip_col        = reverse_map.get('ip')
    timestamp_col = reverse_map.get('timestamp')
    
    if not ip_col or not timestamp_col:
        print("⚠️  Could not find IP or timestamp column")
        return
    
    ip_timeline = defaultdict(list)
    
    for entry in extracted:
        ip        = entry.get(ip_col, 'Unknown').strip()
        timestamp = entry.get(timestamp_col, None)
        
        if timestamp:
            parsed_time = parse_timestamp(str(timestamp))
            if parsed_time:
                ip_timeline[ip].append(parsed_time)
    
    if not ip_timeline:
        print("⚠️  No valid timestamp data found")
        return

    for ip in ip_timeline:
        ip_timeline[ip].sort()

    num_ips = len(ip_timeline)
    
    if num_ips == 1:
        fig, ax = plt.subplots(figsize=(14, 7))
        axes = [ax]
    else:
        cols = 2
        rows = (num_ips + cols - 1) // cols
        fig, axes = plt.subplots(rows, cols, figsize=(16, 5 * rows))
        axes = axes.flatten()
    
    for idx, (ip, times) in enumerate(ip_timeline.items()):

        attempts = list(range(1, len(times) + 1))
        
        if len(times) >= 2:
            duration = (times[-1] - times[0]).total_seconds()
            rate = len(times) / duration if duration > 0 else len(times)
            rate_text = f"Rate: {rate:.2f} attempts/sec"
        else:
            rate_text = "Rate: N/A"
        
        axes[idx].plot(times, attempts, '-', color='#3498db', linewidth=2.5, marker='o', markersize=4)

        axes[idx].set_xlabel('Time', fontsize=12, weight='bold')
        axes[idx].set_ylabel('Cumulative Attempts', fontsize=12, weight='bold')
        axes[idx].set_title(f'IP: {ip}\nTotal: {len(times)} attempts | {rate_text}', 
                           fontsize=13, weight='bold')
        axes[idx].grid(True, alpha=0.3, linestyle='--')

        has_microseconds = any(t.microsecond > 0 for t in times)
        
        if has_microseconds:
            axes[idx].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S.%f'))
        else:
            axes[idx].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

        plt.setp(axes[idx].xaxis.get_majorticklabels(), rotation=45, ha='right')

    for idx in range(num_ips, len(axes)):
        axes[idx].axis('off')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"✅ Timeline graph saved: {output_filename}")
    plt.show()
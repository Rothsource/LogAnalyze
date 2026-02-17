import csv
import json

REQUIRED_COLUMNS = ['ip', 'ipv6', 'timestamp', 'status', 'os']

COLUMN_WIDTHS = {
    'ip'       : 18,
    'ipv6'     : 40,
    'timestamp': 25,
    'status'   : 12,
    'os'       : 20,
    'default'  : 18
}

COLUMN_ALIASES = {
    # IP
    'ip'                        : 'ip',
    'ip_address'                : 'ip',
    'ipaddress'                 : 'ip',
    'ipv4'                      : 'ip',
    'ipv4_address'              : 'ip',
    'session_ip_address'        : 'ip',
    'session_ipaddress'         : 'ip',
    'user_ip'                   : 'ip',

    # IPv6
    'ipv6'                      : 'ipv6',
    'ipv6_address'              : 'ipv6',
    'ip6'                       : 'ipv6',
    'ip_v6'                     : 'ipv6',
    'session_ipv6'              : 'ipv6',

    # Timestamp
    'timestamp'                 : 'timestamp',
    'time'                      : 'timestamp',
    'datetime'                  : 'timestamp',
    'date'                      : 'timestamp',
    'log_time'                  : 'timestamp',
    'event_timestamp'           : 'timestamp',
    'session_timestamp'         : 'timestamp',

    # Status
    'status'                    : 'status',
    'login_status'              : 'status',
    'result'                    : 'status',
    'event_status'              : 'status',
    'authentication_status'     : 'status',

    # OS
    'os'                        : 'os',
    'operating_system'          : 'os',
    'platform'                  : 'os',
    'system'                    : 'os',
    'metadata_os'               : 'os',
    'metadata_operating_system' : 'os',
}

# Status classification - what counts as success vs failed
SUCCESS_STATUSES = {
    'success', 'succeeded', 'ok', 'pass', 'passed', 'authorized', 
    'authenticated', 'granted', 'allowed', 'accepted', 'login_success'
}

FAILED_STATUSES = {
    'failed', 'failure', 'error', 'denied', 'rejected', 'blocked', 
    'unauthorized', 'forbidden', 'invalid', 'incorrect', 'wrong',
    'locked', 'disabled', 'expired', 'timeout', 'refused',
    'login_failed', 'authentication_failed', 'mfa_failed',
    'invalid_password', 'invalid_credentials', 'account_locked',
    'user_not_found', 'session_expired'
}

def normalize_status(status_value):
    """
    Normalize status to either SUCCESS or FAILED
    
    Args:
        status_value: raw status string from log
    
    Returns:
        'SUCCESS', 'FAILED', or original value if unclear
    """
    if not status_value or status_value == 'Can\'t Detect':
        return status_value
    
    status_lower = str(status_value).strip().lower()
    
    # Check success patterns
    if status_lower in SUCCESS_STATUSES:
        return 'SUCCESS'
    
    # Check failed patterns
    if status_lower in FAILED_STATUSES:
        return 'FAILED'
    
    # Check if contains success keywords
    if any(word in status_lower for word in ['success', 'ok', 'pass', 'grant', 'allow']):
        return 'SUCCESS'
    
    # Check if contains failure keywords
    if any(word in status_lower for word in ['fail', 'error', 'deny', 'block', 'reject', 'invalid', 'wrong']):
        return 'FAILED'
    
    # Return original if can't determine
    return status_value

def flatten_dict(d, parent_key='', sep='_'):
    """Flatten nested dict into single level"""
    items = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep=sep))
        else:
            items[new_key] = str(v) if v is not None else ''
    return items

def normalize_columns(raw_columns):
    mapping       = {}
    used_standard = set()

    for col in raw_columns:
        lower    = col.strip().lower()
        standard = COLUMN_ALIASES.get(lower)
        if standard and standard not in used_standard:
            mapping[col] = standard
            used_standard.add(standard)
        else:
            mapping[col] = lower

    return mapping

def prepare_logs(input_filename, columns=None):
    extracted   = []
    raw_columns = []

    try:
        if input_filename.endswith('.csv'):
            with open(input_filename, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                raw_columns = [
                    col for col in reader.fieldnames
                    if col is not None and col.strip() != ''
                ]
                for row in reader:
                    entry = {
                        col.strip().lower(): val
                        for col, val in row.items()
                        if col is not None and col.strip() != ''
                    }
                    extracted.append(entry)

        elif input_filename.endswith('.json'):
            with open(input_filename, 'r', encoding='utf-8') as file:
                raw_content = file.read().strip()

            data = []
            
            # Try normal JSON first
            try:
                parsed = json.loads(raw_content)
                
                # Handle wrapped list e.g. {"logs": [...]}
                if isinstance(parsed, dict):
                    list_found = False
                    for key, val in parsed.items():
                        if isinstance(val, list):
                            data = val
                            list_found = True
                            break
                    if not list_found:
                        data = [parsed]  # single object
                elif isinstance(parsed, list):
                    data = parsed
                else:
                    data = [parsed]

            # If failed, try NDJSON (one JSON object per line)
            except json.JSONDecodeError:
                print("Standard JSON failed, trying NDJSON format...")
                for line_num, line in enumerate(raw_content.splitlines(), 1):
                    line = line.strip()
                    if line:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"Skipping invalid line {line_num}: {str(e)}")
                            continue

            if not data:
                print("No valid JSON data found")
                return None

            # Flatten all nested fields
            flat_data = [flatten_dict(row) for row in data]

            raw_columns = list(flat_data[0].keys())

            for row in flat_data:
                entry = {
                    col.strip().lower(): str(val) if val is not None else ''
                    for col, val in row.items()
                }
                extracted.append(entry)

        else:
            print("Unsupported file type")
            return None

    except FileNotFoundError:
        print(f"File not found: {input_filename}")
        return None

    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    col_mapping      = normalize_columns(raw_columns)
    reverse_map      = {v: k.lower() for k, v in col_mapping.items()}

    status_col = reverse_map.get('status')
    if status_col:
        for entry in extracted:
            if status_col in entry:
                entry[status_col] = normalize_status(entry[status_col])

    found_required   = set(col_mapping.values()) & set(REQUIRED_COLUMNS)
    missing_required = set(REQUIRED_COLUMNS) - found_required

    if missing_required:
        print(f"Column(s) not found: {', '.join(sorted(missing_required))} → will show 'Can't Detect'")

    extra_columns = [
        std for std in col_mapping.values()
        if std not in REQUIRED_COLUMNS
    ]

    final_columns = REQUIRED_COLUMNS + extra_columns

    print(f"\nLoaded {len(extracted)} entries from {input_filename}")
    return extracted, reverse_map
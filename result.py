import json
from Calulate.Filter_ip                        import prepare_logs
from Calulate.totalAttempt_totalFailSuccess    import summarize_logs
from Calulate.threat_level                     import analyze_bruteforce
from analyze.pieChart import create_pie_chart, create_bruteforce_chart

file = 'log.csv'

result = prepare_logs(file)

summary    = summarize_logs(result)
# create_pie_chart(summary)
bruteforce = analyze_bruteforce(result)
create_bruteforce_chart(bruteforce)

# unified = {}
# all_ips = set(summary.keys()) | set(bruteforce.keys())

# for ip in all_ips:
#     s = summary.get(ip,    {})
#     b = bruteforce.get(ip, {})

#     unified[ip] = {
#         "total_requests"       : s.get('total',       0),
#         "failed_logins"        : s.get('failed',      0),
#         "successful_logins"    : s.get('success',     0),
#         "first_seen"           : b.get('first_seen',  'Unknown'),
#         "last_seen"            : b.get('last_seen',   'Unknown'),
#         "threat_level"         : b.get('threat_level',         'Unknown'),
#         "bruteforce_likelihood": b.get('likelihood',           '0'),
#         "attempts_timeline"    : b.get('attempts_timeline',    [])
#     }

# print(json.dumps(unified, indent=2))
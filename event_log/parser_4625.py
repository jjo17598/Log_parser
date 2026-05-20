import re

def parse_log(file_path):
    with open(file_path, 'r') as log:
        content = log.read()

    search = input('Enter the search term: ')

    events = re.split(r'(?=^Information\t)', content, flags=re.MULTILINE)

    matches = []
    for event in events:
        if search in event:
            fields = {
                'security_id':    re.search(r'Security ID:\s+(\S+)', event),
                'account_name':   re.search(r'Account Name:\s+(\S+)', event),
                'account_domain': re.search(r'Account Domain:\s+(.+)', event),
                'logon_id':       re.search(r'Logon ID:\s+(\S+)', event),
            }
            matches.append({
                'event': event.splitlines()[0].strip(),
                'security_id':    fields['security_id'].group(1)    if fields['security_id']    else 'N/A',
                'account_name':   fields['account_name'].group(1)   if fields['account_name']   else 'N/A',
                'account_domain': fields['account_domain'].group(1).strip() if fields['account_domain'] else 'N/A',
                'logon_id':       fields['logon_id'].group(1)       if fields['logon_id']       else 'N/A',
            })

    return matches

result = parse_log("event_log.log")

print("Log Summary:")
for match in result:
    print(match['event'])
    print(f"  Security ID:    {match['security_id']}")
    print(f"  Account Name:   {match['account_name']}")
    print(f"  Account Domain: {match['account_domain']}")
    print(f"  Logon ID:       {match['logon_id']}")
    print()
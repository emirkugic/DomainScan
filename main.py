import requests
import json

# VirusTotal API key
vt_api_key = 'virus-total-api-key'

# OpenCTI API key
opencti_api_key = 'opencti-api-key'

# Cisco CTR credentials
ctr_client_id = 'cisco-ctr-client-id'
ctr_client_password = 'cisco-ctr-client-password'

# Domain to query
domain = 'your-domain.com'


# Query VirusTotal
vt_url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={domain}'
response = requests.get(vt_url)
if response.status_code == 200:
    result = response.json()
    positives = result.get('positives', 0)
    if positives > 10:
        # Query OpenCTI
        opencti_url = f'https://demo.opencti.io/api/v1/stix_domain_entities?search={domain}'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {opencti_api_key}'
        }
        response = requests.get(opencti_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            print(json.dumps(result, sort_keys=False, indent=4))
        else:
            print(f'Error querying OpenCTI: {response.status_code}')
    else:
        print(f'Less than 10 hits for domain {domain} on VirusTotal')

    # Bonus task: Query Cisco AMP EDR for IP addresses
    ip_addresses = result.get('resolutions', [])[
        :3]  # Get the first 3 IP addresses
    for ip_address in ip_addresses:
        ip = ip_address['ip_address']
        ctr_url = f'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables'
        headers = {
            'Authorization': f'Bearer {ctr_client_id}:{ctr_client_password}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        data = json.dumps([{'type': 'ip', 'value': ip}])
        response = requests.post(ctr_url, headers=headers, data=data)

        if response.status_code == 200:
            result = response.json()
            print(json.dumps(result, sort_keys=False, indent=4))
        else:
            print(f'Error querying Cisco AMP EDR: {response.status_code}')

else:
    print(f'Error querying VirusTotal: {response.status_code}')

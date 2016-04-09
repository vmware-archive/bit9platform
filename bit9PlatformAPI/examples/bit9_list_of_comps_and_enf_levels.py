#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pprint import pprint
import logging, csv, os, requests
from bit9api import bit9Api

logging.basicConfig()
requests.packages.urllib3.disable_warnings()
userhome = os.path.expanduser('~')
csv_name = userhome + '/Desktop/test.csv'

server='https://bit9server.bit9se.com/'
api_key='AACB5C5F-D9B4-4694-AB9A-8640FF79D401'

bit9 = bit9Api (server, token=api_key, ssl_verify=False)
search_conditions = ['']
#search_conditions = ['uninstalled:False']

comps = bit9.search('v1/computer', search_conditions)

'''
Current enforcement level. Can be one of:
20=High (Block Unapproved)
30=Medium (Prompt Unapproved)
35=Local approval
40=Low (Monitor Unapproved)
60=None (Visibility)
80=None (Disabled)
'''

enf_dict={20:'high', 30:'medium', 35:'local_approval', 40:'low', 60:'visibility_only', 80:'agent_disabled'}

# For every found computer, write out the name, enforcement level, ip to a csv
b = open(csv_name, 'wb')
a = csv.writer(b)
a.writerow(['host','enforcement_level', 'ip_address', 'uninstalled_state', 'policyName', 'last_checkin'])
for c in comps:
    a.writerow([c['name'], enf_dict[c['enforcementLevel']], c['ipAddress'], c['uninstalled'], c['policyName'],c['lastPollDate']])
    print c['name'], enf_dict[c['enforcementLevel']], c['ipAddress'], c['uninstalled'], c['policyName'], c['lastPollDate']
b.close()
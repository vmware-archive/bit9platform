"""
This is a sample Python script for moving selected computers to different policy at a specified time.

Copyright Bit9, Inc. 2015
support@bit9.com


Disclaimer
+++++++++++++++++++
By accessing and/or using the samples scripts provided on this site (the "Scripts"), you hereby agree to the following terms:
The Scripts are exemplars provided for purposes of illustration only and are not intended to represent specific
recommendations or solutions for API integration activities as use cases can vary widely.
THE SCRIPTS ARE PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED.  BIT9 MAKES NO REPRESENTATION
OR OTHER AFFIRMATION OF FACT, INCLUDING BUT NOT LIMITED TO STATEMENTS REGARDING THE SCRIPTS' SUITABILITY FOR USE OR PERFORMANCE.
IN NO EVENT SHALL BIT9 BE LIABLE FOR SPECIAL, INCIDENTAL, CONSEQUENTIAL, EXEMPLARY OR OTHER INDIRECT DAMAGES OR FOR DIRECT
DAMAGES ARISING OUT OF OR RESULTING FROM YOUR ACCESS OR USE OF THE SCRIPTS, EVEN IF BIT9 IS ADVISED OF OR AWARE OF THE
POSSIBILITY OF SUCH DAMAGES.

Requirements
+++++++++++++++++++

- Bit9 API client (included) which requires requests Python module
- Bit9 Platform Server 7.2.1 or later
- Bit9 API Token (generated in Bit9 Console)

Required python modules can be installed using tools such as easy_install or pip, e.g.
    easy_install requests

+++++++++++++++++++++++
Please update the script with appropriate Bit9 server address and Bit9 token script.
"""

import time
from datetime import datetime
from common import bit9api

bit9 = bit9api.bit9Api(
    "https://<my server address>",  # Replace with actual Bit9 server URL
    token="<enter your Bit9 API token here>",  # Replace with actual Bit9 user token for VT integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

# Setup our arguments (these could be, for example, passed from the command line)
switchTime = "4/1/2015 8:04AM"  # When to switch policies
targetPolicyName = "sales-2"  # Target policy name
computerCondition = ['policyName:sales-1', 'ipAddress!10.0.1.*', 'deleted:false']  # Condition for computers to move

# Sleep until specified time
sleepTime = datetime.strptime(switchTime, '%m/%d/%Y %I:%M%p') - datetime.today()
if sleepTime.total_seconds()>0:
    print('Sleeping for %d seconds' % sleepTime.total_seconds())
    time.sleep(sleepTime.total_seconds())

# Find our destination policy by name
destPolicies = bit9.search('v1/policy', ['name:'+targetPolicyName])
if len(destPolicies)==0:
    raise ValueError("Cannot find destination policy "+targetPolicyName)


# Our condition is "All non-deleted computers in policy 'sales-1' that have IP address that DOES NOT start with 10.0.1
comps = bit9.search('v1/computer', computerCondition)
for c in comps:  # Move each returned computer to the local approval policy
    print("Moving computer %s (IP: %s) from policy %s to policy %s" %
          (c['name'], c['ipAddress'], c['policyName'], targetPolicyName))
    c['policyId'] = destPolicies[0]['id']
    bit9.update('v1/computer', c)


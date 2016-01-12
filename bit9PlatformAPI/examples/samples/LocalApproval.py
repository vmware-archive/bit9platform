"""
This is a sample Python script for moving selected computers to local approval for 10 minutes.

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
import sys
import os

# Include our common folder, presumably peer of current folder
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common'))
import bit9api

bit9 = bit9api.bit9Api(
    "https://localhost",  # Replace with actual Bit9 server URL
    token="<enter your Bit9 API token here>",  # Replace with actual Bit9 user token for VT integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

# Our condition is "All non-deleted computers in policy 'sales-1' that have IP address that DOES NOT start with 10.0.1
comps = bit9.search('v1/computer', ['policyName:sales-1', 'ipAddress!10.0.1.*', 'deleted:false'])
for c in comps:  # Move each returned computer to the local approval policy
    print("Moving computer %s (IP: %s) from policy %s to local approval policy" % (c['name'], c['ipAddress'], c['policyName']))
    c['localApproval'] = True
    bit9.update('v1/computer', c)

# sleep for 10 minutes
time.sleep(10*60)

for c in comps:  # Move all affected computers back to the enforcement policy
    print("Restoring computer %s back to its original policy" % (c['name']))
    c['localApproval'] = False
    bit9.update('v1/computer', c)

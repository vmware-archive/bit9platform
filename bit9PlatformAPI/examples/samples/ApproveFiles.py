"""
This is a sample Python script that locally approves all unapproved files for computers in given policy, under the specific condition

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

# Find all computers in policy 'sales-1'
comps = bit9.search('v1/computer', ['policyName:sales-1', 'deleted:false'])
for c in comps:  # For each returned computer, get list of locally unapproved files
    files = bit9.search('v1/fileInstance', ['computerId:'+str(c['id']), 'localState:1'])
    n = 0
    for f in files:  # For each returned file...
        # Get its file catalog entry to get prevalence
        fcat = bit9.retrieve('v1/fileCatalog', f['fileCatalogId'])
        if fcat['prevalence'] >= 10:  # if prevalent enough...
            f['localState'] = 2  # Approve locally
            bit9.update('v1/fileInstance', f)
            n += 1
    if n > 0:
        print("Locally approved %d files on computer %s" % (n, c['name']))


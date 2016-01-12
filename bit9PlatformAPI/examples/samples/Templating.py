"""
This is a sample Python script that demonstrates VDI templating
It waits for specific computer to show online, and then once it is offline it will create a template of it

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
import datetime
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

while True:
    # Our condition for VM image is policy='virtualized-1' and IP address=10.36.4.3.
    # As soon as it is offline, we will template it. Note that computers that are still initializing
    # cannot be templated
    comps = bit9.search('v1/computer',
                        ['policyName:virtualized-1', 'deleted:false', 'ipAddress:10.36.4.3',
                            'connected:false', 'template:false', 'initializing:false'],
                        limit=1)

    # If it did go offline, template it!
    if len(comps)>0:
        c = comps[0]
        print("VM image %s went offline. We will now make a template of it." % (c['name']))
        c['template'] = True
        c['name'] = 'My template ' + datetime.datetime.now().strftime("%B %d, %Y %I:%M%p")
        c['templateCloneCleanupMode'] = 2  # Automatic, by time
        c['templateCloneCleanupTimeScale'] = 1 # Hours
        c['templateCloneCleanupTime'] = 2  # 2 Hours
        c['templateTrackModsOnly'] = True
        bit9.update('v1/computer', c, url_params='changeTemplate=true')

    # wait 10 seconds and do another check (we might need to template it again some day)
    time.sleep(10)

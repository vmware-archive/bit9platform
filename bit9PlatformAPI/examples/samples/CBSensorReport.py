"""
This is a sample Python script that reports on CarbonBlack sensors on computers with Bit9 Platform agent

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

# Get all computers with CB sensor and group them by sensor version
compsWithCB = bit9.search('v1/computer',
        [  # This array contains our condition
            'deleted:false',  # not deleted
            'uninstalled:false',  # not uninstalled
            'lastPollDate>-7d',  # connected within last week
            'cbSensorId!0',  # with sensor installed (!=0)
            'cbSensorVersion!'  # where sensor version is not null (meaning, sensor was initialized)
        ], group_by='cbSensorVersion')  # group by sensor version
# Get count of all recently connected computers (not deleted or uninstalled)
totalComps = bit9.search('v1/computer', ['deleted:false', 'uninstalled:false', 'lastPollDate>-7d'], limit=-1)["count"]

print("Report by CB sensor version")
print("-----------------------")
if totalComps > 0:  # To avoid division by zero
    totalWithSensor = 0
    for group in compsWithCB:
        print("%-15s : %s" % (group["value"], group["count"]))
        totalWithSensor += group["count"]
    print("-----------------------")
    print("%-15s : %s" % ("Total Computers", totalComps))
    print("%-15s : %s (%2.1f %%)" % ("With Sensor", totalWithSensor, totalWithSensor * 100.0 / totalComps))


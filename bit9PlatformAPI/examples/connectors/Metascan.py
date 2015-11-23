"""
First off, I'm not a programmer so any issues that you have in running this script in your environment are not my fault!
I've borrowed HEAVILY from the script written for VirusTotal so I'm going to leave IN the disclaimer that Bit9 placed on
the original script. Hopefully this will indemnify both Bit9 and me from any issues encountered by you if you use this
script.

If you can find a better way to work any of this, go for it. I'd ask that you update the script in GitHub if you do though.
Thanks and enjoy!

-Patrick

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

- Metascan API Key

- Bit9 Platform Server 7.2.1 or later
- Bit9 API Token (generated in Bit9 Console)
- Bit9 RBAC permission enabled for 'Extend connectors through API'

Required python modules can be installed using tools such as easy_install or pip, e.g.
    easy_install requests

Configuring Connector
+++++++++++++++++++++++

Please update the script with appropriate vt_token, Bit9 server address and Bit9 token at the bottom of the script.


Start the script. No parameters are required. It will process analysis requests from teh Bit9 Platform as long as it is running.
Script execution can be terminated with ctrl+c.
"""

import requests
import datetime
import sys
import bit9api

# -------------------------------------------------------------------------------------------------
# MS connector class. Initialization where keys are specified is done at the bottom of the script
class metascanConnector(object):
    def __init__(self, bit9, ms_token=None, download_location=None):
        """ Requires:
                server -    URL to the Bit9Platform server.  Usually the same as
                            the web GUI.
                sslVerify - verify server SSL certificate
                token - this is for CLI API interface
        """

        if ms_token is None:
            raise TypeError("Missing required MetaScan authentication token.")
        #My test system does not require a API token so I'm not adding it to the JSON call
        self.ms_token = ms_token
        self.ms_url = 'http://yourMetaScanServer/metascan_rest/'
        self.bit9 = bit9
        self.polling_frequency = 30 # seconds
        self.msresults = 0
        self.msavtotal = 0

        # Global dictionary to track our MS scheduled scans. We need this since it takes MS a while to process results
        # and we don't want to keep polling MS too often
        # Any pending results will be kept here, together with next polling time
        self.scheduledScans = {}
        self.download_location = download_location.rstrip("\\")

    def start(self):
        # Register or update our connector (can be done multiple times - will be treated as update on subsequent times)
        r = self.bit9.create('v1/connector', {'name': 'MetaScan', 'analysisName': 'MetaScan',
                            'connectorVersion': '1.0', 'canAnalyze': 'true', 'analysisEnabled': 'true'})
        connectorId = str(r['id'])

        # Loop forever (until killed)
        while True:
            try:
                # Check with Bit9 Platform if we have any analysis still pending
                for i in self.bit9.retrieve("v1/pendingAnalysis", url_params="connectorId=" + connectorId):
                    self.processOneAnalysisRequest(i)
            except:
                print(sys.exc_info()[0])
                print("\n*** Exception processing requests. Will try again in %d seconds." % (self.polling_frequency))
            # Sleep N seconds, and then all over again
            time.sleep(self.polling_frequency)

    def uploadFileToMS(self, pa):
        isError = False
        if self.download_location is not None:
            # This is if we want to locally download file from Bit9
            # (in the case shared folder is not accessible)
            localFilePath = self.download_location + "\\temp.zip"
            self.bit9.retrieve_analyzed_file(pa['id'], localFilePath)
        else:
            # Easier option, if Bit9 shared folder can be accessed directly
            localFilePath = pa['uploadPath']

        dataId = None
        data = open(localFilePath, 'rb').read()
        try:
            headers = {'filename':pa['fileName']}
            r = requests.post(self.ms_url + "file", data=data, headers=headers)
            uploadResults = r.json()
            if uploadResults.get("err") == 'Failed to upload':
                isError = True
                print (uploadResults.get("err"))
            # we got MS dataId. We will need it to check status of the scan at later time
            if isError != True:
                data_id = r.json()["data_id"]
        except:
            isError = True

        if isError:
            # Report to Bit9 that we had error analyzing this file. This means we will not try analysis again.
            pa['analysisStatus'] = 4  # (status: Error)
            pa['analysisError'] = 'MetaScan returned error when attempting to send file for scanning'
        else:
            # Tell Bit9 that we are waiting for the scan to finish
            pa['analysisStatus'] = 1 # (status: Analyzing)

        # Update Bit9 status for this file
        self.bit9.update('v1/pendingAnalysis', pa)
        return dataId

    def reportResultToBit9(self, fileAnalysisId, scanResults):
        # We have results. Create our Bit9 notification
        notification = {
            'fileAnalysisId': fileAnalysisId,
            'product': 'MetaScan',
            'malwareName': '',
            'malwareType': ''
        }
        # Enumerate scan results that have detected the issue and build our
        # 'malwareName' string for the Bit9 notification
        y=scanResults.get("scan_results")
        scans = y.get("scan_details", {})
        n = 0
        for key in scans:
            s = scans[key]
            if s['scan_result_i']:
                if n != 0:
                    notification['malwareType'] += '; '
                notification['malwareName'] += '; '
                notification['malwareType'] += key + ':' + s['threat_found']
                notification['malwareName'] += s['threat_found']
                n += 1
# Let's see if it is malicious. Use some fancy heuristics...
        positivesPerc = 100 * n / self.msavtotal
        if positivesPerc > 50:
            notification['analysisResult'] = 3  # ...malicious
            notification['severity'] = 'critical';
            notification['type'] = 'malicious_file';
        elif positivesPerc > 0:
            notification['analysisResult'] = 2  # ...could be malicious
            notification['severity'] = 'high';
            notification['type'] = 'potential_risk_file';
        else:
            notification['analysisResult'] = 1  # clean!
            notification['severity'] = 'low';
            notification['type'] = 'clean_file';
        # Send notification
        self.bit9.create("v1/notification", notification)
        print("MS analysis for fileAnalysis %d completed. MS result is %d%% malware (%s). Reporting status: %s" % (fileAnalysisId, positivesPerc, notification['malwareName'], notification['type']))

    def processOneAnalysisRequest(self, pa):
        # Use md5 hash if we have one. If not, use Sha256
        fileHash = pa['md5'].strip()
        if fileHash == '':
            fileHash = pa['sha256'].strip()

        lastAttempt = None
        dataId = None
        # Check our cache if we already sent this file for scan
        if fileHash in self.scheduledScans.keys():
            lastAttempt = self.scheduledScans[fileHash]
            # Be polite and don't keep asking MS for status too often. If we already tried recently, bail
            if lastAttempt['nextCheck'] > datetime.datetime.now():
                return
            # Get our dataId we got from MS last time around
            print("Now attempting to send the data ID")
            dataId = lastAttempt['data_id']
            r = requests.get(self.ms_url + "/file/" + dataId, params={'':''})
            print("This is the URL being sent %s" % (self.ms_url + "/file/" + dataId))
            print(r)
        else:
            # we have not asked MS yet. Try with file hash
            r = requests.get(self.ms_url + "/hash/" + fileHash, params={'':''})

        r.raise_for_status()
        if r.status_code == 204:
            # no results from MS because rate limit was reached. We will try again later.
            return

        scanResults = r.json()
        x=scanResults.get("scan_results",{})
        # Check if we got results...
        self.msresults=x.get('scan_all_result_i')
        self.msavtotal=x.get('total_avs')
        if self.msresults is not None:
            # Yes, MS has them. Report results and we are done with the file
            self.reportResultToBit9(pa['id'], scanResults)
            dataId =  None
        elif scanResults.get('data_id') is not None:
            # MS already knows about the file, but scan is not complete. We got dataId for future reference
            dataId = scanResults['data_id'];
        elif pa['uploaded'] == 1:
            # We have file and now we will upload it to MS
            dataId = self.uploadFileToMS(pa)
        else:
            # if we end here, it means that MS doesn't have file, and Bit9 hasn't uploaded it yet from the agent
            # we will come back again in 30 seconds
            dataId = None

        if dataId is not None:
            # Remember dataId since MS wants use to use it for future references to the file
            # We will try again in 1 hour
            self.scheduledScans[fileHash] = {'fileID': dataId, 'nextCheck': datetime.datetime.now()
                                                                      + datetime.timedelta(0, 3600)}

# -------------------------------------------------------------------------------------------------
# Main body of the script

bit9 = bit9api.bit9Api(
    "https://yourbit9serverurl.domain.com",  # Replace with actual Bit9 server URL
    token="",  # Replace with actual Bit9 user token for integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

msConnector = metascanConnector(
    bit9,
    ms_token='123456',  # Replace with your VT key
    download_location= "C:\YourDownloadLocation"  # Replace with actual local file location. If not set,
                                # we will try to access shared folder where this file resides
)

print("\n*** MS script starting")
msConnector.start()

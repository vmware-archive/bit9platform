import requests, json, datetime, time, sys, bit9api
"""
This is a Python script for the VirusTotal Analyst Connector for Bit9 Security Platform.

Requirements
+++++++++++++++++++

- Bit9 API client (included) which requires requests Python module

- VirusTotal API Key

- Bit9 Platform Server 7.2.1 or better
- Bit9 API Token (generated in Bit9 Console)

Required python modules can be installed using tools such as easy_install or pip, e.g.
    easy_install requests

Configuring Connector
+++++++++++++++++++++++

Please update the script with appropriate vt_token, Bit9 server address and Bit9 token at the bottom of the script.


Start the script. No paramters are required. It will process analysis requests from teh Bit9 Platform as long as it is running.
Script execution can be terminated with ctrl+c.
"""

# -------------------------------------------------------------------------------------------------
# VT connector class. Initialization where keys are specified is done at the bottom of the script
class virusTotalConnector(object):
    def __init__(self, bit9, vt_token=None, download_location=None):
        """ Requires:
                server -    URL to the Bit9Platform server.  Usually the same as
                            the web GUI.
                sslVerify - verify server SSL certificate
                token - this is for CLI API interface
        """

        if vt_token is None:
            raise TypeError("Missing required VT authentication token.")
        self.vt_token = vt_token
        self.vt_url = 'https://www.virustotal.com/vtapi/v2'
        self.bit9 = bit9
        self.polling_frequency = 30 # seconds

        # Global dictionary to track our VT scheduled scans. We need this since it takes VT a while to process results
        # and we don't want to keep polling VT too often
        # Any pending results will be kept here, together with next polling time
        self.scheduledScans = {}
        self.download_location = download_location.rstrip("\\")

    def start(self):
        # Register or update our connector (can be done multiple times - will be treated as update on subsequent times)
        r = self.bit9.create('connector', {'name': 'VirusTotal', 'analysisName': 'VirusTotal',
                            'connectorVersion': '1.0', 'canAnalyze': 'true', 'analysisEnabled': 'true'})
        connectorId = str(r['id'])

        # Loop forever (until killed)
        while True:
            try:
                # Check with Bit9 Platform if we have any analysis still pending
                for i in self.bit9.read("pendingAnalysis", url_params="connectorId=" + connectorId):
                    self.processOneAnalysisRequest(i)
            except:
                print(sys.exc_info()[0])
                print("\n*** Exception processing requests. Will try again in %d seconds." % (self.polling_frequency))
            # Sleep N seconds, and then all over again
            time.sleep(self.polling_frequency)

    def uploadFileToVT(self, pa):
        if self.download_location is not None:
            # This is if we want to locally download file from Bit9
            # (in the case shared folder is not accessible)
            localFilePath = self.download_location + "\\temp.zip"
            self.bit9.retrieve_analyzed_file(pa['id'], localFilePath)
        else:
            # Easier option, if Bit9 shared folder can be accessed directly
            localFilePath = pa['uploadPath']

        scanId = None
        files = {'file': open(localFilePath, 'rb')}
        try:
            r = requests.post(self.vt_url + "/file/scan", files=files, params={'apikey': self.vt_token})
            isError = (r.status_code >= 400)
            # we got VT scanId. We will need it to check status of the scan at later time
            if r.status_code == 200:
                scanId = r.json()['scan_id']
        except:
            isError = True

        if isError:
            # Report to Bit9 that we had error analyzing this file. This means we will not try analysis again.
            pa['analysisStatus'] = 4  # (status: Error)
            pa['analysisError'] = 'VirusTotal returned error when attempting to send file for scanning'
        else:
            # Tell Bit9 that we are waiting for the scan to finish
            pa['analysisStatus'] = 1 # (status: Analyzing)

        # Update Bit9 status for this file
        self.bit9.update('pendingAnalysis', pa)
        return scanId

    def reportResultToBit9(self, fileAnalysisId, scanResults):
        # We have results. Create our Bit9 notification
        notification = {
            'fileAnalysisId': fileAnalysisId,
            'product': 'VirusTotal',
            'malwareName': '',
            'malwareType': ''
        }
        # Let's see if it is malicious. Use some fancy heuristics...
        positivesPerc = 100 * scanResults.get('positives') / scanResults.get('total')
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
        notification['externalUrl'] = scanResults.get('permalink')

        # Enumerate scan results that have detected the issue and build our
        # 'malwareName' string for the Bit9 notification
        scans = scanResults.get("scans", {})
        n = 0
        for key in scans:
            s = scans[key]
            if s['detected']:
                if n > 4:
                    notification['malwareType'] += '...'
                    notification['malwareName'] += '...'
                    break
                elif n > 0:
                    notification['malwareType'] += '; '
                    notification['malwareName'] += '; '
                notification['malwareType'] += key + ':' + s['result']
                notification['malwareName'] += s['result']
                n += 1
        # Send notification
        self.bit9.create("notification", notification)

    def processOneAnalysisRequest(self, pa):
        # Use md5 hash if we have one. If not, use Sha256
        fileHash = pa['md5'].strip()
        if fileHash == '':
            fileHash = pa['sha256'].strip()

        lastAttempt = None
        scanId = None
        # Check our cache if we already sent this file for scan
        if fileHash in self.scheduledScans.keys():
            lastAttempt = self.scheduledScans[fileHash]
            # Be polite and don't keep asking VT for status too often. If we already tried recently, bail
            if lastAttempt['nextCheck'] > datetime.datetime.now():
                return
            # Get our scanId we got from VT last time around
            scanId = lastAttempt['scanId']
            r = requests.get(self.vt_url + "/file/report", params={'resource': scanId, 'apikey': self.vt_token})
        else:
            # we have not asked VT yet. Try with file hash
            r = requests.get(self.vt_url + "/file/report", params={'resource': fileHash, 'apikey': self.vt_token})

        r.raise_for_status()
        if r.status_code == 204:
            # no results from VT because rate limit was reached. We will try again later.
            return

        scanResults = r.json()
        # Check if we got results...
        if scanResults.get('positives') is not None:
            # Yes, VT has them. Report results and we are done with the file
            self.reportResultToBit9(pa['id'], scanResults)
            scanId =  None
        elif scanResults.get('scan_id') is not None:
            # VT already knows about the file, but scan is not complete. We got scanId for future reference
            # Let's remember that and try again in 1 hour (per VT best practices)
            scanId = scanResults['scan_id'];
        elif pa['uploaded'] == 1:
            # We have file and now we will upload it to VT
            scanId = self.uploadFileToVT(pa)
        else:
            # if we end here, it means that VT doesn't have file, and Bit9 hasn't uploaded it yet from the agent
            # we will come back again in 30 seconds
            scanId = None

        if scanId is not None:
            # Remember scanId since VT wants use to use it for future references to the file
            # We will try again in 1 hour (per VT best practices)
            self.scheduledScans[fileHash] = {'scanId': scanId, 'nextCheck': datetime.datetime.now()
                                                                      + datetime.timedelta(0, 3600)}

# -------------------------------------------------------------------------------------------------
# Main body of the script

bit9 = bit9api.bit9Api(
    "https://<my server address>",  # Replace with actual Bit9 server URL
    token="<enter your Bit9 API token here>",  # Replace with actual Bit9 user token for VT integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

vtConnector = virusTotalConnector(
    bit9,
    vt_token='<enter your VT API key here>',  # Replace with your VT key
    download_location = "c:\\test"   # Replace with actual local file location. If not set,
                                # we will try to access shared folder where this file resides
)

print("\n*** VT script starting")
vtConnector.start()

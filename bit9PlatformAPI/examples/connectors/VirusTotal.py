"""
This is a Python script for the VirusTotal Analyst Connector for Bit9 Security Platform.

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

- VirusTotal API Key

- Bit9 Platform Server 7.2.1 or later
- Bit9 API Token (generated in Bit9 Console)

Required python modules can be installed using tools such as easy_install or pip, e.g.
    easy_install requests

Configuring Connector
+++++++++++++++++++++++

Please update the script with appropriate vt_token, Bit9 server address and Bit9 token at the bottom of the script.


Start the script. No parameters are required. It will process analysis requests from the Bit9 Platform as long as it is running.
Script execution can be terminated with ctrl+c.
"""

import requests
import datetime
import time
import sys
import os
import zipfile
import tempfile
import shutil

import logging
log = logging.getLogger(__name__)


# -------------------------------------------------------------------------------------------------
# VT connector class. Initialization where keys are specified is done at the bottom of the script
class virusTotalConnector(object):
    def __init__(self, bit9, vt_token=None, connector_name='VirusTotal', allow_uploads=True, download_location=None):
        """ Description of parameters:
                bit9 - bit9api object
                vt_token - API token provided by VirusTotal
                connector_name - name of the connector. Defaults to 'VirusTotal'
                allow_uploads - True to allow uploads of binaries to the VirusTotal servers. If set to False,
                    only hash lookups will be done to te virusTotal
                    Note: In case when allow_uploads is set to False  AND VirusTotal does not recognize the hash,
                    associated Bit9 file analysis request will be cancelled
                download_location - location that will hold the files uploaded from the Bit9 platform
                    before they are sent to the VirusTotal. It is required only if allow_uploads is set to True
                    If set to None, script will attempt to files uploaded from agents on the remote share. If
                    remote share is unavailable, associated Bit9 file analysis request will end in Error state

        """

        if vt_token is None:
            raise TypeError("Missing required VT authentication token.")
        self.vt_token = vt_token
        self.vt_url = 'https://www.virustotal.com/vtapi/v2'
        self.bit9 = bit9
        self.polling_frequency = 30 # seconds
        self.connector_name = connector_name

        # Global dictionary to track our VT scheduled scans. We need this since it takes VT a while to process results
        # and we don't want to keep polling VT too often
        # Any pending results will be kept here, together with next polling time
        self.scheduledScans = {}

        # Download location.
        self.download_location = None
        if download_location:
            self.download_location = os.path.realpath(download_location)
            if not os.path.exists(download_location):
                os.makedirs(download_location)
        self.allow_uploads = allow_uploads

    def start(self):
        # Register or update our connector (can be done multiple times - will be treated as update on subsequent times)
        r = self.bit9.create('v1/connector', {'name': self.connector_name, 'analysisName': self.connector_name,
                            'connectorVersion': '1.0', 'canAnalyze': 'true', 'analysisEnabled': 'true'})

        if not r:
            log.fatal("Could not create connector on the Bit9 server. Are the bit9 server URL and API token correct?")
            return

        connectorId = str(r['id'])

        # Loop forever (until killed)
        while True:
            try:
                # Check with Bit9 Platform if we have any analysis still pending
                for i in self.bit9.retrieve("v1/pendingAnalysis", url_params="connectorId=" + connectorId):
                    self.processOneAnalysisRequest(i)
            except Exception as e:
                log.exception("Error during processing. Will try again in %d seconds." % (self.polling_frequency,))
            # Sleep N seconds, and then all over again
            time.sleep(self.polling_frequency)

    # This function unregisters the connector and deletes all its data
    def unregister(self):
        # Unregister our connector
        r = self.bit9.search('v1/connector', ['name:'+self.connector_name])
        if len(r)>0:
            log.info("Unregistering connector %s and deleting all its data" % self.connector_name)
            self.bit9.delete('v1/connector', r[0])

    def uploadFileToVT(self, pa):
        scanId = None

        if self.download_location:
            # This is if we want to locally download file from Bit9
            # (in the case shared folder is not accessible)
            localFilePath = self.download_location + "\\temp.zip"
            self.bit9.retrieve_analyzed_file(pa['id'], localFilePath)
        else:
            # Easier option, if Bit9 shared folder can be accessed directly
            localFilePath = pa['uploadPath']

        try:
            # the zip file returned by Bit9 should have only one directory entry in it,
            # the file to be analyzed. Extract that file for analysis. This is done since
            # Bit9 retains the original file path information in the zip file, which may
            # include sensitive/personal information that we don't want to disclose to VT.
            z = zipfile.ZipFile(localFilePath)
            infp = z.open(z.filelist[0])
            outfp = tempfile.NamedTemporaryFile()
            shutil.copyfileobj(infp, outfp)
        except Exception as e:
            pa['analysisStatus'] = 4  # (status: Error)
            pa['analysisError'] = 'Received error when attempting to unzip file from Bit9: %s' % str(e)
            # Update Bit9 status for this file
            self.bit9.update('v1/pendingAnalysis', pa)
            log.exception("Could not unzip file from Bit9 for analysis of %s" % pa)
            return scanId

        outfp.seek(0)
        files = {'file': outfp}
        try:
            r = requests.post(self.vt_url + "/file/scan", files=files, params={'apikey': self.vt_token})
            isError = (r.status_code >= 400)
            # we got VT scanId. We will need it to check status of the scan at later time
            if r.status_code == 200:
                scanId = r.json()['scan_id']
        except:
            log.exception("Could not send file %s to VirusTotal" % (pa,))
            isError = True
        finally:
            outfp.close()

        if isError:
            # Report to Bit9 that we had error analyzing this file. This means we will not try analysis again.
            pa['analysisStatus'] = 4  # (status: Error)
            pa['analysisError'] = 'VirusTotal returned error when attempting to send file for scanning'
        else:
            # Tell Bit9 that we are waiting for the scan to finish
            pa['analysisStatus'] = 1 # (status: Analyzing)

        # Update Bit9 status for this file
        self.bit9.update('v1/pendingAnalysis', pa)
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
            notification['severity'] = 'critical'
            notification['type'] = 'malicious_file'
        elif positivesPerc > 0:
            notification['analysisResult'] = 2  # ...could be malicious
            notification['severity'] = 'high'
            notification['type'] = 'potential_risk_file'
        else:
            notification['analysisResult'] = 1  # clean!
            notification['severity'] = 'low'
            notification['type'] = 'clean_file'
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
        self.bit9.create("v1/notification", notification)
        log.info("VT analysis for fileAnalysis %d completed. VT result is %d%% malware (%s). Reporting status: %s"
                 % (fileAnalysisId, positivesPerc, notification['malwareName'], notification['type']))

    def processOneAnalysisRequest(self, pa):
        # Use md5 hash if we have one. If not, use Sha256
        fileHash = pa['md5'].strip()
        if fileHash == '':
            fileHash = pa['sha256'].strip()

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
            log.info("VirusTotal API rate limit reached, will try again later")
            return

        scanId = None
        scanResults = r.json()
        # Check if we got results...
        if scanResults.get('positives') is not None:
            # Yes, VT has them. Report results and we are done with the file
            log.info("%s: VirusTotal has a result ready, reporting to Bit9" % fileHash)
            self.reportResultToBit9(pa['id'], scanResults)
        elif scanResults.get('scan_id') is not None:
            # VT already knows about the file, but scan is not complete. We got scanId for future reference
            # Let's remember that and try again in 1 hour (per VT best practices)
            scanId = scanResults['scan_id']
        elif not self.allow_uploads:
            # Uploads are not allowed. Cancel the analysis
            pa['analysisStatus'] = 5 # (status: Cancelled)
            log.info("%s: VirusTotal has no information and we aren't allowed to upload it. Cancelling the analysis request." % fileHash)
            self.bit9.update('v1/pendingAnalysis', pa)
        elif pa['uploaded'] == 1:
            # We have file and now we will upload it to VT
            log.info("%s: VirusTotal has no information on this hash. Uploading the file" % fileHash)
            scanId = self.uploadFileToVT(pa)
        else:
            # if we end here, it means that VT doesn't have file, and Bit9 hasn't uploaded it yet from the agent
            # we will come back again when we reach this file next time around
            log.info("%s: VirusTotal has no information on this hash. Waiting for Bit9 agent to upload it." % fileHash)
            pass

        if scanId:
            # Remember scanId since VT wants use to use it for future references to the file
            # We will try again in 1 hour (per VT best practices)
            next_check = datetime.datetime.now() + datetime.timedelta(0, 3600)
            self.scheduledScans[fileHash] = {'scanId': scanId, 'nextCheck': next_check}
            log.info("%s: Waiting for analysis to complete. Will check back after %s." % (fileHash,
                                                                                          next_check.strftime("%Y-%m-%d %H:%M:%S")))

if __name__ == '__main__':
    # -------------------------------------------------------------------------------------------------
    # Main body of the script

    try:
        import bit9api
    except ImportError:
        # Import our common bit9api (assumed to live in common folder, sibling to current folder)
        commonPath = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common')
        sys.path.append(commonPath)
        import bit9api

    logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    requests.packages.urllib3.disable_warnings()

    bit9 = bit9api.bit9Api(
        "https://localhost",  # Replace with actual Bit9 server URL
        token="<enter your Bit9 API token here>",  # Replace with actual Bit9 user token for VT integration
        ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
    )

    vtConnector = virusTotalConnector(
        bit9,
        vt_token='<enter your VT API key here>',  # Replace with your VT key
        allow_uploads=True,  # Allow VT connector to upload binary files to VirusTotal
        connector_name='VirusTotal',
        download_location=r'c:\test'  # Replace with actual local file location. If not set,
                                      # script will try to access shared folder where this file resides
                                      # Note that you do not want to end your path with a backslash. ie. use
                                      # r'c:\test' *not* r'c:\test\'.
    )

    print("\n*** VT script starting")
    vtConnector.start()

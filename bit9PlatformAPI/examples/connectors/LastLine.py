#!/usr/bin/python
"""
This is a Python script for the Lastline Analyst Connector for Bit9 Security Platform.

Copyright Bit9, Inc. 2015 
support@bit9.com


Disclaimer
+++++++++++++++++++
By accessing and/or using the samples scripts provided on this site (the Scripts), you hereby agree to the following terms:
The Scripts are exemplars provided for purposes of illustration only and are not intended to represent specific 
recommendations or solutions for API integration activities as use cases can vary widely.      
THE SCRIPTS ARE PROVIDED AS IS WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED.  BIT9 MAKES NO REPRESENTATION
OR OTHER AFFIRMATION OF FACT, INCLUDING BUT NOT LIMITED TO STATEMENTS REGARDING THE SCRIPTS SUITABILITY FOR USE OR PERFORMANCE.
IN NO EVENT SHALL BIT9 BE LIABLE FOR SPECIAL, INCIDENTAL, CONSEQUENTIAL, EXEMPLARY OR OTHER INDIRECT DAMAGES OR FOR DIRECT 
DAMAGES ARISING OUT OF OR RESULTING FROM YOUR ACCESS OR USE OF THE SCRIPTS, EVEN IF BIT9 IS ADVISED OF OR AWARE OF THE 
POSSIBILITY OF SUCH DAMAGES.

Requirements
+++++++++++++++++++

- Python 2.6 or 2.7
- Bit9 API client (included) which requires requests Python module
- Lastline Analysis API client (available at https://analysis.lastline.com/docs/llapi_client/analysis_apiclient.py)

- Lastline API Key
- Lastline API Token

- Bit9 Platform Server 7.2.1 or better
- Bit9 API Token (generated in Bit9 Console)
- Bit9 RBAC permission enabled for 'Extend connectors through API'
Required python modules can be installed using tools such as easy_install or pip, e.g.
	easy_install requests

Configuring Connector
+++++++++++++++++++++++

Please update the script with appropriate LL_API_KEY, LL_API_TOKEN, B9_API_TOKEN, B9_SERVER with your Lastline and B9 API credentials.

By default, the client connects to an API instance running in the Lastline cloud at https://analysis.lastline.com

Starting Connector
+++++++++++++++++++++++

Start the script. No paramters are required. Debug and Error logs will be created in the script folder.
"""

import os
import sys
import datetime
import time
import logging
import json
import analysis_apiclient
import bit9api

# Lastline API parameters
class LastlineAPI:
	def __init__(self, url, key, token, strong_cert, delete_after_analysis = True):
		self.url = url
		self.key = key
		self.token = token
		self.strong_cert = strong_cert # should cert be validated
		self.delete_after_analysis = delete_after_analysis # should file be deleted after analysis

# B9 Connector for Lastline
class LastlineConnector:
	def __init__(self, b9_api, ll_api, download_file_location, polling_period = 30, report_store_location = False, debug_log_filename = "lastline_debug.log", error_log_filename = "lastline_error.log"):
		self.b9_api = b9_api
		self.ll_api = ll_api
		self.polling_period = polling_period
		self.download_file_location = download_file_location
		self.report_store_location = report_store_location
		self.debug_log_filename = debug_log_filename
		self.error_log_filename = error_log_filename

		# Dictionary to map B9 pending analysis requests to Lastline's tasks
		# Any pending requests and finished results will be kept here, together with Lastline uuid
		self.bit9_pending_analysis = {}

		# Dictionary to track LL tasks waiting for completion
		# Any pending results will be kept here, together with their status
		self.ll_tasks = {}

		# Track when we last checked for completed tasks
		self.last_checked_time = datetime.datetime.utcnow() - datetime.timedelta(days=1)

	def start(self):
		self.init_logging()
		try:
			logging.info("*** LL script starting")

			self.ll = analysis_apiclient.AnalysisClient(self.ll_api.url, key=self.ll_api.key, api_token=self.ll_api.token)
			logging.info("Connected to Lastline API [%s]" % self.ll_api.url)

			# Register or update our connector
			r = self.b9_api.create('v1/connector', {'name': 'Lastline', 'analysisName': 'Lastline',
								'connectorVersion': '1.0', 'canAnalyze': 'true', 'analysisEnabled': 'true'})
			connectorId = str(r['id'])
			logging.info("Connected to B9 API [%s]" % self.b9_api.server)

		except Exception as ex:
			logging.error(ex)
			return

		# Loop forever (until killed)
		while True:
			try:
				# Check with LL for any pending tasks
				self.fetchCompletedTasks()
				# Check with Bit9 Platform if we have any analysis still pending
				for i in self.b9_api.retrieve("v1/pendingAnalysis", url_params="connectorId=" + connectorId):
					# Process all B9 pending analysis requests for LL
					self.processOneAnalysisRequest(i)
			except:
				logging.error(sys.exc_info()[0])
				logging.error("*** Exception processing requests. Will try again in %d seconds." % self.polling_period)

			time.sleep(self.polling_period)
		return

	def init_logging(self):
		logger = logging.getLogger("analysis")
		logger.setLevel(logging.DEBUG)

		#clean up any pre-existing handlers!
		handlers = [h for h in logger.handlers]
		for h in handlers:
			logger.removeHandler(h)

		#create console handler and set log level
		ch = logging.StreamHandler()
		ch.setLevel(logging.INFO)
		#create file handler and set log level

		#we overwrite old log files in each run.
		fh = logging.FileHandler(self.debug_log_filename, 'a')
		fh.setLevel(logging.DEBUG)

		#create file handler for the error log
		#each log file grows up to 1 megabyte, and we keep 4 old ones
		eh = logging.FileHandler(self.error_log_filename, 'a')
		eh.setLevel(logging.ERROR)

		#create formatter
		console_formatter = logging.Formatter("%(message)s")
		file_formatter = logging.Formatter("%(asctime)s - %(module)s(%(lineno)d) - %(message)s")

		#add formatter to ch and fh
		ch.setFormatter(console_formatter)
		fh.setFormatter(file_formatter)
		eh.setFormatter(file_formatter)
		#add ch and fh to logger
		logger.addHandler(ch)
		logger.addHandler(fh)
		logger.addHandler(eh)

		logging.root = logger

	def uploadFileToLL(self,pa):
		uuid = None
		isError = False
		file = None
		downloaded = False
		try:
			fileName = pa['fileName'].strip()

			if self.download_file_location is not None:
				# This is if we want to locally download file from Bit9
				# (in the case shared folder is not accessible)
				localFilePath = self.download_file_location + pa['fileName']
				self.b9_api.retrieve_analyzed_file(pa['id'], localFilePath)
				logging.debug("Downloaded file '%s'" % localFilePath)
				downloaded = True
			else:
				# Easier option, if Bit9 shared folder can be accessed directly
				localFilePath = pa['uploadPath']

			file = open(localFilePath, 'rb')
			logging.debug("Submitting '%s' to LL for analysis." % localFilePath)
			submit_result = self.ll.submit_file(file, filename=fileName, verify=self.ll_api.strong_cert, delete_after_analysis=self.ll_api.delete_after_analysis)
			logging.debug("Submit result: %s" % str(submit_result)[:1024])
			result_data = submit_result.get('data', {})

			# we got LL uuid. We will need it to check status of the scan at later time
			uuid = result_data['task_uuid']

			# Tell Bit9 that we are waiting for the scan to finish
			pa['analysisStatus'] = 1 # (status: Analyzing)
			pa['analysisResult'] = 0 # (status: Unknown)

			# Update Bit9 status for this file
			self.b9_api.update('v1/pendingAnalysis', pa)
		finally:
				# Delete downloaded file without exception
				if file != None:
					file.close()
				if (downloaded):
					try:
						os.remove(localFilePath)
						logging.debug("Removed downloaded file '%s'" % localFilePath)
					except OSError:
						pass
		return uuid

	def reportResultToBit9(self, pa, scanResults):
		# We have results. Create our Bit9 notification
		fileAnalysisId = pa['id']
		md5 = pa['md5']
		sha1 = pa['sha1']
		fileName = pa['fileName']

		notification = {
			'fileAnalysisId': fileAnalysisId,
			'product': 'Lastline',
			'appliance': self.ll_api.url.replace("https://", "")
		}
		if 'https://analysis.lastline.com' not in self.ll_api.url:
			externalUrl = '%s/malscape/#/task/%s' % ( self.ll_api.url, scanResults['task_uuid'])
			notification['externalUrl'] = externalUrl
		else:
			notification['appliance'] = notification['appliance'].replace("analysis.lastline.com", "user.lastline.com")

		if 'malicious_activity' in scanResults:
			notification['anomaly'] = ', '.join(scanResults['malicious_activity'])

		# Let's see if it is malicious. Use some fancy heuristics...
		positivesPerc = scanResults['score']
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

		files = []
		if ('report' in scanResults):
			report = scanResults['report']
			if 'overview' in report:
				if 'analysis_engine_version' in report['overview']:
					notification['version'] = report['overview']['analysis_engine_version']
				if 'analysis_engine' in report['overview']:
					notification['targetOS'] = report['overview']['analysis_engine']
			if ('analysis_metadata' in report):
				for element in report['analysis_metadata']:
					if 'metadata_type' in element and 'generated_file' == element['metadata_type']:
						if 'file' in element:
							writtenFile = element['file']
							file = {}
							if 'filename' in writtenFile:
								file['fileName'] = os.path.basename(writtenFile['filename'])
								file['filePath'] = os.path.dirname(writtenFile['filename'])
								if 'ext_info' in writtenFile:
									if 'sha1' in writtenFile['ext_info']:
										file['sha1'] = writtenFile['ext_info']['sha1']
									if 'md5' in writtenFile['ext_info']:
										file['md5'] = writtenFile['ext_info']['md5']
									if 'size' in writtenFile['ext_info']:
										file['fileSize'] = writtenFile['ext_info']['size']
								file['operation'] = 'created'
								files.append(file)
		if len(files) > 0:
			file = { 'fileName' : os.path.basename(fileName),
					 'filePath' : os.path.dirname(fileName),
					 'md5' : md5,
					 'sha1' : sha1,
					 'operation' : 'created'
			}
			files.insert(0, file)
			notification['files'] = files

		self.b9_api.create("v1/notification", notification)
		logging.debug("File analysis completed for '%s' [%s]: %s" % (fileName, md5, notification['type']))

	def fetchTaskResult(self, uuid, fileName):
		logging.debug("Querying LL for json result for '%s'" % uuid)
		json_result = self.ll.get_result(uuid, raw=True)
		logging.debug("Query result: %s" % str(json_result)[:1024])
		result = json.loads(json_result)
		success = result['success']
		if not success:
			logging.error("\t%s", result)
			return False
		if self.report_store_location:
			result_filename = os.path.join(self.report_store_location, os.path.basename(fileName))
			json_result = json.dumps(result, sort_keys=True, indent=4)
			json_fn = result_filename + ".json"
			f = open(json_fn, "w")
			f.write(json_result)
			#first one (in json) was successful.
			#Now let's get it in raw XML.
			logging.debug("Querying LL for xml result for '%s'" % uuid)
			xml_result = self.ll.get_result(uuid, requested_format="xml")
			xml_fn = result_filename + ".xml"
			f = open(xml_fn, "w")
			f.write(xml_result)
		return result

	def fetchCompletedTasks(self):
		try:
			waitingScans = sum(1 for x in self.ll_tasks.values() if x == "pending")
			if (waitingScans > 0):
				moreResults = 1
				while (moreResults == 1):
					logging.debug("Querying LL for completed tasks from %s" % str(self.last_checked_time))
					result = self.ll.completed(after=self.last_checked_time, verify=self.ll_api.strong_cert)
					logging.debug("Query result: %s" % result)
					completed_tasks = result["data"]["tasks"]
					self.last_checked_time = result["data"]["before"]
					moreResults = result["data"]["more_results_available"]
					completedCount = 0
					if len(completed_tasks) > 0:
						for uuid in completed_tasks:
							if uuid in self.ll_tasks.keys():
								self.ll_tasks[uuid] = "completed"
								completedCount += 1
					if completedCount > 0:
						logging.debug("Got %s completed tasks", completedCount)

		except Exception as e:
			logging.error(e)
			return

	def processOneAnalysisRequest(self,pa):
		try:
			# Use md5 hash if we have one
			md5 = pa['md5'].strip()
			fileName = pa['fileName'].strip()

			uuid = None
			# Check our cache if we already sent this file for scan
			if md5 in self.bit9_pending_analysis.keys():
				uuid = self.bit9_pending_analysis[md5]
				if uuid in self.ll_tasks:
					task = self.ll_tasks[uuid]
					if task == "completed":
						# Get our uuid we got from LL last time around
						result = self.fetchTaskResult(uuid, fileName)
						if result == False:
							raise Exception("Error: Result not available")
						self.reportResultToBit9(pa, result['data'])
						del self.ll_tasks[uuid]
						del self.bit9_pending_analysis[md5]
						return
					else:
						# Still waiting for a completed result
						return
			else:
				# we have not asked LL yet. Try with file hash
				try:
					logging.debug("File analysis requested for '%s' [%s]" % (fileName, md5))
					result = self.ll.submit_file_hash(md5=md5, filename=fileName, verify=self.ll_api.strong_cert)
					logging.debug("Query result: %s" % str(result)[:1024])
					if 'error' in result.get('data', {}):
						raise Exception(result['data']['error'])
					# LL task available
					if 'task_uuid' in result.get('data', {}):
						uuid = result['data']['task_uuid'];
					# LL result available
					if 'score' in result.get('data', {}):
						result = self.fetchTaskResult(uuid, fileName)
						if result == False:
							raise Exception("Error: Result not available")
						self.reportResultToBit9(pa, result['data'])
						if uuid in self.ll_tasks:
							del self.ll_tasks[uuid]
						return
				except analysis_apiclient.FileNotAvailableError:
					# file has not already been submitted to the device, need to submit
					if pa['uploaded'] == 1:
						# We have file and now we will upload it to LL
						uuid = self.uploadFileToLL(pa)
					else:
						# if we end here, it means that LL doesn't have file, and Bit9 hasn't uploaded it yet from the agent
						# we will come back again in 30 seconds
						uuid = None
				if uuid is not None:
					# Remember uuid since LL wants use to use it for future references to the file
					# We will try again in 1 hour (per LL best practices)
					self.bit9_pending_analysis[md5] = uuid
					self.ll_tasks[uuid] = "pending"

		except Exception as ex:
			logging.error(ex)
			# Report to Bit9 that we had error analyzing this file. This means we will not try analysis again.
			pa['analysisStatus'] = 4  # (status: Error)
			pa['analysisError'] = 'Lastline %s' % str(ex)

			# Update Bit9 status for this file
			self.b9_api.update('v1/pendingAnalysis', pa)

# -------------------------------------------------------------------------------------------------
# Main body of the script

b9_api = bit9api.bit9Api(
	server = 'https://B9_SERVER',
	ssl_verify = False, # Validate cert against CA
	token = 'B9_API_TOKEN'  # Need to add B9 API token here
	)

ll_api = LastlineAPI(
	url = 'https://analysis.lastline.com',
	key = 'LL_API_KEY', # Need to add Lastline API key here
	token = 'LL_API_TOKEN', # Need to add Lastline API token here
	strong_cert = False) # Validate cert against CA
# Need to specify an existing accessible path here (such as c:\\test\\)
connector = LastlineConnector(b9_api, ll_api, download_file_location="c:\\test\\")

connector.start()

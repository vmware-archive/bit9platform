#
# Bit9 Platform API
# Copyright Bit9, Inc. 2014 
# support@bit9.com
#

import json
import requests


class bit9Api(object):
    """ Python bindings for Bit9Platform API 
    Example:
    import bit9api
    cb = bit9api.bit9Api("https://<bit9 server address>", token="apitoken")
    # get metadata for all svchost.exe's not from c:\\windows
    procs = cb.process_search(r"process_name:svchost.exe -path:c:\\windows\\")  
    for proc in procs['results']:
        proc_detail = cb.process(proc['id'])
        print proc_detail['process']['start'], proc_detail['process']['hostname'], proc_detail['process']['path']
    """
    def __init__(self, server, ssl_verify=True, token=None):
        """ Requires:
                server -    URL to the Bit9Platform server.  Usually the same as 
                            the web GUI.
                sslVerify - verify server SSL certificate
                token - this is for CLI API interface
        """

        if not server.startswith("http"): 
            raise TypeError("Server must be URL: e.g, https://bit9server.local")

        if token is None: 
            raise TypeError("Missing required authentication token.")

        self.server = server.rstrip("/")
        self.sslVerify = ssl_verify
        self.tokenHeader = {'X-Auth-Token': token}
        self.tokenHeaderJson = {'X-Auth-Token': token, 'content-type': 'application/json'}

    # Private function that downloads file in chunks
    def __download_file(self, obj_id, obj_name, local_path, chunk_size_kb=10):
        # NOTE the stream=True parameter
        url = self.server + '/' + obj_name + '?id=' + str(obj_id) + '&downloadFile=true'
        r = requests.get(url, headers=self.tokenHeaderJson, verify=self.sslVerify, stream=True)
        r.raise_for_status()
        n = 0
        with open(local_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=chunk_size_kb*1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                    f.flush()
                    n += 1

    # Download file from server to the local file system from fileUpload object
    def retrieve_uploaded_file(self, obj_id, local_path):
        return self.__download_file(obj_id, 'fileUpload', local_path)

    # Download file from server to the local file system from pendingAnalysis object
    def retrieve_analyzed_file(self, obj_id, local_path):
        return self.__download_file(obj_id, 'pendingAnalysis', local_path)

    # Read object using HTTP GET request
    def read(self, api_obj, obj_id=0, url_params=''):
        if obj_id:
            api_obj = api_obj + '/' + str(obj_id)
        if url_params:
            url_params = '?' + url_params.lstrip("?")
        url = self.server + '/' + api_obj + url_params
        r = requests.get(url, headers=self.tokenHeaderJson, verify=self.sslVerify)
        r.raise_for_status()
        return r.json()

    # Create object using HTTP POST request. Note that this can also be used to update existing object
    def create(self, api_obj, data, url_params=''):
        if not data:
            raise TypeError("Missing object data.")
        if url_params:
            url_params = '?' + url_params.lstrip("?")
        url = self.server + '/' + api_obj + url_params
        r = requests.post(url, data=json.dumps(data), headers=self.tokenHeaderJson, verify=self.sslVerify)
        r.raise_for_status()
        return r.json()
    
    # Update object using HTTP PUT request
    def update(self, api_obj, data, obj_id=0, url_params=''):
        if not data:
            raise TypeError("Missing object data.")
        if url_params:
            url_params = '?' + url_params.lstrip("?")
        if not obj_id:
            obj_id = data['id']
        url = self.server + '/' + api_obj + '/' + str(obj_id) + url_params
        r = requests.put(url, data=json.dumps(data), headers=self.tokenHeaderJson, verify=self.sslVerify)
        r.raise_for_status()
        return r.json()

    # Delete object using HTTP DELETE request.
    def delete(self, api_obj, data=None, obj_id=0, url_params=''):
        if not obj_id and data:
            obj_id = data['id']
        if url_params:
            url_params = '?' + url_params.lstrip("?")
        if not obj_id:
            raise TypeError("Missing object data or id.")
        url = self.server + '/' + api_obj + '/' + str(obj_id) + url_params
        r = requests.delete(url, headers=self.tokenHeaderJson, verify=self.sslVerify)
        r.raise_for_status()

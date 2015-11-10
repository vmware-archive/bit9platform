import sys
import os
import time

# Includes the "common" folder that comes from GitHub
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common'))
import bit9api

bit9 = bit9api.bit9Api(
    "https://bit9.server.xyz",  # Replace with actual Bit9 server URL
    token="api_token",  # Replace with actual Bit9 user token for VT integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

# Set the desired debug properties here. Documentation for this can be found here: https://github.com/carbonblack/bit9platform/tree/master/bit9PlatformAPI/docs
kernelTrace = 4
debugLevel = 6
debugDuration = 1

# Find all computers with the specified name that are connected
comps = bit9.search('v1/computer', ['name:DOMAIN\NAME', 'connected:true'])

# Iterate through each computer that was found and perform the specified actions
for c in comps: 
    print("Changing debug level for computer %s (IP: %s)" % (c['name'], c['ipAddress']))
    c['kernelDebugLevel'] = kernelTrace
    c['debugLevel'] = debugLevel
    c['debugDuration'] = debugDuration
    bit9.update('v1/computer', c,'','changeDiagnostics=true')

# Sleep for the debugDuration
# In order to account for some delay in setting the debugging, multiplying the debugDuration (which is in minutes) by 70 to move it into seconds and add some overhead
debugDurationSeconds = debugDuration * 70
print('Sleeping for %s seconds to let the debugging happen' % debugDurationSeconds)
for i in range(debugDurationSeconds,0,-1):
    time.sleep(1)
    sys.stdout.write(str(i)+' ')
    sys.stdout.flush()

# # Iterate through each computer again and trigger a diagnostic upload
# comps = bit9.search('v1/computer', ['name:domain\example', 'connected:true'])
for c in comps:
    print("Triggering diagnostic upload for computer %s (IP: %s)" % (c['name'], c['ipAddress']))
    c['debugFlags'] = 0x01
    bit9.update('v1/computer', c,'','changeDiagnostics=true')

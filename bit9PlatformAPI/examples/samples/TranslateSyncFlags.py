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

# Find all computers with the specified name that are connected
comps = bit9.search('v1/computer', ['name:DOMAIN\NAME', 'connected:true'])

# List of the sync flags and their associated translation
hexSyncFlags = [(0x01, "Agent is going through initialization"), (0x02, "Agent is going through full cache re-synch"), (0x08, "Agent config list is out of date"), (0x10, "Agent Enforcement is out of date"), (0x20, "Kernel is not connected to the agent"), (0x40, "Agent events timestamps indicate that system clock is out of synch"), (0x80, "Agent has failed the health check"), (0x100, "This is clone that is tracking only new files"), (0x200, "This version of kernel is not supported by the agent (Linux only)")]

# Iterate through each computer that was found and translate the sync flags
for c in comps: 
    print("Computer: %s (IP: %s)" % (c['name'], c['ipAddress']))
    print("Sync Flags: %s" % c['syncFlags'])
    if c['syncFlags'] != 0:
        # This is where we compare the syncFlags to the values in hexSyncFlags, then print the matching translations
        for flag_string in [trans for flag, trans in hexSyncFlags if c['syncFlags'] & flag ]:
            print("The flag '%s' was found in the sync flag." % flag_string) 
    else:
        print("Sync Flag was 0")

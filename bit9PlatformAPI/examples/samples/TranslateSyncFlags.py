import sys
import os
import argparse

# Includes the "common" folder that comes from GitHub
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'common'))
import bit9api

bit9 = bit9api.bit9Api(
    "https://bit9.server.xyz",  # Replace with actual Bit9 server URL
    token="api_token",  # Replace with actual Bit9 user token for VT integration
    ssl_verify=False  # Don't validate server's SSL certificate. Set to True unless using self-signed cert on IIS
)

# This function will perform the lookup of the sync flags and return the translated value
def convert_sync_flags(syncFlag):
    # Set the found_flags value back to the base of no flags found
    found_flags = []
    
    # List of the sync flags and their associated translation
    hexSyncFlags = [(0x01, "Agent is going through initialization"), (0x02, "Agent is going through full cache re-synch"), (0x08, "Agent config list is out of date"), (0x10, "Agent Enforcement is out of date"), (0x20, "Kernel is not connected to the agent"), (0x40, "Agent events timestamps indicate that system clock is out of synch"), (0x80, "Agent has failed the health check"), (0x100, "This is clone that is tracking only new files"), (0x200, "This version of kernel is not supported by the agent (Linux only)")]
    
    # Checks if syncFlag is 0, then does the translation of the sync flags
    if syncFlag != 0:
        # This is where we compare the syncFlags to the values in hexSyncFlags, then print the matching translations
        for flag,trans in hexSyncFlags:
            if syncFlag&flag>0:
                # Store the sync flag and the translation in the found_flags list
                found_flags.append((flag,trans))
    else:
        found_flags = [(0,"No sync issues")]
    return found_flags

# This function will parse the command line used when running the script, and does the search of the
def main(argv):
    # Create the initial search_conditions list that will be populated
    search_conditions=[]
    
    # Generate the parser object
    parser = argparse.ArgumentParser(description='This is a sample to search the API and return sync flags. All searches are done via a LIKE search')
    parser.add_argument('-n', action='store', dest='comp_name', help='Computer name to search for')
    parser.add_argument('-p', action='store', dest='policy', help='Policy name to search for')
    parser.add_argument('-u', action='store', dest='user_name', help='Last logged in user name to search for')
    parser.add_argument('-c', action='store', dest='connect_tf', help='Either true or false for connected computers')
    
    if argv == []:
        print("No arguments were provided")
        parser.print_help()
        sys.exit(1)
    
    # Store the results from the command line in the 'results' variable
    results = parser.parse_args()
    
    # Add the arguments into ths search_conditions list
    if results.comp_name != None:
        search_conditions.append('name:*'+results.comp_name+'*')
    if results.policy != None:
        search_conditions.append('policyName:*'+results.policy+'*')
    if results.user_name != None:
        search_conditions.append('users:*'+results.user_name+'*')
    if results.connect_tf != None:
        if results.connect_tf in ("true", "false"):
            search_conditions.append('connected:'+results.connect_tf)
        elif results.connect_tf not in ("true", "false"):
            print("Ignoring connected argument. It MUST be equal to either 'true' or 'false'")

    # Find all computers using the parameters provided at the command line
    comps = bit9.search('v1/computer', search_conditions)
    
    # For every found computer, print out the name, IP, sum of the sync flags, then send the data to the conver_sync_flags function
    for c in comps: 
        print("Computer: %s (IP: %s)" % (c['name'], c['ipAddress']))
        print("Sync Flags: %s" % c['syncFlags'])
        translated_syncFlags=convert_sync_flags(c['syncFlags'])
        # Go through each result that was translated and print them out
        for flag, trans in translated_syncFlags:
            print("Sync Flag '%s' translates to '%s'" % (flag, trans))
            
if __name__ == "__main__":
    main(sys.argv[1:])

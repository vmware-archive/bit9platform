#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Example Usage:
# python initiate_cache_check.py -q name:BIT9SE\W7-LOW

from pprint import pprint
import logging, csv, sys, os, requests, argparse
from bit9api import bit9Api
from logging import handlers

requests.packages.urllib3.disable_warnings()
logging.getLogger("requests").setLevel(logging.WARNING)

LOG_FILENAME='initiate_cache_check.log'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.propagate = False
formatter = logging.Formatter("%(asctime)s - %(funcName)s - %(levelname)s - %(message)s")
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1048576,backupCount=5,)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)


def build_cli_parser():
    parser = argparse.ArgumentParser(description="This script initiates Cache Checks using the Bit9 API.")
    # for each supported output type, add an option
    #
    parser.add_argument("-s", "--server", action="store", default='https://192.168.230.4', dest="server",
                      help="Bit9 server's URL.  e.g., https://192.168.230.4")
    parser.add_argument("-a", "--apitoken", action="store", default='AACB5C5F-D9B4-4694-AB9A-8640FF79D401', dest="token",
                      help="API Token for Carbon Black server")
    parser.add_argument("-n", "--ssl-verify", action="store", default=False, dest="ssl_verify",
                      help="Verify server SSL certificate. Defaults to 'False': Do not verify.")
    parser.add_argument("-q", "--query", action="append", default=[], dest="query",
                      help="query to select computers to act upon")
    return parser

def init_cc(bit9, agent_id, ccLevel, refreshFlags):
    print "\nWe'll fix it right up! Bit9 Agent ID: %d, Cache Check Level %s and Policy Rule Sync %d" % (agent_id, ccLevel, refreshFlags)

    url_params = 'changeDiagnostics=true'
    api_obj = '/v1/computer'
    data = {'id': agent_id, 'ccLevel': ccLevel, 'refreshFlags': refreshFlags}

    results = bit9.create(api_obj, data, url_params)
    print "CCLevel %s and Policy Refresh %s scheduled for %s" % (str(results['ccLevel']), str(results['refreshFlags']),  results['name'])
    logger.info("CCLevel %s and Policy Refresh %s scheduled for %s" % (str(results['ccLevel']), str(results['refreshFlags']),  results['name']))

def main(argv):
    parser = build_cli_parser()
    args = parser.parse_args()
    if not args.server or not args.token or args.query is None:
        print "Missing required param; run with --help for usage"
        sys.exit(-1)

    print "Computer search criteria: %s" % args.query
    logger.info("Computer search criteria: %s" % args.query)

    bit9 = bit9Api (args.server, token=args.token, ssl_verify=args.ssl_verify)
    search_conditions = args.query

    comps = bit9.search('v1/computer', search_conditions)

    for comp in comps:
        if comp['ccLevel'] != 0:
            print "%s already performing a Cache Consistency check.  Skipping this computer." % comp['name']
            logger.info("%s already performing a Cache Consistency check.  Skipping this computer." % comp['name'])
            continue

        agent_id = comp['id']

        ccLevel = raw_input("\n\nInitiate Cache Check for Computer '%s' in policy '%s'\n"
                             "Cache consistency check level can be one of:\n"
                             "0 = None\n"
                             "1 = Quick verification\n"
                             "2 = Rescan known files\n"
                             "3 = Full scan for new files: [0,1,2,3] " % (comp['name'], comp['policyName']))

        if not ccLevel in ['1', '2','3']:
            print "User response was not '1', '2' or '3'. Skipping cache check for %s!" % comp['name']
            logger.info("User response was not '1', '2' or '3'. Skipping cache check for %s!" % comp['name'])
            ccLevel = 0


        refreshFlags = raw_input("\nRequest Resync of Policy Rules for Computer '%s' in policy '%s'\n"
                                 "Resync of policy rules can be one of:\n"
                                 "0 = None\n"
                                 "1 = Refresh confg list\n"
                                 "2 = Refresh config list from the file: [0,1,2] " % (comp['name'], comp['policyName']))

        if refreshFlags == '1':
            refreshFlags = 32
        elif refreshFlags == '2':
            refreshFlags = 4096
        else:
            print "User response was not '1' or '2'. Skipping policy rules sync for Computer %s!" % comp['name']
            logger.info("User response was not '1' or '2'. Skipping policy rules sync for Computer %s!" % comp['name'])
            refreshFlags = 0

        if ccLevel == 0 and refreshFlags == 0:
            print "\nCache Check and Policy Refresh both unset, skipping %s" % comp['name']
            logger.info("Cache Check and Policy Refresh both unset, skipping %s" % comp['name'])
            pass
        else:
            init_cc(bit9, agent_id, ccLevel, refreshFlags)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

'''Available computer fields as of Bit9 7.2.1.710
CLIPassword
SCEPStatus
agentCacheSize
agentMemoryDumps
agentQueueSize
agentVersion
automaticPolicy
cbSensorFlags
cbSensorId
cbSensorVersion
ccFlags
ccLevel
clVersion
computerTag
connected
dateCreated
daysOffline
debugDuration
debugFlags
debugLevel
deleted
description
disconnectedEnforcementLevel
enforcementLevel
forceUpgrade
hasHealthCheckErrors
id
initializing
ipAddress
kernelDebugLevel
lastPollDate
lastRegisterDate
localApproval
macAddress
machineModel
memorySize
name
osName
osShortName
platformId
policyId
policyName
policyStatusDetails
prioritized
processorCount
processorModel
processorSpeed
refreshFlags
supportedKernel
syncFlags
syncPercent
systemMemoryDumps
tamperProtectionActive
tdCount
template
templateCloneCleanupMode
templateCloneCleanupTime
templateCloneCleanupTimeScale
templateComputerId
templateDate
templateTrackModsOnly
uninstalled
upgradeError
upgradeErrorCount
upgradeErrorTime
upgradeStatus
users
virtualPlatform
virtualized
'''
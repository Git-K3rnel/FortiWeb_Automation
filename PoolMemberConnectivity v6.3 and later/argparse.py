import argparse
from serverPool import *


parser = argparse.ArgumentParser(prog='PROG', formatter_class=argparse.RawDescriptionHelpFormatter, description="WAF Menue")
parser.add_argument('-m', '--main', action='store_true', help='Runs script main function')
parser.add_argument('-si', '--sessionInfo', action='store_true', help='Gets seesion count, concurrent sessions and response time')
parser.add_argument('-ar', '--arplist', action='store_true', help='Gets Device ARP list')
args = parser.parse_args()

if args.main:
    main()

if args.sessionInfo:
    get_policy_status()

if args.arplist:
    get_arp_list()

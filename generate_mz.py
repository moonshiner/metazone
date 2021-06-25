#!/usr/bin/python3

import argparse
import yaml
import sys
from mzlib import map_rrtype, lookup, mz_emit_property, cz_hash32, canonical_rr_format

#
# generate_mz: create RFC-1035 format metazone from YAML config
#
# LM: 2021-06-25 00:40:18-07:00
# Shawn Instenes <sinstenes@gmail.com>
#
#

parser = argparse.ArgumentParser(description='Generate metazone from YAML')
parser.add_argument('--file', default='metazone.yaml',
                    help='metazone configuration file to use')
parser.add_argument('--zone', default='metazone.local',
                    help='metazone name to use')
parser.add_argument('--serial', default='1',
                    help='set metazone serial number')
parser.add_argument('--mname', default='authority.metazone.local',
                    help='default MNAME in metazone SOA')
parser.add_argument('--hname', default='metamgr.metazone.local',
                    help='default authority in metazone SOA')
parser.add_argument('--digits', default='5',
                    help='Number of digits to count zones')
parser.add_argument('--preferv4', default='true',
                    help='DNS lookups prefer V4 answers')
parser.add_argument('--debug', default='false',
                    help='set debugging modes, spoof DNS lookups')
args = parser.parse_args()

FILE = args.file
ZONE = args.zone
SERIAL = args.serial
MNAME = args.mname
HNAME = args.hname
try:
    DIGITS = int(args.digits)
except Exception:
    DIGITS = 5

PREFERV4 = True if args.preferv4 == "true" else False
DEBUG = True if args.debug == "true" else False

try:
    yml = yaml.safe_load(open(FILE, "r"))
except Exception:
    print(str.format("Error loading {0}\n", FILE))
    sys.exit(1)

try:
    search_path = yml['host_search_path']
except Exception:
    print("No DNS search path (host_search_path) defined.\n")
    sys.exit(1)

print(str.format("""
;
$ORIGIN {0}
;
@ IN SOA {1} {2} {3} 900 300 604800 300
;
""", ZONE, MNAME, HNAME, SERIAL))
print(str.format(""";
@ IN NS ns1.invalid.
;
version IN TXT "3"
;
; DEFAULTS
;
"""))
for key in yml['defaults'].keys():
    print(str.format("""attribute 3600 IN PTR {0}""", key))
    rrtype = map_rrtype(key)
    itm = yml['defaults'][key]
    entry = lookup(yml, itm, search_path, PREFERV4, DEBUG)
    mz_emit_property(sys.stdout, yml, key, '', rrtype, entry, search_path)

for zgname in yml['zone_groups']:
    count = len(yml[zgname].keys())
    print(str.format(""";
; ZONE DATA {0}
;
""", zgname))
    print(str.format('zonecount.{1} 3600 IN TXT "{0}"', count, zgname))
    print(str.format('digits.{1} 3600 IN TXT "{0}"', DIGITS, zgname))
    zc = 0
    for zn in yml[zgname].keys():
        zc += 1
        ovr_props = yml[zgname][zn]
        lbl = cz_hash32(zn)
        mu = canonical_rr_format(yml, zn, 'PTR', '')
        print(str.format('{0}.{1} 3600 IN PTR {2}', lbl, zgname, mu))
        print(str.format('{0:#0' + str(DIGITS) + 
            'd}.zonelist.{1} 3600 IN CNAME {2}', zc, zgname, lbl + "." + 
            zgname))
        if ovr_props is not None:
            for itm in ovr_props.keys():
                key = ovr_props[itm]
                rrtype = map_rrtype(itm)
                entry = lookup(yml, key, search_path, PREFERV4, DEBUG)
                mu = canonical_rr_format(yml, entry, rrtype, '')
                print(str.format('{0}.{1}.{2} 3600 IN {3} {4}', itm, lbl, zgname, rrtype, mu))

print(str.format(""";
; NAME SERVER GROUPS
;
"""))
for nsg in yml['name_server_groups'].keys():
    # if an NSG is valid, querying version.<NSG>.<ZONE>. should always work
    print(str.format(";\nversion.{0} 3600 IN CNAME version.{1}.", nsg, ZONE))
    nsgd = yml['name_server_groups'][nsg]
    if isinstance(nsgd, dict):  # If it's not a dictionary, no overrides
        for itm in nsgd.keys():
            if itm == "members":
                nlist = nsgd[itm]
                nlist = lookup(yml, nlist, search_path, PREFERV4, DEBUG)
                for ns in nlist.split(" "):
                    print(str.format("{0} 3600 IN DNAME {1}.{2}.", ns, nsg, 
                        ZONE))
            else:
                rrtype = map_rrtype(itm)
                try:
                    cfg = nsgd[itm]
                    cfg = lookup(yml, cfg, search_path, PREFERV4, DEBUG)
                except Exception:
                    cfg = "LOOKUP ERROR: " + nsgd[itm]
                mz_emit_property(sys.stdout, yml, itm, nsg, rrtype, cfg, search_path)


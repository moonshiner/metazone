#!/usr/bin/env python
import binascii
import argparse

def hexrdata(rdata, qname="allowed-transfer", ttl=3600):
    # allow-transfer 3600 IN TYPE42
    qrec = "{}  {} IN TYPE42 ".format(qname, ttl)
    ans = binascii.hexlify(rdata)
    alen = int(len(ans) / 2)
    payload = "%0.2X" % alen + ans.decode()
    print("{} \# {} {}".format(qrec, alen + 1, payload))


def main():
    parser = argparse.ArgumentParser(description='create generic rdata')
    parser.add_argument('rdata', help='rdata')
    args = parser.parse_args()
    rdata = args.rdata.strip("'").replace(' ', '').encode()
    hexrdata(rdata)

if __name__ == "__main__":
    main()

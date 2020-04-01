#!/usr/bin/env python3
# encoding: utf-8

RECORDS = {
	1 : "A",
	28 : "AAAA",
	2 : "NS",
	18 : "AFSDB",
	252 : "AXFR",
	5 : "CNAME",
	6 : "SOA",
	7 : "MB",
	8 : "MG",
	9 : "MR",
	10 : "NULL",
	11 : "WKS",
	12 : "PTR",
	13 : "HINFO",
	14 : "MINFO",
	15 : "MX",
	16 : "TXT",
	17 : "RP",
	19 : "X25",
	20 : "ISDN",
	21 : "RT",
	22 : "NSAP",
	23 : "NSAP-PTR",
	24 : "SIG",
	25 : "KEY",
	26 : "PX",
	27 : "GPOS",
	31 : "EID",
	32 : "NIMLOC",
	33 : "SRV",
	34 : "ATMA",
	35 : "NAPTR",
	36 : "KX",
	37 : "CERT",
	38 : "A6",
	39 : "DNAME",
	40 : "SINK",
	41 : "OPT",
	42 : "APL",
	43 : "DS",
	45 : "IPSECKEY",
	46 : "RRSIG",
	47 : "NSEC",
	48 : "DNSKEY",
	49 : "DHCID",
	50 : "NSEC3",
	51 : "NSEC3PARAM",
	55 : "HIP",
	56 : "NINFO",
	57 : "RKEY",
	58 : "TALINK",
	100 : "UINFO",
	101 : "UID",
	102 : "GID",
	103 : "UNSPEC",
	249 : "TKEY",
	52 : "TLSA",
	250 : "TSIG",
	251 : "IXFR",
	255 : "*",
	257 : "CAA",
	32768 : "TA",
	32769 : "DLV"
}

CODE = {
	0  : "No Error",
	1  : "Format Error",
	2  : "Server Failure",
	3  : "Non-Existent Domain",
	4  : "Not Implemented",
	5  : "Query Refused",
	6  : "Name Exists when it should not",
	7  : "RR Set Exists when it should not",
	8  : "RR Set that should exist does not",
	9  : "Server Not Authoritative for zone",
	9  : "Not Authorized",
	10 : "Name not contained in zone",	
	16 : "Bad OPT Version",
	16 : "TSIG Signature Failure",	
	17 : "Key not recognized", 	
	18 : "Signature out of time window", 	
	19 : "Bad TKEY Mode",
	20 : "Duplicate key name",
	21 : "Algorithm not supported",
	22 : "Bad Truncation"
}
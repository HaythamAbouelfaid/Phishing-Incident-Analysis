#!/usr/bin/env python3
import re, sys, pathlib

p = pathlib.Path("headers/email_header.txt")
if len(sys.argv) > 1: p = pathlib.Path(sys.argv[1])
hdr = p.read_text(errors="ignore")

def find(line_pat):
    m = re.search(line_pat, hdr, re.IGNORECASE)
    return m.group(0).strip() if m else "(not found)"

from_ = re.search(r"^From:\s*(.*)$", hdr, re.MULTILINE|re.IGNORECASE)
retp = re.search(r"^Return-Path:\s*(.*)$", hdr, re.MULTILINE|re.IGNORECASE)
arf  = find(r"^Authentication-Results:.*$")
spf  = find(r"spf=\w+")
dkim = find(r"dkim=\w+")
dmarc= find(r"dmarc=\w+")

print("=== Header Quick Check ===")
print("From:        ", from_.group(1).strip() if from_ else "(not found)")
print("Return-Path: ", retp.group(1).strip() if retp else "(not found)")
print("Auth-Results:", arf)
print("SPF:", spf, "| DKIM:", dkim, "| DMARC:", dmarc)

# Simple verdict based on domain mismatch and external origin
suspicious = []
from_dom = re.search(r"<.*@([^>]+)>|@([^\s>]+)", (from_.group(1) if from_ else ""))
ret_dom   = re.search(r"<.*@([^>]+)>|@([^\s>]+)", (retp.group(1) if retp else ""))

def dom(m): 
    return (m.group(1) or m.group(2)).lower() if m else None

FD, RD = dom(from_dom), dom(ret_dom)
if FD and "lcps.org" not in FD: suspicious.append(f"From domain external: {FD}")
if RD and "lcps.org" not in RD: suspicious.append(f"Return-Path external: {RD}")

if "spf=fail" in spf.lower() or "dkim=fail" in dkim.lower() or "dmarc=fail" in dmarc.lower():
    suspicious.append("An auth check failed (SPF/DKIM/DMARC)")

print("\nVerdict:")
print(" - SAFE-ish (but verify context)" if not suspicious else " - SUSPICIOUS:")
for s in suspicious: print("   •", s)

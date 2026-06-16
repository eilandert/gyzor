#!/usr/bin/env python3
"""Generate expected.tsv from the corpus using the REAL pyzor DataDigester.

This is the source of truth for the gyzor digest parity test. Run it with pyzor
installed (the gyzor CI does this in a python step):

    pip install pyzor
    python3 gen_expected.py

It writes "<name>\t<sha1hex>" lines for every testdata/corpus/*.eml.
"""
import email
import glob
import os

from pyzor.digest import DataDigester

here = os.path.dirname(os.path.abspath(__file__))
corpus = os.path.join(here, "corpus")
out = os.path.join(here, "expected.tsv")

lines = []
for path in sorted(glob.glob(os.path.join(corpus, "*.eml"))):
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        msg = email.message_from_bytes(fh.read())
    digest = DataDigester(msg).value
    lines.append("%s\t%s" % (name, digest))

with open(out, "w") as fh:
    fh.write("\n".join(lines) + "\n")

print("wrote %d digests to %s" % (len(lines), out))

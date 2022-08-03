#!/usr/bin/env python3
# Some simple custom code lints, mostly implemented by means of grepping code

import os
import re
import sys

SCALECODEC_RE = r'\bparity_scale_codec(_derive)?::'
JSONRPSEE_RE = r'\bjsonrpsee[_a-z0-9]*::'

# List Rust source files
def rs_sources(exclude = []):
    exclude = [ os.path.normpath(dir) for dir in ['target', '.git', '.github'] + exclude ]
    is_excluded = lambda top, d: os.path.normpath(os.path.join(top, d).lower()) in exclude

    for top, dirs, files in os.walk('.', topdown=True):
        dirs[:] = [ d for d in dirs if not is_excluded(top, d) ]
        for file in files:
            if os.path.splitext(file)[1].lower() == '.rs':
                yield os.path.join(top, file)

# Disallow certain pattern in source files, with exceptions
def disallow(pat, exclude = []):
    print("Searching for '{}':".format(pat))
    pat = re.compile(pat)
    found_re = False

    for path in rs_sources(exclude):
        with open(path) as file:
            for (line_num, line) in enumerate(file, start = 1):
                line = line.rstrip()
                if pat.search(line):
                    found_re = True
                    print("{}:{}:{}".format(path, line_num, line))

    print()
    return not found_re

def run_checks():
    ok = True
    ok = ok and disallow(SCALECODEC_RE, exclude = ['serialization/core'])
    ok = ok and disallow(JSONRPSEE_RE, exclude = ['rpc'])
    return ok

if __name__ == '__main__':
    if not run_checks():
        sys.exit(1)

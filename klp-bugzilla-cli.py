#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2021-2024 SUSE
# Author: Fernando Gonzalez

import bugzilla
import concurrent.futures
import os
import re
import subprocess
import time
import sys
from tabulate import tabulate
from bugzilla.exceptions import BugzillaError
from requests.exceptions import RequestException

def connect_bugzilla():
    URL = "https://bugzilla.suse.com"
    api_key = os.environ["BUGZILLA_API_KEY"]

    print(f"[+] Connecting to '{URL}'")

    return bugzilla.Bugzilla(URL, api_key=api_key)

def fetch_bugs():
    print(f"[+] Downloading bugs...")

    query = bzapi.build_query(
            status="NEW",
            component="Kernel Live Patches",
            assigned_to="kernel-lp")

    query["ids_only"] = True
    ids = [b.id for b in bzapi.query(query)]
    bugs = bzapi.getbugs(ids)

    deps_ids = [b.depends_on[0] for b in bugs if len(b.depends_on) > 0]
    deps_fields = ["status", "assigned_to", "whiteboard"]
    deps = {d.id:d for d in bzapi.getbugs(deps_ids,include_fields=deps_fields)}

    return bugs, deps

def check_status(bug, cve, dep):
    affected = "No"

    '''
    status types:
    - Fixed: Bug has been fixed in all affected SLEs.
    - Incomplete: Probably someone is working on the bug.
    - Not-Fixed: Probably no one has started working yet on the bug OR
      it has been discarded.
    - Dropped: Bug has been discarded with 100% certainty.
    '''
    if "WONTFIX" in dep.status:
        return "Dropped", affected

    ret = subprocess.run(['klp-build', "scan", "--cve", cve],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         text=True)
    if ret.returncode:
        sys.exit(f"Unexpected klp-build error:\n{ret.stderr}")

    if "Upstream\nNone" in ret.stdout:
        return "Not-Upstream", ""

    # Number of unique commits fixing the bug.
    # Worst case, there are several unique commits per SLE.
    ncommits = len(set(re.findall(r'[a-z0-9]{40}', ret.stdout)))
    status = f"Fixed({ncommits})" if ncommits else "Not-Fixed"

    report = re.findall(r'[A-Za-z0-9\-\t .]+$', ret.stderr)[0]
    if "All supported codestreams are already patched" not in report:
        # List of affected codestreams.
        affected = report[1:]

    if dep and "security-team" not in dep.assigned_to:
        status = f"Incomplete({ncommits})"

    return status, affected

def check_classification(bug):
    rating = ["trivial", "medium", "complex"]

    while True:
        try:
            comments = bug.getcomments()
            break
        except (BugzillaError, RequestException):
           # There's a max number of allowed simultaneous requests...
            time.sleep(5)

    for c in comments:
        if "nstange" in c["creator"]:
            return w if any((w:=i) in c["text"] for i in rating) else "unknown"

    return "None"

def get_dependency(bug, deps):
    d = bug.depends_on
    return deps[d[0]] if len(d) else None

def get_cvss(dep):
    if dep is None:
        return "None"

    raw = dep.whiteboard.split(':')
    return raw[3] if len(raw) >= 4 else "None"

if __name__ == '__main__':
    global bzapi
    table = []
    pool = {}

    bzapi = connect_bugzilla()
    bugs, deps = fetch_bugs()

    print(f"[+] Processing {len(bugs)} bugs")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for b in bugs:
            summary = b.summary.split(':')
            if len(summary) < 3:
                continue

            #Expected format: "*: CVE-XXXX-XXXXX: *: subsystem:*"
            cve = summary[1][5:]
            subsystem = summary[3][:40]
            d = get_dependency(b, deps)
            cvss = get_cvss(d)
            classification = check_classification(b)
            priority = b.priority[5:]

            job = executor.submit(check_status, b, cve, d)
            pool[job] = [b.id, cve, subsystem, cvss, priority, classification]

        print(f"[+] Scanning bugs with klp-build. Go for a coffee :)\n")

        for job in concurrent.futures.as_completed(pool):
            bug = pool[job]
            bug.extend(job.result())
            table.append(bug)

    print(tabulate(table, headers=["ID", "CVE", "SUBSYSTEM", "CVSS", "PRIORITY",
                                  "CLASSIFICATION", "STATUS", "AFFECTED"]))

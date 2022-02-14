#!/usr/bin/env python3

import collections
import itertools
import os
import re
import subprocess
import sys

PUC = "../pamu2fcfg/pamu2fcfg"

resident = ["", "-r"]

presence = ["", "-P"]

pin = ["", "-N"]

verification = ["", "-V"]

Credential = collections.namedtuple(
    "Credential", "keyhandle pubkey attributes oldformat"
)

sshformat = 0


def print_test_case(filename, sshformat, credentials):

    start = """
  cfg.auth_file = "{authfile}";
  cfg.sshformat = {ssh};
  rc = get_devices_from_authfile(&cfg, username, dev, &n_devs);
  assert(rc == 1);
  assert(n_devs == {devices});
"""

    checks = """
  assert(strcmp(dev[{i}].coseType, "es256") == 0);
  assert(strcmp(dev[{i}].keyHandle, "{kh}") == 0);
  assert(strcmp(dev[{i}].publicKey, "{pk}") == 0);
  assert(strcmp(dev[{i}].attributes, "{attr}") == 0);
  assert(dev[{i}].old_format == {old});
"""

    free = """
  free(dev[{i}].coseType);
  free(dev[{i}].attributes);
  free(dev[{i}].keyHandle);
  free(dev[{i}].publicKey);
"""
    end = """
  memset(dev, 0, sizeof(dev));
"""

    code = ""
    free_block = ""

    code += start.format(authfile=filename, ssh=sshformat, devices=len(credentials))
    for c, v in enumerate(credentials):
        code += checks.format(
            i=c, kh=v.keyhandle, pk=v.pubkey, attr=v.attributes, old=v.oldformat
        )
        free_block += free.format(i=c)

    code += free_block + end

    print(code)


def generate_credential(filename, mode, *args):
    command = [PUC, "-u@USERNAME@" if mode == "w" else "-n"]
    command.extend([x for x in args if x.strip() != ""])
    line = subprocess.check_output(command).decode("utf-8")
    with open(filename, mode) as handle:
        handle.write(line)

    matches = re.match(r"^.*?:(.*?),(.*?),es256,(.*)", line, re.M)
    return Credential(
        keyhandle=matches.group(1),
        pubkey=matches.group(2),
        attributes=matches.group(3),
        oldformat=0,
    )


# Single credentials
print("Generating single credentials", file=sys.stderr)

for (r, p, n, v) in itertools.product(resident, presence, pin, verification):
    filename = "credentials/new_" + r + p + v + n + ".cred.in"
    print("Generating " + filename, file=sys.stderr)
    credentials = [generate_credential(filename, "w", r, p, v, n)]
    filename = os.path.splitext(filename)[0]
    print_test_case(filename, sshformat, credentials)


# Double credentials
print("Generating double credentials", file=sys.stderr)

for (r, p, n, v) in itertools.product(resident, presence, pin, verification):
    filename = "credentials/new_double_" + r + p + v + n + ".cred.in"
    print("Generating " + filename, file=sys.stderr)
    credentials = [
        generate_credential(filename, "w", r, p, v, n),
        generate_credential(filename, "a", r, p, v, n),
    ]
    filename = os.path.splitext(filename)[0]
    print_test_case(filename, sshformat, credentials)

# Mixed credentials
print("Mixed double credentials", file=sys.stderr)

for (p1, p2) in itertools.product(presence, presence):
    filename = "credentials/new_mixed_" + p1 + "1" + p2 + "2" + ".cred.in"
    print("Generating " + filename, file=sys.stderr)
    credentials = [
        generate_credential(filename, "w", p1),
        generate_credential(filename, "a", p2),
    ]
    filename = os.path.splitext(filename)[0]
    print_test_case(filename, sshformat, credentials)

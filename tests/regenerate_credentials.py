#!/bin/python2

import collections
import re
import subprocess
import sys
import getpass

PUC = "../pamu2fcfg/pamu2fcfg"

user = getpass.getuser()

resident = ["", "-r"]

presence = ["", "-P"]

pin = ["", "-N"]

verification = ["", "-V"]

Credential = collections.namedtuple("Credential", "keyhandle pubkey attributes oldformat")

sshformat = 0

def print_test_case(filename, sshformat, credentials):

    start = """
  cfg.auth_file = "{authfile}";
  cfg.sshformat = {ssh};
  rc = get_devices_from_authfile(&cfg, %(user)s, dev, &n_devs);
  assert(rc == 1);
  assert(n_devs == {devices});
""" % {'user': user}

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
  memset(dev, 0, sizeof(dev_t) * {devices});
"""

    code = ""
    free_block = ""

    code += start.format(authfile = filename, ssh = sshformat, devices = len(credentials))
    for c, v in enumerate(credentials):
        code += checks.format(i = c, kh = v.keyhandle, pk = v.pubkey, attr = v.attributes, old = v.oldformat)
        free_block += free.format(i = c)

    code += free_block + end.format(devices = len(credentials))

    print(code)


# Single credentials
print ("Generating single credentials", file=sys.stderr)

for r in resident:
    for p in presence:
        for n in pin:
            for v in verification:
                filename = "credentials/new_" + r + p + v + n
                print ("Generating " + filename, file=sys.stderr)
                line = subprocess.check_output([PUC, "-u"+user, r, p, v, n]).decode('utf-8')
                matches = re.match(r'^.*?:(.*?),(.*?),es256,(.*)', line, re.M)
                with open(filename, "w") as outfile:
                    outfile.write(line)
                credentials = [Credential(keyhandle = matches.group(1),
                                         pubkey = matches.group(2),
                                         attributes = matches.group(3),
                                         oldformat = 0)]

                print_test_case(filename, sshformat, credentials)


# Double credentials
print ("Generating double credentials", file=sys.stderr)

for r in resident:
    for p in presence:
        for n in pin:
            for v in verification:
                filename = "credentials/new_double_" + r + p + v + n
                print ("Generating " + filename, file=sys.stderr)
                line = subprocess.check_output([PUC, "-u"+user, r, p, v, n]).decode('utf-8')

                matches = re.match(r'^.*?:(.*?),(.*?),es256,(.*)', line, re.M)
                with open(filename, "w") as outfile:
                    outfile.write(line)
                credentials = [Credential(keyhandle = matches.group(1),
                                         pubkey = matches.group(2),
                                         attributes = matches.group(3),
                                         oldformat = 0)]

                line = subprocess.check_output([PUC, "-n", r, p, v, n]).decode('utf-8')

                matches = re.match(r'^.*?:(.*?),(.*?),es256,(.*)', line, re.M)
                with open(filename, "a") as outfile:
                    outfile.write(line)
                credentials += [Credential(keyhandle = matches.group(1),
                                         pubkey = matches.group(2),
                                         attributes = matches.group(3),
                                         oldformat = 0)]

                print_test_case(filename, sshformat, credentials)

# Mixed credentials
print ("Mixed double credentials", file=sys.stderr)

options = [("", ""), ("", "-P"), ("-P", ""), ("-P", "-P")]

for p1, p2 in options:
    filename = "credentials/new_mixed_" + p1 +"1" + p2 + "2"
    print ("Generating " + filename, file=sys.stderr)
    line = subprocess.check_output([PUC, "-u"+user, p1]).decode('utf-8')

    matches = re.match(r'^.*?:(.*?),(.*?),es256,(.*)', line, re.M)
    with open(filename, "w") as outfile:
        outfile.write(line)
    credentials = [Credential(keyhandle = matches.group(1),
                              pubkey = matches.group(2),
                              attributes = matches.group(3),
                              oldformat = 0)]

    line = subprocess.check_output([PUC, "-n", p2]).decode('utf-8')

    matches = re.match(r'^.*?:(.*?),(.*?),es256,(.*)', line, re.M)
    with open(filename, "a") as outfile:
        outfile.write(line)
    credentials += [Credential(keyhandle = matches.group(1),
                               pubkey = matches.group(2),
                               attributes = matches.group(3),
                               oldformat = 0)]

    print_test_case(filename, sshformat, credentials)

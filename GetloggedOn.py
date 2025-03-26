#!/usr/bin/python3
from __future__ import division, print_function
import re
import logging
import time
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr, lsat, lsad
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
import socket

logger.init()
logging.getLogger().setLevel(logging.INFO)

class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None, timeout=5):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(timeout)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__disabled = False
        self.__shouldStop = False
        self.__started = False
        self.__scmr = None
        self.__timeout = timeout

    def getRRP(self):
        return self.__rrp

    def connectWinReg(self):
        try:
            rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
            rpc.set_smb_connection(self.__smbConnection)
            rpc.set_connect_timeout(self.__timeout)
            self.__rrp = rpc.get_dce_rpc()
            self.__rrp.connect()
            self.__rrp.bind(rrp.MSRPC_UUID_RRP)
        except Exception as e:
            logging.warning(f"RemoteRegistry connection attempt failed: {str(e)}")
            raise

    def __checkServiceStatus(self):
        try:
            ans = scmr.hROpenSCManagerW(self.__scmr)
            self.__scManagerHandle = ans['lpScHandle']
            ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
            self.__serviceHandle = ans['lpServiceHandle']
            ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
            
            if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
                self.__shouldStop = True
                self.__started = False
            elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
                self.__shouldStop = False
                self.__started = True
            else:
                raise Exception(f'Unknown service state 0x{ans["CurrentState"]:x}')

            if not self.__started:
                ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
                if ans['lpServiceConfig']['dwStartType'] == 0x4:
                    self.__disabled = True
                    scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
                scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
                time.sleep(0.5)

        except Exception as e:
            logging.error(f"Service check failed: {str(e)}")
            raise

    def __restore(self):
        try:
            if self.__shouldStop:
                scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
            if self.__disabled:
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x4)
        except Exception as e:
            logging.warning(f"Restore failed: {str(e)}")

    def finish(self):
        try:
            self.__restore()
            if self.__rrp:
                self.__rrp.disconnect()
            if self.__scmr:
                self.__scmr.disconnect()
        except:
            pass

class Checker:
    def __init__(self, username, password, domain, options):
        self.username = username
        self.password = password
        self.domain = domain
        self.options = options
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = options.aesKey
        self.timeout = options.timeout
        self.port = int(options.port)
        self.output_file = options.output_file
        
        if options.hashes:
            self.lmhash, self.nthash = options.hashes.split(':')

    def write_to_file(self, message):
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(message + '\n')

    def check_host(self, host):
        target_ip = self.options.target_ip or host
        start_time = time.time()
        
        try:
            smb = SMBConnection(host, target_ip, sess_port=self.port, timeout=self.timeout)
            
            if self.options.k:
                smb.kerberosLogin(self.username, self.password, self.domain,
                                 self.lmhash, self.nthash, self.aesKey, self.options.dc_ip)
            else:
                smb.login(self.username, self.password, self.domain,
                        self.lmhash, self.nthash)

            remote_ops = RemoteOperations(smb, self.options.k, self.options.dc_ip, self.timeout)
            
            try:
                remote_ops.connectWinReg()
                dce = remote_ops.getRRP()
                
                users = []
                try:
                    resp = rrp.hOpenUsers(dce)
                    hKey = resp['phKey']
                    index = 0
                    while True:
                        try:
                            resp = rrp.hBaseRegEnumKey(dce, hKey, index)
                            userSid = resp['lpNameOut'].rstrip('\0')
                            if re.match(r"^S-1-5-21-[\d-]+$", userSid):
                                users.append(userSid)
                            index += 1
                        except DCERPCException as e:
                            if e.get_error_code() == 0x103:
                                break
                            raise
                except Exception as e:
                    error_msg = f"[{host:15}] Registry error: {str(e)}"
                    logging.error(error_msg)
                    self.write_to_file(error_msg)
                    return

                if not users:
                    msg = f"[{host:15}] No logged users"
                    logging.info(msg)
                    self.write_to_file(msg)
                    return

                try:
                    lsa_binding = r'ncacn_np:%s[\pipe\lsarpc]' % target_ip
                    rpc = transport.DCERPCTransportFactory(lsa_binding)
                    rpc.set_smb_connection(smb)
                    dce_lsa = rpc.get_dce_rpc()
                    dce_lsa.connect()
                    dce_lsa.bind(lsat.MSRPC_UUID_LSAT)

                    resp = lsad.hLsarOpenPolicy2(dce_lsa, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
                    policyHandle = resp['PolicyHandle']

                    try:
                        resp = lsat.hLsarLookupSids(dce_lsa, policyHandle, users, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
                    except DCERPCException as e:
                        if 'STATUS_SOME_NOT_MAPPED' in str(e):
                            resp = e.get_packet()
                        else:
                            raise

                    logged_users = []
                    for item in resp['TranslatedNames']['Names']:
                        if item['Use'] == SID_NAME_USE.SidTypeUser and not item['Name'].endswith('$'):
                            domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                            logged_users.append(f"{domain}\\{item['Name']}")

                    if logged_users:
                        msg = f"[{host:15}] Logged users: {', '.join(logged_users)}"
                        logging.info(msg)
                        self.write_to_file(msg)
                    else:
                        msg = f"[{host:15}] No active logons"
                        logging.info(msg)
                        self.write_to_file(msg)

                except Exception as e:
                    error_msg = f"[{host:15}] LSA error: {str(e)}"
                    logging.error(error_msg)
                    self.write_to_file(error_msg)

            except Exception as e:
                error_msg = f"[{host:15}] Check failed: {str(e)}"
                logging.error(error_msg)
                self.write_to_file(error_msg)
            
            finally:
                remote_ops.finish()
                smb.logoff()

        except (SessionError, socket.timeout, socket.error) as e:
            error_msg = f"[{host:15}] Connection failed: {str(e)}"
            logging.error(error_msg)
            self.write_to_file(error_msg)
        except Exception as e:
            error_msg = f"[{host:15}] Error: {str(e)}"
            logging.error(error_msg)
            self.write_to_file(error_msg)
        finally:
            debug_msg = f"[{host:15}] Check completed in {time.time()-start_time:.2f}s"
            logging.debug(debug_msg)
            self.write_to_file(debug_msg)

def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(description="Windows Logon Checker (Multi-Threaded)")
    parser.add_argument('target', nargs='?', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('--host-file', help='File containing list of hosts')
    parser.add_argument('--threads', type=int, default=1, help='Number of concurrent threads (default: 1)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds')
    parser.add_argument('-port', choices=['139', '445'], default='445', help='SMB port')
    parser.add_argument('-hashes', metavar="LMHASH:NTHASH", help='NTLM hashes')
    parser.add_argument('-k', action='store_true', help='Use Kerberos authentication')
    parser.add_argument('-aesKey', metavar="hex key", help='AES encryption key')
    parser.add_argument('-dc-ip', metavar="ip", help='Domain controller IP')
    parser.add_argument('-target-ip', metavar="ip", help='Target server IP')
    parser.add_argument('-debug', action='store_true', help='Enable debug output')
    parser.add_argument('-no-pass', action='store_true', help='Don\'t ask for password')
    parser.add_argument('-o', '--output-file', help='Output file to write results')

    if len(sys.argv) == 1:
        parser.print_help()
        return

    options = parser.parse_args()

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remote_name = parse_target(options.target or '')
    password = password if not options.no_pass else ''

    targets = []
    if options.host_file:
        try:
            with open(options.host_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error("Error reading host file: %s", str(e))
            return

    if remote_name:
        targets.append(remote_name)

    if not targets:
        logging.error("No targets specified!")
        return

    checker = Checker(username, password, domain, options)

    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {executor.submit(checker.check_host, host): host for host in targets}
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as e:
                error_msg = f"[{host:15}] Unhandled error: {str(e)}"
                logging.error(error_msg)
                if options.output_file:
                    with open(options.output_file, 'a') as f:
                        f.write(error_msg + '\n')

if __name__ == '__main__':
    main()

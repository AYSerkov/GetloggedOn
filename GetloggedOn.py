#!/usr/bin/python3
from __future__ import division, print_function
import re
import logging
import time
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from impacket import version
from impacket.dcerpc.v5 import transport, rrp, lsat, lsad
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
import socket

class RemoteOperations:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None

    def connectWinReg(self):
        try:
            rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
            rpc.set_smb_connection(self.__smbConnection)
            self.__rrp = rpc.get_dce_rpc()
            self.__rrp.connect()
            self.__rrp.bind(rrp.MSRPC_UUID_RRP)
        except Exception as e:
            logging.warning(f"Ошибка подключения к реестру: {str(e)}")
            raise

    def getRRP(self):
        return self.__rrp

    def finish(self):
        if self.__rrp:
            self.__rrp.disconnect()

class Checker:
    def __init__(self, username, password, domain, options):
        self.username = username
        self.password = password
        self.domain = domain
        self.options = options
        self.lmhash = ''
        self.nthash = ''
        self.timeout = options.timeout
        self.port = int(options.port)
        self.output_file = options.output_file

        if options.hashes:
            self.lmhash, self.nthash = options.hashes.split(':')

    def write_output(self, message):
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(f"{message}\n")

    def check_host(self, host):
        target_ip = self.options.target_ip or host
        start_time = time.time()
        
        try:
            smb = SMBConnection(host, target_ip, sess_port=self.port, timeout=self.timeout)
            
            if self.options.k:
                smb.kerberosLogin(self.username, self.password, self.domain,
                                 self.lmhash, self.nthash, self.options.aesKey, self.options.dc_ip)
            else:
                smb.login(self.username, self.password, self.domain,
                          self.lmhash, self.nthash)
            
            remote_ops = RemoteOperations(smb)
            remote_ops.connectWinReg()
            dce = remote_ops.getRRP()

            # Чтение SID из реестра
            resp = rrp.hOpenUsers(dce)
            hKey = resp['phKey']
            users = []
            index = 0

            while True:
                try:
                    resp = rrp.hBaseRegEnumKey(dce, hKey, index)
                    userSid = resp['lpNameOut'].rstrip('\0')
                    if re.match(r"^S-1-5-21-[\d-]+$", userSid):
                        users.append(userSid)
                    index += 1
                except DCERPCException as e:
                    if e.error_code == 0x103:  # ERROR_NO_MORE_ITEMS
                        break
                    raise

            rrp.hBaseRegCloseKey(dce, hKey)

            
            lsa_binding = r'ncacn_np:%s[\pipe\lsarpc]' % target_ip
            rpc = transport.DCERPCTransportFactory(lsa_binding)
            rpc.set_smb_connection(smb)
            dce_lsa = rpc.get_dce_rpc()
            dce_lsa.connect()
            dce_lsa.bind(lsat.MSRPC_UUID_LSAT)

            resp = lsad.hLsarOpenPolicy2(dce_lsa, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policy_handle = resp['PolicyHandle']

            try:
                resp = lsat.hLsarLookupSids(dce_lsa, policy_handle, users, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
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

            message = f"[{host:15}] Активные сессии: {', '.join(logged_users) if logged_users else 'отсутствуют'}"
            logging.info(message)
            self.write_output(message)

        except SessionError as e:
            error_msg = f"[{host:15}] Ошибка SMB: {e}"
            logging.error(error_msg)
            self.write_output(error_msg)
        except socket.error as e:
            error_msg = f"[{host:15}] Ошибка сети: {e}"
            logging.error(error_msg)
            self.write_output(error_msg)
        except Exception as e:
            error_msg = f"[{host:15}] Неизвестная ошибка: {str(e)}"
            logging.error(error_msg)
            self.write_output(error_msg)
        finally:
            if 'remote_ops' in locals():
                remote_ops.finish()
            if 'smb' in locals():
                smb.logoff()
            debug_msg = f"[{host:15}] Проверка завершена за {time.time()-start_time:.2f}с"
            logging.debug(debug_msg)
            self.write_output(debug_msg)

def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(description="Проверка активных сессий пользователей")
    parser.add_argument('target', nargs='?', help='[[domain/]username[:password]@]<target>')
    parser.add_argument('--host-file', help='Файл со списком хостов')
    parser.add_argument('--threads', type=int, default=2, help='Количество потоков (по умолчанию: 2)')
    parser.add_argument('--timeout', type=int, default=5, help='Таймаут подключения (сек)')
    parser.add_argument('-port', choices=['139', '445'], default='445', help='Порт SMB')
    parser.add_argument('-hashes', metavar="LMHASH:NTHASH", help='NTLM хэши')
    parser.add_argument('-k', action='store_true', help='Использовать Kerberos')
    parser.add_argument('-aesKey', metavar="hex_key", help='AES ключ для Kerberos')
    parser.add_argument('-dc-ip', metavar="ip", help='IP доменного контроллера')
    parser.add_argument('-target-ip', metavar="ip", help='Целевой IP')
    parser.add_argument('-debug', action='store_true', help='Режим отладки')
    parser.add_argument('-no-pass', action='store_true', help='Не запрашивать пароль')
    parser.add_argument('-o', '--output-file', help='Файл для сохранения результатов')

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
            logging.error(f"Ошибка чтения файла хостов: {str(e)}")
            return
    elif remote_name:
        targets.append(remote_name)
    else:
        logging.error("Цели не указаны!")
        return

    checker = Checker(username, password, domain, options)
    
    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {executor.submit(checker.check_host, host): host for host in targets}
        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as e:
                error_msg = f"[{host:15}] Необработанная ошибка: {str(e)}"
                logging.error(error_msg)
                if options.output_file:
                    checker.write_output(error_msg)

if __name__ == '__main__':
    main()

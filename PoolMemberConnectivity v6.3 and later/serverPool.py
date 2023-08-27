import paramiko
import requests
import json
import base64
import time
from colorama import init, Fore, Style
import re

baseurl = f'https://{waf_ip}'
username = ''
password = ''
waf_ip = ''
adomsList = []
no_telnet = []

# Initialize colorama
init()

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(waf_ip, username=username, password=password)
except paramiko.ssh_exception.SSHException as err:
    print(f'{Fore.RED} {err}')
    exit()


def get_adom():
    """
    Retrieves a list of ADOMs (Administrative Domains) from the WAF API URL.

    Returns:
        list: A list of ADOM names.

    Raises:
        None.
    """
    adoms = []
    requests.packages.urllib3.disable_warnings()
    root_header = {"Accept": "application/json", "Authorization": "BASE64_ENCODED_OF_CREDENTIALS"} # {"username":"YOUR_USERNAME","password":"YOUR_PASSWORD","vdom":"root"}
    adoms_list_url = f'{baseurl}/api/v2.0/System/Status.Adoms'
    adoms_res = requests.get(adoms_list_url, verify=False, headers=root_header)
    adoms_json = json.loads(adoms_res.text)
    for adom in adoms_json['results']:
        adoms.append(adom['name'])
    return adoms


def get_server_pool_name(cred):
    """
    Retrieves a list of Pool names from the WAF API URL.

    Returns:
        list: A list of Pool names.

    Raises:
        None.
    """
    temp_poolNames = []
    poolNames = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": cred}
    server_pool_list_url = f'{baseurl}/api/v2.0/cmdb/server-policy/server-pool'
    server_pool_res = requests.get(server_pool_list_url, verify=False, headers=other_header)
    server_pool_json = json.loads(server_pool_res.text)
    for spn in server_pool_json['results'][:10]:
        temp_poolNames.append(spn['name'])
    for i in temp_poolNames:
        poolNames.append(i)
    return poolNames


def get_pool_detail(Pool_name, cred):
    """
    Retrieves the details of a server pool from the WAF API URL.

    Args:
        pool_name (str): The name of the pool.
        adom (str): The referer value for the request headers.

    Returns:
        list: A list of pool details.

    Raises:
        None.
    """
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": cred}
    server_pool_detail_url = f'{baseurl}/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey={Pool_name}'
    server_pool_detail_res = requests.get(server_pool_detail_url, verify=False, headers=other_header)
    server_pool_detail_json = json.loads(server_pool_detail_res.text)
    return server_pool_detail_json['results']


def get_server_policy(cred, Pool_name):
    """
    Retrieves a list of server policies associated with a specific pool name.

    Args:
        adom (str): The ADOM (Administrative Domain) for the request.
        pool_name (str): The name of the pool.

    Returns:
        list: A list of server policy names associated with the pool name.

    Raises:
        None.
    """
    serverPoolList = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": cred}
    server_policy_url = f'{baseurl}/api/v2.0/cmdb/server-policy/policy'
    server_policy_res = requests.get(server_policy_url, verify=False, headers=other_header)
    server_policy_json = json.loads(server_policy_res.text)
    for serverPolicy in server_policy_json['results']:
        if serverPolicy['server-pool'] == Pool_name:
            serverPoolList.append(serverPolicy['name'])
    return serverPoolList


def get_web_protection_profile(cred):
    """
    Retrieves the web protection profiles which do not have
    URL access rules for a given ADOM (Administrative Domain).

    Args:
        adom (str): The name of the ADOM to retrieve the web protection profiles for.

    Returns:
        list: A list of web protection profiles which do not have URL access rules.
    """
    default_wpp = [
        'Inline Standard Protection',
        'Inline Extended Protection',
        'Inline Alert Only',
        'Inline Exchange 2013',
        'Inline Exchange 2016',
        'Inline Exchange 2019',
        'Inline SharePoint 2013',
        'Inline SharePoint 2016',
        'Inline WordPress',
        'Inline Drupal',
    ]
    empty_wpp = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "applicaiton/json", "Authorization": cred}
    wpp_url = f'{baseurl}/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
    wpp_res = requests.get(wpp_url, verify=False, headers=other_header)
    wpp_json = json.loads(wpp_res.text)
    for each_wpp in wpp_json['results']:
        if each_wpp['url-access-policy_val'] == '0' and each_wpp['name'] not in default_wpp:
            empty_wpp.append(each_wpp['name'])
    return empty_wpp


def get_policy_status():
    """
    Retrieves and prints the concurrent, session count and response time
    for specific portals.

    Args:
        None.

    Returns:
        None.
    """
    creds = to_b64(get_adom())
    portals = []
    for cred in creds:
        other_header = {"Accept": "application/json", "Authorization": cred}
        policy_status_url = f'{baseurl}/api/v2.0/policy/policystatus'
        ps_res = requests.get(policy_status_url, verify=False, headers=other_header)
        ps_json = json.loads(ps_res.text)
        for each_ps in ps_json['results']:
            if each_ps['name'] in portals:
                print(f'{each_ps["name"]} conCurrent is :  {each_ps["connCntPerSec"]}')
                print(f'{each_ps["name"]} sessionCount is : {each_ps["sessionCount"]}')
                print(f'{each_ps["name"]} responseTime is : {each_ps["app_response_time"]}')


def to_b64(lst):
    """
    Converts a list of strings to base64-encoded representations.

    Args:
        lst : A list of strings to be converted.

    Returns:
        lst: A list of base64-encoded string
    """
    creds_b64 = []
    for i in lst:
        creds = f'{{"username":"{username}","password":"{password}","vdom":"{i}"}}'
        cred_b64 = base64.b64encode(creds.encode('ascii'))
        adom_b64 = base64.b64encode(i.encode('ascii'))
        adomsList.append(adom_b64)
        creds_b64.append(cred_b64.decode('utf-8'))
    return creds_b64


def clear_file_content():
    """
    Clears the content of specific files.
    """
    with open('records.txt', 'w') as f:
        f.truncate(0)
    with open('servers.txt', 'w') as f:
        f.truncate(0)
    with open('servers.json', 'w') as f:
        f.truncate(0)


def make_json(pool_detail, server_policy):
    """
    Creates a JSON representation of pool details and server policy.

    Args:
        pool_detail (list): A list of pool details.
        server_policy (str): The server policy to be included in the JSON.

    Returns:
        list: A JSON file containing information of pool details and server policy.
    """
    data = {}
    data_list = []
    status = ''
    for i in pool_detail:
        if i['status_val'] == '1':
            status = 'Enable'
        elif i['status_val'] == '2':
            status = 'Maintenance'
        elif i['status_val'] == '3':
            status = 'Disable'
        if i['ip'] != '0.0.0.0':
            data = {
                "address": i['ip'],
                "port": i['port'],
                "status": status,
                "policy": server_policy
            }
        else:
            data = {
                "address": i['domain'],
                "port": i['port'],
                "status": status,
                "policy": server_policy
            }

        data_list.append(data)
    return data_list


def make_records_txt(record_list):
    """
    Writes the IP addresses or domains and ports from a record list to a text file.

    Args:
        record_list (list): A list of records containing IP addresses or domains and ports.

    Returns:
        None
    """
    with open('records.txt', 'a') as f:
        for i in record_list:
            if i['ip'] != '0.0.0.0':
                f.write(f'{i["ip"]}:{i["port"]}\n')
            else:
                f.write(f'{i["domain"]}:{i["port"]}\n')


def make_servers_txt(result, adom, pool, fip, status, policy):
    """
    Appends server connection information to a text file based on the result.

    Args:
        result (list): A list containing the result of the server connection.
        adom (str): The ADOM (Administrative Domain) associated with the server.
        pool (str): The pool to which the server belongs.
        fip (str): The IP address of the server.
        status (str): The status of the server.
        policy (str): The policy associated with the server.

    Returns:
        None.
    """
    with open('servers.txt', 'a') as h:
        if 'Connected' in result[0]:
            print(f'{Fore.GREEN}[+] {fip}-Connected')
            result = f'[+] {adom} | {pool} | {fip} | {status} | {policy} | "Connected" |'
            h.write(f'{result}\n')
        else:
            print(f'{Fore.RED}[-] {fip}-NotConnected')
            result = f'[-] {adom} | {pool} | {fip} | {status} | {policy} | "NotConnected" |'
            h.write(f'{result}\n')


def do_ssh(cmd):
    """
    Executes an SSH command on a remote server and returns the result.

    Args:
        cmd (str): The SSH command to be executed.

    Returns:
        list: A list of strings representing the result of the SSH command.
    """
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.close()
    time.sleep(.5)
    result = stdout.readlines()
    return result


def get_arp_list():
    """
   Retrieves the ARP (Address Resolution Protocol) list from a device and saves it to a file.

    Args:
        None.

    Returns:
        None.

    """
    print(f'{Style.RESET_ALL}----------------------------------')
    print('Getting Device ARP list . . .')
    time.sleep(3)
    with open('servers.txt', 'a') as m:
        m.write(f'\n\n-------------------------------Arp Table-----------------------------\n\n')
        result = do_ssh('diagnose network arp list')
        formatted_output = str(result).replace('\\n', '\n').replace('\\t', '\t')
        m.write(str(formatted_output))
    print('ARP list saved to servers.txt file.')


def check_ping():
    """
    Checks the ping status of servers that have no Telnet access and writes the results
    to a file.

    Args:
        None.

    Returns:
        None.
    """
    print(f'\n{Style.RESET_ALL}Found {Fore.RED}{len(no_telnet)} {Style.RESET_ALL}server(s) with no Telnet access.')
    ping_answer = input(
        f'{Style.RESET_ALL}Do you want to ping servers that have no Telnet access? {Fore.GREEN}(y/n) {Style.RESET_ALL}: ')
    if ping_answer == 'y' or ping_answer == 'yes':
        print('----------------------------------')
        print(f'{Style.RESET_ALL}Pinging Servers with no Telnet: ')
        with open('servers.txt', 'a') as l:
            l.write(f'\n-------------------------------Ping Status-----------------------------\n\n')
            for address in no_telnet:
                result = do_ssh(f'execute ping-option repeat-count 1\nexecute ping {address}')
                # print(result)
                if '64 bytes' in result[2]:
                    print(f'{Fore.GREEN}[+] {address} is Up')
                    l.write(f'{address} | no Telnet | Yes Ping\n')
                else:
                    print(f'{Fore.RED}[-] {address} is Down')
                    l.write(f'{address} | no Telnet | No Ping\n')
    else:
        print(f'{Fore.GREEN}Good bye :)')
        exit()


def main():
    creds = to_b64(get_adom())
    fdict = {}
    pattern = r'"([^"]+)"[^"]*$'
    clear_file_content()
    # Loops through all adoms and gets pool details.
    for adom, cred in zip(adomsList[:2], creds):
        adom_decode = base64.b64decode(adom).decode("utf-8")
        print(f'{Style.RESET_ALL}\nGetting {Fore.YELLOW}"{adom_decode}"{Style.RESET_ALL} pool members :')
        spn = get_server_pool_name(cred)
        sdict = {}
        fdict[adom_decode] = sdict
        totalPoolMember = 0
        for i in spn:
            print(f'{Fore.GREEN}[+] {i}')
            serverPool = get_server_policy(cred, i)
            poolDetail = get_pool_detail(i, cred)
            finalJson = make_json(poolDetail, serverPool)
            make_records_txt(poolDetail)
            sdict[i] = finalJson
            totalPoolMember += 1
        print(f'{Style.RESET_ALL}Total Pool Members : {Fore.YELLOW}{totalPoolMember}\n')

    with open('servers.json', 'w') as f:
        f.write(json.dumps(fdict))

    # Add web Protection Profile section to the servers.txt file
    with open('servers.txt', 'a') as h:
        h.write(f'-------------------------------Web Protection Profiles-----------------------------\n\n')
        h.write(f'Web protection profiles without URL access rule :\n')
        for adom, cred in zip(adomsList, creds):
            adom_decode = base64.b64decode(adom).decode("utf-8")
            wpp = get_web_protection_profile(cred)
            h.write(f'\n{adom_decode}|{str(wpp)}\n')
        h.write(f'\n-------------------------------Pool Members Status---------------------------------\n')
        h.write(f'| VDOM | Pool Member | Address | Status | Policy Name | Connectivity |\n\n')

    print(f'{Style.RESET_ALL}\nAll data fetched and saved to "servers.txt" file')

    answer = input(f'{Style.RESET_ALL}do you want to check for connectivity ? {Fore.GREEN}(y/n) {Style.RESET_ALL}:  ')

    if answer == 'y' or answer == 'yes':
        print('----------------------------------')
        print(f'{Style.RESET_ALL}Checking Server Availability: ')
        with open('servers.json') as d:
            data = json.load(d)
            for adom, pool in data.items():
                for pool, detail in pool.items():
                    for innerdict in detail:
                        fip = f'{innerdict["address"]}:{innerdict["port"]}'
                        status = innerdict['status']
                        policy = innerdict['policy']
                        result = do_ssh(f'execute telnettest {fip}')
                        if 'Connected' not in result[0]:
                            no_telnet.append(innerdict["address"])
                        make_servers_txt(result, adom, pool, fip, status, policy)
    else:
        print(f'{Fore.GREEN}Good bye :)')
        exit()

    check_ping()

if __name__ == '__main__':
    main()

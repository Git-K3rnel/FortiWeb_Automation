import paramiko
import requests
import json
import base64
import time
from colorama import init, Fore, Style
import re

baseurl = ''
username = ''
password = ''
waf_ip = ''

# Initialize colorama
init()


def getAdom():
    adoms = []
    requests.packages.urllib3.disable_warnings()
    root_header = {"Accept": "application/json", "Authorization": "BASE64_ENCODED_CREDS_OF_ROOT_ADOM"}
    adoms_list_url = f'{baseurl}/api/v2.0/System/Status.Adoms'
    adoms_res = requests.get(adoms_list_url, verify=False, headers=root_header)
    adoms_json = json.loads(adoms_res.text)
    for adom in adoms_json['results'] :
        adoms.append(adom['name'])
    return adoms


def getServerPoolName(adom):
    temp_poolNames = []
    poolNames = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": adom}
    server_pool_list_url = f'{baseurl}/api/v2.0/cmdb/server-policy/server-pool'
    server_pool_res = requests.get(server_pool_list_url, verify=False, headers=other_header)
    server_pool_json = json.loads(server_pool_res.text)
    for spn in server_pool_json['results']:
        temp_poolNames.append(spn['name'])
    for i in temp_poolNames :
            poolNames.append(i)
    return poolNames


def getPoolDetail(poolName,adom):
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": adom}
    server_pool_detail_url = f'{baseurl}/api/v2.0/cmdb/server-policy/server-pool/pserver-list?mkey={poolName}'
    server_pool_detail_res = requests.get(server_pool_detail_url, verify=False, headers=other_header)
    server_pool_detail_json = json.loads(server_pool_detail_res.text)
    return server_pool_detail_json['results']


def getServerPolicy(adom,PoolName):
    serverPoolList = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": adom}
    server_policy_url = f'{baseurl}/api/v2.0/cmdb/server-policy/policy'
    server_policy_res = requests.get(server_policy_url, verify=False, headers=other_header)
    server_policy_json = json.loads(server_policy_res.text)
    for serverPolicy in server_policy_json['results'] :
        if serverPolicy['server-pool'] == PoolName:
            serverPoolList.append(serverPolicy['name'])
    return serverPoolList


def getWebProtectionProfile(adom):
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
    other_header = {"Accept": "applicaiton/json", "Authorization": adom}
    wpp_url = f'{baseurl}/api/v2.0/cmdb/waf/web-protection-profile.inline-protection'
    wpp_res = requests.get(wpp_url, verify=False, headers=other_header)
    wpp_json = json.loads(wpp_res.text)
    for each_wpp in wpp_json['results'] :
        if each_wpp['url-access-policy_val'] == '0' and each_wpp['name'] not in default_wpp:
            empty_wpp.append(each_wpp['name'])
    return empty_wpp


def to_b64(list) :
    adoms_b64 = []
    for i in list:
        jsonAdom = f'","vdom":"{i}"'
        jsonAdom += '}'
        b64 = base64.b64encode(jsonAdom.encode('ascii'))
        adoms_b64.append(b64.decode('utf-8'))
    return adoms_b64


def clearFileContent():
    with open('records.txt','w') as f:
        f.truncate(0)
    with open('servers.txt','w') as f:
        f.truncate(0)
    with open('servers.json','w') as f:
        f.truncate(0)


def makeJson(poolDetail, serverPolicy):
    data = {}
    data_list = []
    status = ''
    for i in poolDetail:
        if i['status_val'] == '1' :
            status = 'Enable'
        elif i['status_val'] == '2' :
            status = 'Maintenance'
        elif i['status_val'] == '3':
            status = 'Disable'
        if i['ip'] != '0.0.0.0':
            data = {
                "address" : i['ip'],
                "port": i['port'],
                "status": status,
                "policy" : serverPolicy 
            }
        else :
            data = {
                "address" : i['domain'],
                "port": i['port'],
                "status": status,
                "policy" : serverPolicy 
            }

        data_list.append(data)
    return data_list


def makeRecordsTXT(record_list):
    with open('records.txt', 'a') as f :
        for i in record_list :
            if i['ip'] != '0.0.0.0':
                f.write(f'{i["ip"]}:{i["port"]}\n')
            else :
                f.write(f'{i["domain"]}:{i["port"]}\n')


def makeServersTXT(result,adom,pool,fip,status,policy):
    with open('servers.txt', 'a') as h :
            if 'Connected' in result[0] :
                print(f'{Fore.GREEN}[+] {fip}-Connected')
                result = f'[+] {adom} | {pool} | {fip} | {status} | {policy} | "Connected" |'
                h.write(f'{result}\n')
            else:
                print(f'{Fore.RED}[-] {fip}-NotConnected')
                result = f'[-] {adom} | {pool} | {fip} | {status} | {policy} | "NotConnected" |'
                h.write(f'{result}\n')


def do_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(waf_ip, username=username, password=password)
    with open('servers.json') as d:
        data = json.load(d)
        for adom, pool in data.items() :
            for pool, detail in pool.items():
                for innerdict in detail :
                    fip = f'{innerdict["address"]}:{innerdict["port"]}'
                    status = innerdict['status']
                    policy = innerdict['policy']
                    stdin, stdout, stderr = ssh.exec_command(f'execute telnettest {fip}')
                    stdin.close()
                    result = stdout.readlines()
                    makeServersTXT(result,adom,pool,fip,status,policy)


def main():
    adoms = to_b64(getAdom())
    fdict = {}
    pattern = r'"([^"]+)"[^"]*$'
    clearFileContent()
    for adom in adoms:
        adom_decode = base64.b64decode(adom).decode("utf-8")
        match = re.search(pattern, adom_decode)
        captureVdom = match.group(1)
        print(f'{Style.RESET_ALL}\nGetting {Fore.YELLOW}"{captureVdom}"{Style.RESET_ALL} pool members :')
        spn = getServerPoolName(adom)
        sdict= {}
        fdict[captureVdom] = sdict
        totalPoolMember = 0
        for i in spn :
            print(f'{Fore.GREEN}[+] {i}')
            serverPool = getServerPolicy(adom,i)
            poolDetail = getPoolDetail(i,adom)
            finalJson = makeJson(poolDetail,serverPool)
            makeRecordsTXT(poolDetail)
            sdict[i] = finalJson
            totalPoolMember += 1
        print(f'{Style.RESET_ALL}Total Pool Members : {Fore.YELLOW}{totalPoolMember}\n')
    
    with open('servers.json', 'w') as f :
        f.write(json.dumps(fdict))

    with open('servers.txt', 'a') as h :
        h.write(f'-------------------------------Web Protection Profiles-----------------------------\n\n')
        h.write(f'Web protection profiles without URL access rule :\n')
        for adom in adoms:
            adom_decode = base64.b64decode(adom).decode("utf-8")
            match = re.search(pattern, adom_decode)
            captureVdom = match.group(1)
            wpp = getWebProtectionProfile(adom)
            h.write(f'\n{captureVdom}|{str(wpp)}\n')
        h.write(f'\n-------------------------------Pool Members Status---------------------------------\n')
        h.write(f'| VDOM | Pool Member | Address | Status | Policy Name | Connectivity |\n\n')

    print(f'{Style.RESET_ALL}\nAll data fetched and saved to "servers.txt" file')

    answer = input(f'{Style.RESET_ALL}do you want to check for connectivity ? {Fore.GREEN}(y/n) {Style.RESET_ALL}:  ')

    if answer == 'y' or answer == 'yes' :
        print('----------------------------------')
        print(f'{Style.RESET_ALL}Checking Server Availability: ')
        do_ssh()
    else :
        print(f'{Fore.GREEN}Good bye :)')
        exit()

if __name__ == '__main__' :
    main()

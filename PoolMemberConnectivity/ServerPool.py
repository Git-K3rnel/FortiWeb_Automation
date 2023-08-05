import paramiko
import requests
import json
import base64
import time
from colorama import init, Fore, Style

waf_IP = 'WAF_IP_ADDRESS'
baseurl = f'https://{waf_IP}:90/'
username = 'WAF_USERNAME'
password ='WAF_PASSWORD'
adomsList = []

# Initialize colorama
init()

def getAdom():
    adoms = []
    requests.packages.urllib3.disable_warnings()
    root_header = {"Accept": "applicaiton/json", "Authorization": "BASE64_ENCODED_CREDS_OF_ROOT_ADOM"} #(username:password:root)
    adoms_list_url = f'{baseurl}/api/v1.0/System/Status/Adoms'
    adoms_res = requests.get(adoms_list_url, verify=False, headers=root_header)
    adoms_json = json.loads(adoms_res.text)
    for adom in adoms_json :
        adoms.append(adom['name'])
    return adoms


def getServerPoolName(cred):
    temp_poolNames = []
    poolNames = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "applicaiton/json", "Authorization": cred}
    server_pool_list_url = f'{baseurl}/api/v1.0/ServerObjects/Server/ServerPoolList'
    server_pool_res = requests.get(server_pool_list_url, verify=False, headers=other_header)
    server_pool_json = json.loads(server_pool_res.text)
    for spn in server_pool_json:
        temp_poolNames.append(spn['name'])
    for i in temp_poolNames :
            poolNames.append(i)
    return poolNames


def getPoolDetail(poolName,cred):
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "applicaiton/json", "Authorization": cred}
    server_pool_detail_url = f'{baseurl}/api/v1.0/ServerObjects/Server/ServerPool/{poolName}/EditServerPoolRule'
    server_pool_detail_res = requests.get(server_pool_detail_url, verify=False, headers=other_header)
    server_pool_detail_json = json.loads(server_pool_detail_res.text)
    return server_pool_detail_json


def getServerPolicy(cred,PoolName):
    serverPoolList = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "applicaiton/json", "Authorization": cred}
    server_policy_url = f'{baseurl}/api/v1.0/Policy/ServerPolicy/ServerPolicy'
    server_policy_res = requests.get(server_policy_url, verify=False, headers=other_header)
    server_policy_json = json.loads(server_policy_res.text)
    for serverPolicy in server_policy_json :
        if serverPolicy['serverPool'] == PoolName:
            serverPoolList.append(serverPolicy['name'])
    return serverPoolList


def getWebProtectionProfile(cred):
    default_wpp = ['Inline High Level Security',
    'Inline Medium Level Security',
    'Inline Alert Only',
    'Inline Exchange 2013',
    'Inline Exchange 2016',
    'Inline SharePoint 2013',
    'Inline SharePoint 2016',
    'Inline WordPress',
    'Inline Drupal',
    'Self_ProtectionPolicy']
    empty_wpp = []
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "applicaiton/json", "Authorization": cred}
    wpp_url = f'{baseurl}/api/v1.0/Policy/WebProtectionProfile/InlineProtectionProfile'
    wpp_res = requests.get(wpp_url, verify=False, headers=other_header)
    wpp_json = json.loads(wpp_res.text)
    for each_wpp in wpp_json :
        if 'URLAccess' not in each_wpp and each_wpp['name'] not in default_wpp:
            empty_wpp.append(each_wpp['name'])
    return empty_wpp


def to_b64(list) :
    creds_b64 = []
    for i in list:
        creds = f'{username}:{password}:{i}'
        cred_b64 = base64.b64encode(creds.encode('ascii'))
        adom_b64 = base64.b64encode(i.encode('ascii'))
        adomsList.append(adom_b64)
        creds_b64.append(cred_b64.decode('utf-8'))
    return creds_b64


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
        if i['status'] == 1 :
            status = 'Disable'
        elif i['status'] == 2 :
            status = 'Enable'
        elif i['status'] == 3:
            status = 'Maintenance'
        data = {
            "ip" : i['ip'],
            "port": i['port'],
            "status": status,
            "policy" : serverPolicy 
        }   
        data_list.append(data)
    return data_list


def makeRecordsTXT(record_list):
    with open('records.txt', 'a') as f :
        for i in record_list :
            f.write(f'{i["ip"]}:{i["port"]}\n')


def makeServersTXT(result,adom,pool,fip,status,policy):
    with open('servers.txt', 'a') as h :
            if 'Connected' in result[0] :
                print(f'{Fore.GREEN}[+] {fip}-Connected')
                result = f'[+] {adom}|{pool}|{fip}|{status}|{policy}|"Connected"'
                h.write(f'{result}\n')
            else:
                print(f'{Fore.RED}[-] {fip}-NotConnected')
                result = f'[-] {adom}|{pool}|{fip}|{status}|{policy}|"NotConnected"'
                h.write(f'{result}\n')


def do_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(waf_IP, username=username, password=password)
    with open('servers.json') as d:
        data = json.load(d)
        for adom, pool in data.items() :
            for pool, detail in pool.items():
                for innerdict in detail :
                    fip = f'{innerdict["ip"]}:{innerdict["port"]}'
                    status = innerdict['status']
                    policy = innerdict['policy']
                    stdin, stdout, stderr = ssh.exec_command(f'execute telnettest {fip}')
                    stdin.close()
                    result = stdout.readlines()
                    makeServersTXT(result,adom,pool,fip,status,policy)


def main():
    creds = to_b64(getAdom())
    fdict = {}
    clearFileContent()
    for adom,cred in zip (adomsList,creds):
            adom_decode = base64.b64decode(adom).decode("utf-8")
            print(f'{Style.RESET_ALL}\nGetting "{adom_decode}" pool members :')
            spn = getServerPoolName(cred)
            sdict= {}
            fdict[adom_decode] = sdict
            for i in spn :
                print(f'{Fore.GREEN}[+] {i}')
                serverPool = getServerPolicy(cred,i)
                poolDetail = getPoolDetail(i,cred)
                finalJson = makeJson(poolDetail,serverPool)
                makeRecordsTXT(poolDetail)
                sdict[i] = finalJson
    
    with open('servers.json', 'w') as f :
        f.write(json.dumps(fdict))

    with open('servers.txt', 'a') as h :
        h.write(f'-------------------------------Web Protection Profiles-----------------------------\n\n')
        h.write(f'Web protection profiles without URL access rule :\n')
        for adom,cred in zip (adomsList,creds):
            adom_decode = base64.b64decode(adom).decode("utf-8")
            wpp = getWebProtectionProfile(cred)
            h.write(f'\n{adom_decode}|{str(wpp)}\n')
        h.write(f'\n-------------------------------Pool Members Status---------------------------------\n\n')

    print(f'{Style.RESET_ALL}\nAll data fetched and saved to "servers.txt" file')

    answer = input(f'{Style.RESET_ALL}do you want to check for connectivity ? {Fore.GREEN}(y/n) {Style.RESET_ALL}:  ')

    if answer == 'y' or answer == 'yes' :
        print('----------------------------------')
        print(f'{Style.RESET_ALL}Checking Server Availability: ')
        do_ssh()
    else : 
        print(f'Good bye :)')
        exit()

if __name__ == '__main__' :
    main()

import requests
import json
import re


firewall1_post_data = {}
firewall1_login_url = ''
firewall1_login_headers = {}

firewall2_post_data = {}
firewall2_login_url = ''
firewall2_login_headers = {}


def save_firewall1_firewall_policy_json():
    requests.packages.urllib3.disable_warnings()
    res = requests.post(firewall1_login_url, data=firewall1_post_data, verify=False, headers=firewall1_login_headers)
    rawHeader = str(res.headers)
    cookie = rawHeader.split(',')[2].split(';')[0].split(':')[1].replace("'","").strip()
    policy_url = 'https://IP_ADDRESS/api/v2/cmdb/firewall/policy?with_meta=1&datasource=1&exclude-default-values=1&start=0&count=1500&vdom=root'
    auth_headers = {"Cookie":cookie,"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"}
    res2 = requests.get(policy_url,headers=auth_headers,verify=False)
    result_dict = res2.json()

    with open('firewall1.json','w') as file:
        json.dump(result_dict, file)


def check_firewall1_policy(vip):
    info_list = []
    with open('firewall1.json','r') as newfile:
        json_data = json.load(newfile)


    for i in range(len(json_data['results'])):
        
        has_destination_address = json_data['results'][i].get('dstaddr')
        if has_destination_address is None:
            pass
        else:
            dstAddress_array = json_data['results'][i]['dstaddr']
            for dstadd in dstAddress_array:
                temp_list = []
                if bool(re.search(f'{vip}$', dstadd['name'])):#if vip in dstadd['name']:
                    get_status = json_data['results'][i].get('status')
                    if get_status == 'disable':
                        pass
                    else:
                        srcAddress_array = json_data['results'][i]['srcaddr']
                        for srcadd in srcAddress_array:
                            if srcadd['name'] == 'all':
                                temp_list.append('firewall1')
                                temp_list.append(json_data['results'][i]['policyid'])
                                first_part_public_ip = dstadd['name'].split('to')[0]
                                temp_list.append(first_part_public_ip)
                                info_list.append(temp_list)
    return info_list


def save_firewall2_firewall_policy_json():
    requests.packages.urllib3.disable_warnings()
    res = requests.post(firewall2_login_url, data=firewall2_post_data, verify=False, headers=firewall2_login_headers)
    rawHeader = str(res.headers)
    cookie = rawHeader.split(',')[2].split(';')[0].split(':')[1].replace("'","").strip()
    policy_url = 'https://IP_ADDRESS/api/v2/cmdb/firewall/policy?with_meta=1&datasource=1&exclude-default-values=1&start=0&count=1500&vdom=root'
    auth_headers = {"Cookie":cookie,"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"}
    res2 = requests.get(policy_url,headers=auth_headers,verify=False)
    result_dict = res2.json()

    with open('firewall2.json','w') as file:
        json.dump(result_dict, file)


def check_firewall2_policy(vip):
    info_list = []
    with open('firewall2.json','r') as newfile:
        json_data = json.load(newfile)


    for i in range(len(json_data['results'])):
        
        has_destination_address = json_data['results'][i].get('dstaddr')
        if has_destination_address is None:
            pass
        else:
            dstAddress_array = json_data['results'][i]['dstaddr']
            for dstadd in dstAddress_array:
                temp_list = []
                if bool(re.search(f'{vip}$', dstadd['name'])):#if vip in dstadd['name']:
                    get_status = json_data['results'][i].get('status')
                    if get_status == 'disable':
                        pass
                    else:
                        srcAddress_array = json_data['results'][i]['srcaddr']
                        for srcadd in srcAddress_array:
                            if srcadd['name'] == 'all':
                                temp_list.append('firewall2')
                                temp_list.append(json_data['results'][i]['policyid'])
                                first_part_public_ip = dstadd['name'].split('to')[0]
                                temp_list.append(first_part_public_ip)
                                info_list.append(temp_list)
    return info_list
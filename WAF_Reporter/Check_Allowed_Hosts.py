import requests
import json
import base64
from colorama import init, Fore, Style
from getpass import getpass
import sys

baseurl = ''
username = input('Enter username: ')
password = getpass('Enter Password: ')
username = ''
password = ''
adomsList = []
root_auth_string = f'{{"username":"{username}","password":"{password}","vdom":"root"}}'
root_auth_base64 = base64.b64encode(root_auth_string.encode('ascii'))

def get_adom():
    adoms = []
    requests.packages.urllib3.disable_warnings()
    root_header = {"Accept": "application/json",
                   "Authorization": root_auth_base64}
    adoms_list_url = f'{baseurl}/api/v2.0/System/Status.Adoms'
    try:
        adoms_res = requests.get(
            adoms_list_url, verify=False, headers=root_header, timeout=2)
        if adoms_res.status_code == 401:
            print(f'{Fore.RED}[-] Authentication Faild, try again.')
            exit()
    except requests.exceptions.Timeout:
        print(f'{Fore.RED} [-] Connection Timed out. . .')
        exit()
    adoms_json = json.loads(adoms_res.text)
    for adom in adoms_json['results']:
        adoms.append(adom['name'])
    return adoms


def to_b64(lst):
    creds_b64 = []
    for i in lst:
        creds = f'{{"username":"{username}","password":"{password}","vdom":"{i}"}}'
        cred_b64 = base64.b64encode(creds.encode('ascii'))
        adom_b64 = base64.b64encode(i.encode('ascii'))
        adomsList.append(adom_b64)
        creds_b64.append(cred_b64.decode('utf-8'))
    return creds_b64


def get_api_response(url, cred):
    requests.packages.urllib3.disable_warnings()
    other_header = {"Accept": "application/json", "Authorization": cred}
    api_url = f'{baseurl}{url}'
    try:
        api_res = requests.get(api_url, verify=False, headers=other_header)
        if api_res.status_code == 401:
            print(f'{Fore.RED}[-] Authentication Faild, try again.')
            exit()
        if api_res.status_code == 500:
            print(f'{Fore.RED}[-] Internal Server Error, try again.')
            exit()
    except requests.exceptions.Timeout:
        print(f'{Fore.RED} [-] Connection Timed out. . .')
        exit()
    api_json = json.loads(api_res.text)
    return api_json['results']


def get_server_policy_list(cred):
    all_server_policies = get_api_response('/api/v2.0/cmdb/server-policy/policy', cred)
    return all_server_policies

def get_policy_content_route_size(cred, policy_name):
    content_route_size = 0
    url = f'/api/v2.0/cmdb/server-policy/policy?mkey={policy_name}'
    policy_details = get_api_response(url, cred)
    content_route_size = policy_details['sz_http-content-routing-list']
    return content_route_size


def allowed_policy_content_routes(cred, policy_name):
    isAllowed = True
    allowed_policy_content_routes = []
    url1 = f'/api/v2.0/cmdb/server-policy/policy/http-content-routing-list?mkey={policy_name}'
    content_route_list = get_api_response(url1, cred)
    for content_route_entry in content_route_list:
        content_route_id = content_route_entry['id']
        url2 = f'/api/v2.0/cmdb/server-policy/policy/http-content-routing-list?mkey={policy_name}&sub_mkey={content_route_id}'
        content_route_detail = get_api_response(url2, cred)
        web_protection_profile_name = content_route_detail['web-protection-profile']
        web_protection_profile_name_encoded = requests.utils.quote(web_protection_profile_name)
        url3 = f'/api/v2.0/cmdb/waf/web-protection-profile.inline-protection?mkey={web_protection_profile_name_encoded}'
        web_protection_profile_detail = get_api_response(url3, cred)
        url_access_policy_name = web_protection_profile_detail['url-access-policy']
        if url_access_policy_name == 'Deny Zone to Zone':
            continue
        else:
            url4 = f'/api/v2.0/cmdb/waf/url-access.url-access-policy/rule?mkey={url_access_policy_name}'
            url_access_policy_list = get_api_response(url4, cred)
            for url_access_rule in url_access_policy_list:
                if url_access_rule['url-access-rule-name'] == 'deny' or url_access_rule['url-access-rule-name'] == 'Deny' or url_access_rule['url-access-rule-name'] == 'block' or url_access_rule['url-access-rule-name'] == 'Block':
                    isAllowed = False
                else:
                    pass
            if isAllowed:
                allowed_policy_content_routes.append(
                    content_route_entry['content-routing-policy-name'])
    return allowed_policy_content_routes

def allowed_normal_policy(cred,policy_name):
    isAllowed = True
    allowed_policies = []
    url1 = f'/api/v2.0/cmdb/server-policy/policy?mkey={policy_name}'
    policy_detail = get_api_response(url1,cred)
    web_protection_profile_name = policy_detail['web-protection-profile']
    if web_protection_profile_name == '':
        print(f'{policy_name} has no wpp')
    else:
        web_protection_profile_name_encoded = requests.utils.quote(web_protection_profile_name)
        url3 = f'/api/v2.0/cmdb/waf/web-protection-profile.inline-protection?mkey={web_protection_profile_name_encoded}'
        web_protection_profile_detail = get_api_response(url3, cred)
        url_access_policy_name = web_protection_profile_detail['url-access-policy']
        if url_access_policy_name == 'Deny Zone to Zone':
            pass
        else:
            url4 = f'/api/v2.0/cmdb/waf/url-access.url-access-policy/rule?mkey={url_access_policy_name}'
            url_access_policy_list = get_api_response(url4, cred)
            for url_access_rule in url_access_policy_list:
                if url_access_rule['url-access-rule-name'] == 'deny' or url_access_rule['url-access-rule-name'] == 'Deny' or url_access_rule['url-access-rule-name'] == 'block' or url_access_rule['url-access-rule-name'] == 'Block' or url_access_rule['url-access-rule-name'] == 'deny 160' or url_access_rule['url-access-rule-name'] == 'deny 68':
                    isAllowed = False
                else:
                    pass
            if isAllowed:
                allowed_policies.append(policy_name)
    return allowed_policies


def main():
    creds = to_b64(get_adom())
    # step1 get all server policy names
    for adom, cred in zip(adomsList[], creds[]):
        adom_decode = base64.b64decode(adom).decode("utf-8")
        print(f'Get {adom_decode} list')
        server_policy_list = get_server_policy_list(cred)
        # step2 check if policy has content route
        for policy_entry in server_policy_list:
            content_route_size = get_policy_content_route_size(cred, policy_entry['name'])
            if content_route_size != 0:
                pass
                allowed_content_routes = allowed_policy_content_routes(cred, policy_entry['name'])
                print(
                    f'{policy_entry["name"]}:{policy_entry["vserver"]}:{allowed_content_routes}')
            else:
                allowed_normal_policies = allowed_normal_policy(cred,policy_entry['name'])
                print(allowed_normal_policies)
            # print(f'{policy_name} has {content_route_size}')


if __name__ == '__main__':
    main()

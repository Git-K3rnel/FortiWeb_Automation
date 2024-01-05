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

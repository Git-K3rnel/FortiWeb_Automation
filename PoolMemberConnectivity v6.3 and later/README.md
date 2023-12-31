# Pool Member Connectivity v6.3 and later

In this script i try to find all pool members and their ports in a `FortiWeb` device with `API` calls and execute `telnettest` on them.

then results are saved in `servers.txt` file, this script aslo finds the `server policy` associated with corresponding `server pool`.

rest of the features are as follows :

## Features
- Finds all pool members in all ADOMS.
- Finds all ports associated with pool members.
- Finds all pool members status (enable/disable).
- Finds all web protection profiles that don't have URL access rule.
- Finds which server policy a pool member belongs to.
- Finds session information of the WAF (concurrent sessions, session count, response time)
- Gets device ARP list.
- Checks if a pool member is live on its port by executing `telnettest` command on WAF.
- Pool members which do not have telnet access are pinged to make sure they are down.
- Creates a JSON file containing all information mentioned above.
- Creates a greppable file (servers.txt) containing all information mentioned above.
- User-friendly command-line interface.
- Colorful output to better detect the messages on terminal.

## Changes

1. In fortiweb version 6.3 and later authenticatoin mechanism has changed.

    you need to provide `username`, `password` and `vdom` in a json format like this :

    ```bash
    { 
        "username": "admin",
        "password": "xxxxx",
        "vdom": "root"
    }
    ```

    and then base64 encode it and put it in `Authorization` header.

2. API paths have changed which you can find them in fortinet REST API Documentation or through inspecting request in browser console.
3. Some data structres have changed.

## Requirement
Before using this script you need to have these components installed :
```bash
- python 3.x >
- paramiko
- requests
- json
- base64
- colorama
```

## Usage

Just provide the IP address of your waf device in `waf_IP` variable and your username and password:

```python
waf_IP = 'WAF_IP_ADDRESS'
baseurl = f'https://{waf_IP}/'
username = 'USERNAME'
password ='PASSWORD'
```


You can also run this script with `argparse.py` file and pass the argument to it to do its job :


```python
python.exe argparse -h

usage: PROG [-h] [-m] [-si] [-ar]

WAF Menue

options:
  -h, --help          show this help message and exit
  -m, --main          Runs script main function
  -si, --sessionInfo  Gets seesion count, concurrent sessions and response
                      time
  -ar, --arplist      Gets Device ARP list
```

## Output

After running the script, three files will be generated :
- 1.Records.txt : Contains servers IP:Port that is used by script.
- 2.Servers.txt : A grepable file which you can use to see the final result (this is the file you should look at)
- 3.Servers.json : A json file generated for internal use by script, you can also use it to see the result as json.

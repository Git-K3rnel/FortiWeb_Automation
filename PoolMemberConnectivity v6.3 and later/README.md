# Pool Member Connectivity v6.3 and later

In this script i try to find all pool members and their ports in a `FortiWeb` device with `API` calls and execute `telnettest` on them.

then results are saved in `servers.txt` file, this script aslo finds the `server policy` associated with corresponding `server pool`

## Features
- Finds all pool members in all ADOMS
- Finds all ports associated with pool members
- Finds all pool members status (enable/disable)
- Finds all web protection profiles that don't have URL access rule
- Finds which server policy a pool member belongs to
- Finds Web Protection Profiles which does not have URL access rule
- Checks if a pool member is live on its port by executing `telnettest` command on WAF
- Creates a JSON file containing all information mentioned above
- Creates a greppable file (servers.txt) containing all information mentioned above
- Colorful output to better detect the messages on terminal

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

## Usage

Just provide the IP address of your waf device in `baseurl` variable and set your base64 credentials of fortiweb in `Authorization` header in script

```python
waf_IP = 'WAF_IP_ADDRESS'
baseurl = f'https://{waf_IP}/'
username = 'USERNAME'
password ='PASSWORD'
root_header = {"Accept": "applicaiton/json", "Authorization": "BASE64_ENCODED_CREDS_OF_ROOT_ADOM"} #{"username":"admin","password":"xxxxx","vdom":"root"}
```

## Output

After running the script, three files will be generated :
- 1.Records.txt : Contains servers IP:Port that is used by script.
- 2.Servers.txt : A grepable file which you can use to see the final result (this is the file you should look at)
- 3.Servers.json : A json file generated for internal use by script, you can also use it to see the result as json.

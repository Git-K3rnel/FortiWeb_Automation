# Pool Member Connectivity

In this script i try to find all pool members and their ports in a `FortiWeb` device with `API` calls and execute `telnet` on them.

then results are saved in `servers.txt` file, this script aslo finds the `server policy` associated with corresponding `server pool`

## Usage

Just provide the IP address of your waf device in `baseurl` variable and set your base64 credentials of fortiweb in `Authorization` header in script

```python
baseurl = https://WAF_IP_ADDRESS/
username = 'USERNAME'
password ='PASSWORD'
root_header = {"Accept": "applicaiton/json", "Authorization": "BASE64_ENCODED_CREDS_OF_ROOT_ADOM"} #(username:password:root)
```

## SSH Connection

For SSH connection i use `paramiko`,  so don't forget to set your username and password in `do_ssh()` function :

```python
ssh.connect('WAF_IP_ADDRESS', username='YOUR_USERNAME', password='YOUR_PASSWORD')
```

## Output

After running the script, three files will be generated :
- 1.Records.txt--------------------Contains servers IP:Port that is used by script.
- 2.Servers.txt---------------------A grepable file which you can use to see the final result (this is the file you should look at)
- 3.Servers.json--------------------A json file generated for internal use by script, you can also use it to see the result as json.

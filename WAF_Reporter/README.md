# WAF Reporter Script

## Intro
As you know fortiweb does not always give the reports you may need, so you may think of a custom, modular script to get exactly what you want.

here is my script trying to assist  you to get what you need out of different fortiweb features and combine it together to get a fully customize report.

this script provides 10 custom popular and most needed reports which may come handy when you work with fortiweb, these reports are :

- Showing policies in monitor mode
- Showing policies without web protection profile
- Showing policies without protected hostname
- Showing policies which SSL/TLS Encryption Level is medium
- Showing policies which HSTS is disable
- Show policies which traffic log is disable
- Show policies which no-parse is enable
- Show policies with default error page
- Show policies without http redirect
- Show policies which are only http
- Showing URL access rules with action "pass"
- Showing URL access policies without deny rule
- Showing web portection profiles without signature
- Showing web portection profiles without protocol HTTP Constraint
- Showing server pool which its pool member server-type is domain
- Showing Objects that have no dependency to remove them from the WAF

you can also add aditional reports as you need to the script.

## Usage
- Install modules in `requirements.txt`
- Provide username and passwords for connecting to WAF
- Provide WAF url in `baseurl` variable (Ex. https://IP_ADDRESS)

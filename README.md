# xrpl_toml
Fetches and Analyses a TOML file for XRPL validators

Example usage:
```
from fetch_toml import fetch_toml
mydomain = "alloy.ee"
tomljson = fetch_toml(mydomain)
print(tomljson)
```

**Reverse Lookup**

```
from address_domain import address_domain
from fetch_toml import fetch_toml
address = "rKLDcskSc7EaHDkBohxioXcASzDmWcQZNc"
'''
Optional websocketserver:port - defaults to wss://xrpl.ws:443
'''
hasdomain = address_domain(address)

print(hasdomain)

if hasdomain['error'] == False:
   mytoml = fetch_toml(hasdomain['domain'])

print(mytoml)
```

The tool also does other checks, such as validity of SSL certificate, mandatory stanzas, syntax and header information such as `Content-Type`, `CORS`. The tool will only fetch from sites that use `https` . The TOML will be fetched even if the certificate is invalid, but return a key pair `"Error" : true`

Tested on Python 3.8.

**Note**: The `_xrpl` DNS TXT entry, is not part of any recommended specification. If there are multiple validator keys to be recorded in the TXT entry, please separate them with semi-colons.

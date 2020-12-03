#!/usr/bin/env python
# coding: utf-8

import datetime
import requests
import toml
import json
from urllib.parse import urlparse
import ssl
import socket
import urllib3
import re
import dns.resolver
import tldextract
from address_domain import address_domain

# Required, since we fetch from domains with invalid SSL certificates too
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The following stanzas are mandatory in an xrp-ledger.toml file
req_stanzas = ['VALIDATORS','METADATA','PRINCIPALS']

# The following should be arrays of the form [[VALIDATORS]]
m_array = ['VALIDATORS','PRINCIPALS','SERVERS','ACCOUNTS','CURRENCIES']

# The required Content-Type to be sent by the server
ctypes = ['application/toml']

# Location of the TOML file for the XRPL
tomlsuffix = "/.well-known/xrp-ledger.toml"


def ssl_expiry_datetime(hostname):
    #ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
               socket.socket(socket.AF_INET),
               server_hostname=hostname,
        )

        conn.settimeout(3.0)

        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        return ssl_info

    except ssl.SSLError:
        
        return False

def get_xrpl_dns(domain,prefix = '_xrpl'):
        #res = dns.resolver.Resolver()
        res = dns.resolver.Resolver()
        res.nameservers = ['1.1.1.1','8.8.8.8']
        try:
            txtrec = prefix + '.' + domain
            #answers = res.query(txtrec, 'TXT')
            answers = res.resolve(txtrec,"TXT")
             
            for rdata in answers:
                vlist =  rdata.to_text().strip('\"').split(';')
                return [x.strip() for x in vlist]
                
        except Exception as e:
            return False


def header_suggestions(webserver='apache',errortype='ctype'):
    suggestdict = {}
    errorlist = ['cors','ctype']
    if errortype.lower() not in errorlist:
        return "Incorrect warning type"
    suggestdict['nginx'] = {}
    suggestdict['apache'] = {}
    # Suggestions for correcting the warnings
    suggestdict['nginx']['cors'] = 'Add the line-   add_header \'Access-Control-Allow-Origin\' \'*\';  -for the location /.well-known/xrp-ledger.toml in your nginx configuration.'
    suggestdict['apache']['cors'] = 'Create the entry- Header set Access-Control-Allow-Origin "*"  -in /.well-known/.htaccess'
    suggestdict['nginx']['ctype'] = 'Add the line- default_type \'application/toml\'; -for the location /.well-known/xrp-ledger.toml in your nginx configuration.'
    suggestdict['apache']['ctype'] = 'Create the entry-  AddType application/toml .toml -in your /.well-known/.htaccess'
    
    if webserver.lower().find("apache") != -1:
        return suggestdict['apache'][errortype]
    else:
        if webserver.lower().find("nginx") != -1:
            return suggestdict['nginx'][errortype]
        else:
            return "No suggestions for this webserver - " + errortype



def islist(obj):
    if ("list" in str(type(obj)) ):
        return True
    else :
        return False

def datecon(o):
    if isinstance(o, datetime.datetime):
       return o.__str__()


def fetch_toml(domain):
    mytoml = {
              'error': False,
              #'server_headers': {},
              #'toml': {},
              #'CORS' : False,
              #'rawtoml' : '',
              #'SSLvalidity' : '',
              #'tomlfile' : ''

              }



    if urlparse(domain).netloc == '':
        mytoml['domain'] = urlparse(domain).path
    else:
        mytoml['domain'] = urlparse(domain).netloc

    # https is forced here. We will not retrieve a file served under http
    mytoml['tomlfile'] = 'https://'+ mytoml['domain'] + tomlsuffix
    
    try:
       r = requests.get( mytoml['tomlfile'], verify=False,timeout=3)
       r.raise_for_status()
    except requests.exceptions.RequestException:
        mytoml['error'] = True
        mytoml['error_msg'] = "No TOML file here"
       
        
        return json.dumps(mytoml)


    mytoml['server_headers'] = dict(r.headers)
    mytoml['header_suggestions'] = []
    # Check for CORS
    if 'Access-Control-Allow-Origin' in mytoml['server_headers']:
        if mytoml['server_headers']['Access-Control-Allow-Origin'] == '*':
           mytoml['CORS']=True
        else:
           mytoml['CORS']=False
           mytoml['header_suggestions'].append(header_suggestions(mytoml['server_headers']['Server'],'cors'))
    else:
        mytoml['CORS']=False
        mytoml['header_suggestions'].append(header_suggestions(mytoml['server_headers']['Server'],'cors'))
    ctypes = ['application/toml']
    
    if 'Content-Type' in mytoml['server_headers']:
        if mytoml['server_headers']['Content-Type'] not in ctypes:
            mytoml['header_warnings'] = "Content-Type should be application/toml"
            mytoml['header_suggestions'].append(header_suggestions(mytoml['server_headers']['Server'],'ctype'))        
        
    else:
        mytoml['header_warnings'] = "Content-Type unspecified"
        mytoml['header_suggestions'].append(header_suggestions(mytoml['server_headers']['Server'],'ctype'))
    if len(mytoml['header_suggestions']) == 0:
        mytoml['header_suggestions'] = 'No Warnings'
    try:
        mytoml['toml'] = toml.loads(r.text)
        # Loop to check for XRPL related stanzas
        mytoml['xrp_toml_errors']=[]
        
        for st in req_stanzas:
            if st not in mytoml['toml']:
                mytoml['xrp_toml_errors'].append("Stanza " + st + " missing")
                
        for st in m_array:
            if st in mytoml['toml']:
                if islist(mytoml['toml'][st]) == False:
                    mytoml['xrp_toml_errors'].append("Stanza " + st + " should be [["+ st + "]]")
        if len(mytoml['xrp_toml_errors']) == 0:
           mytoml['xrp_toml_errors']= False
    
    except:
        
        mytoml['toml']=''
        mytoml['error'] = True
        mytoml['error_msg'] = "Invalid TOML file"
        #mytoml['rawtoml'] = r.text
        return json.dumps(mytoml,default=datecon)

    if urlparse(domain).netloc == '':
        mytoml['domain'] = urlparse(domain).path
    else:
        mytoml['domain'] = urlparse(domain).netloc

    #mytoml['rawtoml'] = r.text.split("\n")

    checkSSL = ssl_expiry_datetime(mytoml['domain'])
    
    if checkSSL == False:
        mytoml['error'] = True
        mytoml['TLSInfo'] = "Invalid Certificate"
    else:
        mytoml['TLSInfo'] = checkSSL

    dnsdom = tldextract.extract(mytoml['domain']).registered_domain

    dnstxt = get_xrpl_dns(dnsdom)
    mytoml['xrpl_DNS_entry'] = {}
    if dnstxt == False:
        mytoml['xrpl_DNS_entry']['error'] = True 
        mytoml['xrpl_DNS_entry']['error_msg'] = "No TXT record for _xrpl." + dnsdom + " found"
        mytoml['xrpl_DNS_entry']['suggestion'] = "Create a TXT record \'_xrpl\' in the domain " + dnsdom + " with your validator Public Key as the value"
    else:
        mytoml['xrpl_DNS_entry']['name'] = "_xrpl." + dnsdom
        

        mytoml['xrpl_DNS_entry']['value'] = dnstxt
        mytoml['xrpl_DNS_entry']['in_toml'] = []
        if 'VALIDATORS' in mytoml['toml']:
            for v in mytoml['toml']['VALIDATORS']:
                if v['public_key'] in dnstxt:
                    mytoml['xrpl_DNS_entry']['in_toml'].append(v['public_key'])


    # Check address - domain mapping
    mytoml['xrpl_address_domain'] = []
    if 'ACCOUNTS' in mytoml['toml']:
         for a in mytoml['toml']['ACCOUNTS']:
              hasdomain = address_domain(a['address'])
              if hasdomain['error'] == False:
                 mytoml['xrpl_address_domain'].append({'domain':hasdomain['domain'] , 'address': a['address'] ,  'index': hasdomain['index']})

    return json.dumps(mytoml,default=datecon)

if __name__ == '__main__':
   import argparse
   parser = argparse.ArgumentParser()
   parser.add_argument("domain", type=str,
                    help="Analyse the TOML of a domain")
   args = parser.parse_args()
   r = fetch_toml(args.domain)
   print(r)

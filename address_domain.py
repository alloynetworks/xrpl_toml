import json
import requests
import checkaddress
import websockets
import asyncio

@asyncio.coroutine
def account_info(xrpaddress, wsserver):
     
    websocket = yield from websockets.connect(
            wsserver)


    try:
       
       query  = {
             'command': 'account_info',
             'account': xrpaddress,
             'strict': True,
             'ledger_index': 'current',
             'queue': True
       }
       yield from websocket.send(json.dumps(query))
        

       resp = yield from websocket.recv()
       return resp
       
    except:
       return False 

    finally:
        yield from websocket.close()

def address_domain(xrpaddress,wsserver='wss://xrpl.ws:443'):
    

    respdict = {'error':True,
                'domain' : '',
                'index' : ''
                }

    if checkaddress.checkaddress(xrpaddress) == True:
       
        ddict = asyncio.get_event_loop().run_until_complete(account_info(xrpaddress,wsserver))
        if ddict == False:
            return respdict
        
        ddict = json.loads(ddict)
        
        if ddict['status'] == 'success':
            accountdict = ddict['result']['account_data']
            if 'Domain' in accountdict:
                dhex = accountdict['Domain']
                domain = bytearray.fromhex(dhex).decode()
                respdict['error'] = False
                respdict['domain'] = domain
                respdict['index'] = accountdict['index']
            
    return respdict


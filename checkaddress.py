import codecs

def checkaddress(address):

    from hashlib import sha256
    digits58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

    def to_bytes(n, length, endianess='big'):
        h = '%x' % n
        s = codecs.decode(('0'*(len(h) % 2) + h).zfill(length*2), "hex_codec")
        return s if endianess == 'big' else s[::-1]



    def decode_base58(bc, length):
        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return to_bytes(n, length, 'big')
	
    def check_bc(bc):
        try:
            bcbytes = decode_base58(bc, 25)
        except ValueError:
            return False
        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
    return check_bc(address)


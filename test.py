from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

master_key = long_to_bytes(0x2b7e151628aed2a6abf7158809cf4f3c, 16)
counter = Counter.new(nbits=128, initial_value=0)
aes_ctr = AES.new(master_key, AES.MODE_CTR, counter=counter)

plaintext = '1234567890abcdef1234567890abcdef'
print hex(bytes_to_long(aes_ctr.encrypt(plaintext)))[2:]

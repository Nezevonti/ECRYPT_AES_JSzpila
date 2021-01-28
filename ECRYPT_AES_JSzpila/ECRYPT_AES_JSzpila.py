import sys
import copy
import numpy as np

from AES_system import AES_system
from Block import Block
from Byte import Byte



def hexstring2hexarray(hex_string):# make sure the length is 16
    hex_array=[]
    for i in range(int(len(hex_string)/2)):
        substr = hex_string[(i*2):(i*2)+2]
        hex_array.append(int(substr,16))
    return hex_array



#MAIN#

print('Provide plaintext : in for of hexes : 2 digits per char : plaintext will be padded')
plaintext = input()
print('Provide key : in form of hexes : 16 byte - 32 digit!')
key_input = input()
print('Provide IV : in form of hexes : 16 byte - 32 digit! If not needed - input e')
iv_input = input()
if(iv_input == 'e'):
    iv_input = key_input
print('Provide mode: EBC / CBC / OFB / CFB')
mode = input()

system = AES_system(hexstring2hexarray(plaintext),hexstring2hexarray(key_input))

print('Encrypt or decrypt? e/d')
direction = input()
if(direction == 'e'):
    if(mode=='EBC'):
        system.print_plaintext()
        system.print_init_key()
        system.encrypt_ebc()
        print('')
        system.print_Message()
    if(mode=='CBC'):
        system.print_plaintext()
        system.print_init_key()
        system.encrypt_cbc(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()
    if(mode=='OFB'):
        system.print_plaintext()
        system.print_init_key()
        system.encrypt_ofb(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()
    if(mode=='CFB'):
        system.print_plaintext()
        system.print_init_key()
        system.encrypt_cfb(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()
elif(direction == 'd'):
    if(mode=='EBC'):
        system.print_plaintext()
        system.print_init_key()
        system.decrypt_ebc()
        print('')
        system.print_Message()
    if(mode=='CBC'):
        system.print_plaintext()
        system.print_init_key()
        system.decrypt_cbc(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()
    if(mode=='OFB'):
        system.print_plaintext()
        system.print_init_key()
        system.decrypt_ofb(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()
    if(mode=='CFB'):
        system.print_plaintext()
        system.print_init_key()
        system.decrypt_cfb(hexstring2hexarray(iv_input))
        print('')
        system.print_Message()





"""
#key = hexstring2hexarray('00010000000001000000000101000000')
#input = hexstring2hexarray('f34481ec3cc627bacd5dc3fb08f273e6')

key = hexstring2hexarray('00000000000000000000000000000000')
input = hexstring2hexarray('f34481ec3cc627bacd5dc3fb08f273e6')

#'abcd efgh ijkl mnop rstu vwxy z'
tmp_array = [int('01',16),int('89',16),int('fe',16),int('76',16),int('23',16),int('ab',16),int('dc',16),int('54',16),int('45',16),int('cd',16),int('ba',16),int('32',16),int('67',16),int('ef',16),int('98',16),int('10',16)]
tmp_key1 = [int('0f',16),int('47',16),int('0c',16),int('af',16),int('15',16),int('d9',16),int('b7',16),int('7f',16),int('71',16),int('e8',16),int('ad',16),int('67',16),int('c9',16),int('59',16),int('d6',16),int('98',16)]
tmp_key2 = [int('dc',16),int('9b',16),int('97',16),int('38',16),int('90',16),int('49',16),int('fe',16),int('81',16),int('37',16),int('df',16),int('72',16),int('15',16),int('b0',16),int('e9',16),int('3f',16),int('a7',16)]
tmpBlock = Block(tmp_array)

keyBlock1 = Block(tmp_key1)
#print('key')
#keyBlock1.print_Block()
keyBlock2 = Block(tmp_key2)





example = AES_system(input,key)
example.print_plaintext()
example.print_init_key()
example.encrypt_cbc(key)
print('')
example.print_Message()
"""





##example.decrypt_ebc()




"""    
tmpBlock.print_Block()
print('')

print('add round key')
tmpBlock.add_round_key(keyBlock1)
tmpBlock.print_Block()

print('sub bytes')
tmpBlock.sub_bytes()
tmpBlock.print_Block()
print('shift')
tmpBlock.shift_rows()
tmpBlock.print_Block()

#print('shift inv')
#tmpBlock.inv_shift_rows()
#tmpBlock.print_Block()

print('mix collumns')
tmpBlock.mix_collumns()
tmpBlock.print_Block()

#print('mix collumns inv')
#tmpBlock.inv_mix_collumns()
#tmpBlock.print_Block()

print('add Round Key')
tmpBlock.add_round_key(keyBlock2.get_Matrix())
tmpBlock.print_Block()

#
#def inv_sub_bytes():
#
#def shift_rows():
#
#def inv_shift_rows():
#
#def mix_collumns():
#
#def inv_mix_collumns():
#
#def mix_collumn_single():
"""
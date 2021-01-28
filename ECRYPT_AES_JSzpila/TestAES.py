import unittest
import logging
import sys
import copy
import numpy as np

from AES_system import AES_system
from Block import Block
from Byte import Byte


class Test_TestAES(unittest.TestCase):
    def test_EBC(self):
        log = logging.getLogger('test_ebc')
        for key,IV,plain,cypher in param_list:
            with self.subTest():
                system = AES_system(hexstring2hexarray(plain),hexstring2hexarray(key))
                system.encrypt_ebc()
                if(system.print_MessageStr() != cypher):
                    self.fail("output not matching expected")
                else:
                    log.debug('recived')
                    log.debug(system.print_MessageStr())
                    log.debug('expected')
                    log.debug(cypher)
                    log.debug('Output correct')

    def test_CBC(self):
        log = logging.getLogger('test_cbc')
        for key,IV,plain,cypher in param_list:
            with self.subTest():
                system = AES_system(hexstring2hexarray(plain),hexstring2hexarray(key))
                system.encrypt_cbc(hexstring2hexarray(IV))
                if(system.print_MessageStr() != cypher):
                    self.fail("output not matching expected")
                else:
                    log.debug('recived')
                    log.debug(system.print_MessageStr())
                    log.debug('expected')
                    log.debug(cypher)
                    log.debug('Output correct')
    def test_OFB(self):
        log = logging.getLogger('test_ofb')
        for key,IV,plain,cypher in param_list:
            with self.subTest():
                system = AES_system(hexstring2hexarray(plain),hexstring2hexarray(key))
                system.encrypt_ofb(hexstring2hexarray(IV))
                if(system.print_MessageStr() != cypher):
                    self.fail("output not matching expected")
                else:
                    log.debug('recived')
                    log.debug(system.print_MessageStr())
                    log.debug('expected')
                    log.debug(cypher)
                    log.debug('Output correct')

    def test_CFB(self):
        log = logging.getLogger('test_cfb')
        for key,IV,plain,cypher in param_list:
            with self.subTest():
                system = AES_system(hexstring2hexarray(plain),hexstring2hexarray(key))
                system.encrypt_cfb(hexstring2hexarray(IV))
                if(system.print_MessageStr() != cypher):
                    self.fail("output not matching expected")
                else:
                    log.debug('recived')
                    log.debug(system.print_MessageStr())
                    log.debug('expected')
                    log.debug(cypher)
                    log.debug('Output correct')



    


if __name__ == '__main__':
    unittest.main()

def hexstring2hexarray(hex_string):# make sure the length is 16
    hex_array=[]
    for i in range(int(len(hex_string)/2)):
        substr = hex_string[(i*2):(i*2)+2]
        hex_array.append(int(substr,16))
    return hex_array

# Key ; IV ; Plaintext ; Ciphertext
param_list = [
         ('00000000000000000000000000000000','00000000000000000000000000000000',
          'f34481ec3cc627bacd5dc3fb08f273e6','0336763e966d92595a567cc9ce537f5e'),
         ('00000000000000000000000000000000','00000000000000000000000000000000',
          '9798c4640bad75c7c3227db910174e72','a9a1631bf4996954ebc093957b234589'),
         ('00000000000000000000000000000000','00000000000000000000000000000000',
          '96ab5c2ff612d9dfaae8c31f30c42168','ff4f8391a6a40ca5b25d23bedd44a597'),
         ('10a58869d74be5a374cf867cfb473859','00000000000000000000000000000000',
          '00000000000000000000000000000000','6d251e6944b051e04eaa6fb4dbf78465'),
         ('cb9fceec81286ca3e989bd979b0cb284','00000000000000000000000000000000',
          'f34481ec3cc627bacd5dc3fb08f273e6','241b1a96bc2512215e18f751ac63b8d1')
     ]
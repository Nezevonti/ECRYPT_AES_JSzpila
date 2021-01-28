import sys
import copy
import numpy as np

from Byte import Byte



class Block(object):
    """
    This class holds the 4x4 matrix of bytes
    and creattion and shift/mix/substitution functions
    Acceptcs 16 byte plaintext input (16 chars)
    or 16 int array as input
    """

    Matrix = []
    # learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    xtime = lambda a: ((((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1))

    def __init__(self,plaintext):
        #class constructor
        self.Matrix = self.text_2_matrix(plaintext)

    def __xor__(self,other_block):
        #overloaded XOR operator
        tmpMatrix = copy.deepcopy(self.Matrix)
        tmpOtherMatrix = other_block.get_Matrix()

        for i in range(4):
            for j in range(4):
                tmpMatrix[i][j] = Byte(self.Matrix[i][j]^tmpOtherMatrix[i][j])

        self.Matrix = copy.deepcopy(tmpMatrix)

    def text_2_matrix(self,plaintext):
        #take in 16bytes (or less) of text, pad it if needed
        #Then translate all chars into numerical values and
        #save them as an array of Byte objects in Matrix
        #If input was full of ints - no need to change

        plaintext = self.pad_text(plaintext)
        
        tmp_Matrix = []
        for i in range(4):
            tmp_array=[]
            for j in range(4):
                current_char = plaintext[i*4+j] #translate chars to numerical values
                if(type(current_char) == str):
                    tmp_array.append(Byte(ord(current_char)))
                elif(type(current_char) == int):
                    tmp_array.append(Byte(current_char))
            tmp_Matrix.append(tmp_array)
        return tmp_Matrix

    def pad_text(self,plaintext): #simple padding to 16 bytes, by adding 0 at the end. Prone to attack but I can change it later
        text_length = len(plaintext)
        difference =  text_length % 16
        if difference != 0:
            for x in range(difference):
                plaintext = plaintext + '0'
            return plaintext
        else:
            return plaintext

    def print_Block(self): #prints the block in 4x4 way to the console
        iterator=0;
        for i in range(4):
            for j in range(4):
                tmp = self.Matrix[i][j];
                print(hex(tmp.get_Byte()),end=' ')
            print('')
    
    def sub_bytes(self): #run the sub_bytes on all 4x4 bytes in matrix
        tmp_Matrix = self.Matrix
        for i in range(4):
            for j in range(4):
                tmp_Matrix[i][j] = Byte(self.Matrix[i][j].sub_bytes())
        self.Matrix = tmp_Matrix

    def inv_sub_bytes(self): #run the inversion of sub_bytes on all 4x4 bytes in matrix
        tmp_Matrix = self.Matrix
        for i in range(4):
            for j in range(4):
                tmp_Matrix[i][j] = Byte(self.Matrix[i][j].inv_sub_bytes())
        self.Matrix = tmp_Matrix

    def shift_rows(self): #run the shift row function, shifts bytes to the left
        #row 0 - no shift
        #row 1 - shift by one
        #row 2 - shift by two
        #row 3 - shift by three
        tmpMatrix = copy.deepcopy(self.Matrix)
        index=0
        for i in range(16):
            self.Matrix[i//4][i%4]=tmpMatrix[index//4][index%4]
            index = (index+5)%16

    def inv_shift_rows(self): #invokes the shift row function 3 times, gives the same output as array before shift_rows
        #row 1 - shift by one
        self.shift_rows()
        self.shift_rows()
        self.shift_rows()

    def xtime(self,a):
        if(a & 0x80):
            return (((a << 1) ^ 0x1B) & 0xFF)
        else:
            return (a<<1)

    def mix_collumns(self): #responsible for the mix_collumns function. Works by matrix multiplcation in GF(2^8) using prime polinomial
        tmpMatrix = copy.deepcopy(self.Matrix)
        single_collumn = copy.deepcopy(self.Matrix[0])
        for i in range(4):
            single_collumn[0], single_collumn[1], single_collumn[2], single_collumn[3] = tmpMatrix[i][0], tmpMatrix[i][1], tmpMatrix[i][2], tmpMatrix[i][3]

            #print('before : ',end='')
            #for x in range(4):
            #     tmp = single_collumn[x];
            #     print(hex(tmp.get_Byte()),end=' ')
            #print('')

            u = single_collumn[0]
            t = Byte(single_collumn[0].get_Byte() ^ single_collumn[1].get_Byte() ^ single_collumn[2].get_Byte() ^ single_collumn[3].get_Byte())
            single_collumn[0] ^= t ^ self.xtime(single_collumn[0] ^ single_collumn[1])
            single_collumn[1] ^= t ^ self.xtime(single_collumn[1] ^ single_collumn[2])
            single_collumn[2] ^= t ^ self.xtime(single_collumn[2] ^ single_collumn[3])
            single_collumn[3] ^= t ^ self.xtime(single_collumn[3] ^ u)

            #print('after : ',end='')
            #for x in range(4):
            #    tmp = single_collumn[x];
            #    print(hex(tmp),end=' ')
            #print('')

            for j in range(4):
                self.Matrix[i][j] = Byte(single_collumn[j])
    
    def inv_mix_collumns(self):
        single_collumn = copy.deepcopy(self.Matrix[0])
        tmpMatrix = copy.deepcopy(self.Matrix)

        for i in range(4):
            single_collumn[0], single_collumn[1], single_collumn[2], single_collumn[3] = tmpMatrix[i][0], tmpMatrix[i][1], tmpMatrix[i][2], tmpMatrix[i][3]

            u = self.xtime(self.xtime(single_collumn[0]^single_collumn[2]))
            v = self.xtime(self.xtime(single_collumn[1]^single_collumn[3]))
            single_collumn[0] ^= u
            single_collumn[1] ^= v
            single_collumn[2] ^= u
            single_collumn[3] ^= v

            for j in range(4):
                tmpMatrix[i][j] = Byte(single_collumn[j])

        self.Matrix = copy.deepcopy(tmpMatrix)

        self.mix_collumns()

    def add_round_key(self,key): #Adds (XOR) round key to the block
       #key is Block object!
        tmpMatrix = copy.deepcopy(self.Matrix)
        keyMatrix = key.get_Matrix()
        for i in range(4):
            for j in range(4):
                tmpMatrix[j][i]^=keyMatrix[j][i]

        for i in range(4):
            for j in range(4):
                tmpMatrix[j][i] = Byte(tmpMatrix[j][i])
        self.Matrix = copy.deepcopy(tmpMatrix)

    def get_Matrix(self):
        return self.Matrix

    def ebc_round(self,key): #runs the whole round on the block
        self.sub_bytes()
        self.shift_rows()
        self.mix_collumns()
        self.add_round_key(key)
        #self.print_Block()

    def ebc_round_decrypt(self,key): #same as above but for decryption
        self.add_round_key(key)
        self.inv_mix_collumns()
        self.inv_shift_rows()
        self.inv_sub_bytes()
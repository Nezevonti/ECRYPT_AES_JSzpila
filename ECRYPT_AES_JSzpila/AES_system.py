import sys
import copy
import numpy as np

from Block import Block
from Byte import Byte





class AES_system(object):
    """
    this class holds functions related to working on whole key and text
    Also encryption decryption function of all modes

    Supported modes:
    EBC
    CBC
    OFB
    CFB
    """

    r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self,plaintext, initial_key):
        self.plaintext = plaintext
        self.blocks = int(len(plaintext)/16) #number of blocks

        if(len(plaintext)%16 != 0): #if the length of input is not full block leave space (additional block) for the rest
            self.blocks += 1
        
        self.initial_key_block = Block(initial_key)
        self.rounds = self.get_rounds(len(initial_key))
        self.expanded_key = self.expand(initial_key,self.rounds)# call the key expansion function
        self.split_text = self.split_plaintext() #split the input into blocks

    def get_rounds(self,key_length): #should support different lengths
        #Different number of rounds depending on key length
        if(key_length == 16): return 10
        if(key_length == 24): return 12
        if(key_length == 32): return 14

    def print_row(self,row): #print the singular row
        for byte in row:
            print(hex(byte.get_Byte()), end = ' ')

        print('')
    
    def expand(self,initial_key,rounds):
        #get Matrix of initial key and a deepcpy of it to add new rows into
        initial_key_Block = Block(initial_key)
        expanded_key_rows = copy.deepcopy(initial_key_Block.get_Matrix())
        expanded_key_blocks = []
        #get arrays for finished and intermidiate rows and set them to size
        new_row = copy.deepcopy(expanded_key_rows[0]) #finished row, to be pushed into expanded_key
        row_m_1 = copy.deepcopy(expanded_key_rows[0]) #row[x-1] Minus 1
        row_m_4 = copy.deepcopy(expanded_key_rows[0]) #row[x-4] Minus 4
        row_x = copy.deepcopy(expanded_key_rows[0]) #= LeftShift(row_m_1)
        row_y = copy.deepcopy(expanded_key_rows[0]) #= SubBytes(x)
        row_z = copy.deepcopy(expanded_key_rows[0]) #= y^rcon
        row_r = [hex(0),hex(0),hex(0),hex(0)] #=rcon
        special_iterator = 1 #of times special rules were used

        #expanded_key_blocks.append(initial_key_Block)

        #Each new key row is a XOR of previous row and the one 4 rows earlier (w[i] = w[i-1] ^ w[w-4])
        #IF the itearator is a multiple of 4 the operation is more complicated
        #Previous row is rotaated left shift and sub bytes is applied
        #the result is XORed the row 4 earliers and constant R_con

        for i in range(4,(rounds+1)*4,1):
            if((i%4)==0):

                #print current state of expanded key rows
                #print('')
                #print('expanded rows - current state')
                #for rows in expanded_key_rows:
                    #self.print_row(rows)
                #print('')
                #print('')

                #non-typical row, expand according to special rules
                row_m_1 = copy.deepcopy(expanded_key_rows[i-1])
                #print('row -1 :')
                #self.print_row(row_m_1)

                #get row[i-4]
                row_m_4 =  copy.deepcopy(expanded_key_rows[i-4])

                #print('row -4 :')
                #self.print_row(row_m_4)
                
                #shift left
                row_x[0],row_x[1],row_x[2],row_x[3] = row_m_1[1], row_m_1[2], row_m_1[3], row_m_1[0]
                #print('row x :')
                #self.print_row(row_x)

                #subBytes
                for j in range(4):
                    row_y[j] = Byte(row_x[j].sub_bytes())

                #print('row y :')
                #self.print_row(row_y)

                #get rCon & XOR it with row_y. Only 1 Byte of r_con changes
                row_z[0] = Byte(row_y[0] ^ self.r_con[special_iterator])
                row_z[1] = row_y[1]
                row_z[2] = row_y[2]
                row_z[3] = row_y[3]
                special_iterator += 1
                    
                #print('row z :')
                #self.print_row(row_z)

                #print('---')
                #initial_key_Block.print_Block()
                #print('---')

                #print('row -4 :')
                #self.print_row(row_m_4)

                

                #get new_row
                for l in range(4):
                    new_row[l] = Byte(row_m_4[l] ^ row_z[l])

            else:
                row_m_1 = copy.deepcopy(expanded_key_rows[i-1])
                row_m_4 = copy.deepcopy(expanded_key_rows[i-4])

                for l in range(4):
                    new_row[l] = Byte(row_m_4[l] ^ row_m_1[l])
            #print('new row ' + str(i))
            #self.print_row(new_row)
            #push new key row into the array with others
            new_row_fin = copy.deepcopy(new_row)
            expanded_key_rows.append(new_row_fin)

            #every 4 rows, create block with 4 last rows
            if(i%4==0):
                block_array = []
                for a in range(4):
                    row = copy.deepcopy(expanded_key_rows[i-4+a])
                    for b in range(4):
                        block_array.append(row[b].get_Byte())

                #print('new block')
                newBlock = Block(block_array)
                #newBlock.print_Block()
                #print('')

                expanded_key_blocks.append(copy.deepcopy(newBlock))

        #add last 4 rows / last block
        block_array = []
        key_rows_length = len(expanded_key_rows)
        for a in range(4):
            row = copy.deepcopy(expanded_key_rows[key_rows_length-4+a])
            for b in range(4):
                block_array.append(row[b].get_Byte())

        #print('new block')
        newBlock = Block(block_array)
        #newBlock.print_Block()
        #print('')

        expanded_key_blocks.append(copy.deepcopy(newBlock))

        #return list of blocks
        #print whole key
        #print('finished key')
        #for block in expanded_key_blocks:
        #    print('')
        #    block.print_Block()

        return expanded_key_blocks
    
    #old func, not exactly working
    def expand_key(self,initial_key,rounds):

        initial_key_Block = Block(initial_key)

        initial_key_Matrix = initial_key_Block.get_Matrix()
        tmp_collumn = initial_key_Matrix[0]
        new_collumn = initial_key_Matrix[0]
        row_m_4 = initial_key_Matrix[0]
        iterator = 1

        expanded_key_rows = copy.deepcopy(initial_key_Matrix)

        #do key expansion algorithm
        for i in range(4,(rounds+1)*4,1):
            if(i%4==0):
                #expand multiple 4
                    tmp_collumn[0], tmp_collumn[1], tmp_collumn[2], tmp_collumn[3] = expanded_key_rows[i-1][1], expanded_key_rows[i-1][2], expanded_key_rows[i-1][3], expanded_key_rows[i-1][0]

                    
                    #debug print
                    print('')
                    print(hex(tmp_collumn[0].get_Byte()), end = ' ')
                    print(hex(tmp_collumn[1].get_Byte()), end = ' ')
                    print(hex(tmp_collumn[2].get_Byte()), end = ' ')
                    print(hex(tmp_collumn[3].get_Byte()), end = ' ')
                    print('')
                    

                    tmp_collumn[0], tmp_collumn[1], tmp_collumn[2], tmp_collumn[3] = tmp_collumn[0].sub_bytes(), tmp_collumn[1].sub_bytes(), tmp_collumn[2].sub_bytes(), tmp_collumn[3].sub_bytes()
                    tmp_collumn[0] ^= self.r_con[iterator]
                    iterator += 1

                    
                    #debug print
                    print(hex(tmp_collumn[0]), end = ' ')
                    print(hex(tmp_collumn[1]), end = ' ')
                    print(hex(tmp_collumn[2]), end = ' ')
                    print(hex(tmp_collumn[3]), end = ' ')
                    print('')
                    

                    tmp_collumn[0], tmp_collumn[1], tmp_collumn[2], tmp_collumn[3] = Byte(tmp_collumn[0]), Byte(tmp_collumn[1]), Byte(tmp_collumn[2]), Byte(tmp_collumn[3])

                    #new_collumn = expanded_key_collumns[i-4] ^ tmp_collumn
                    row_m_4[0], row_m_4[1], row_m_4[2], row_m_4[3] = expanded_key_rows[i-4][0],expanded_key_rows[i-4][1],expanded_key_rows[i-4][2],expanded_key_rows[i-4][3]

                    print(hex(row_m_4[0].get_Byte()), end = ' ')
                    print(hex(row_m_4[1].get_Byte()), end = ' ')
                    print(hex(row_m_4[2].get_Byte()), end = ' ')
                    print(hex(row_m_4[3].get_Byte()), end = ' ')
                    print('')

                    new_collumn[0] = Byte(expanded_key_rows[i-4][0] ^ tmp_collumn[0])
                    new_collumn[1] = Byte(expanded_key_rows[i-4][1] ^ tmp_collumn[1])
                    new_collumn[2] = Byte(expanded_key_rows[i-4][2] ^ tmp_collumn[2])
                    new_collumn[3] = Byte(expanded_key_rows[i-4][3] ^ tmp_collumn[3])

                    
                    #debug print
                    print(hex(new_collumn[0].get_Byte()), end = ' ')
                    print(hex(new_collumn[1].get_Byte()), end = ' ')
                    print(hex(new_collumn[2].get_Byte()), end = ' ')
                    print(hex(new_collumn[3].get_Byte()), end = ' ')
                    print('')
                    print('')
                    
                    
            else:
                #expand normally
                #new_collumn = expanded_key_collumns[i-4] ^ expanded_key_collumns[i-1]
                new_collumn[0] = Byte(expanded_key_rows[i-4][0] ^ expanded_key_rows[i-1][0])
                new_collumn[1] = Byte(expanded_key_rows[i-4][1] ^ expanded_key_rows[i-1][1])
                new_collumn[2] = Byte(expanded_key_rows[i-4][2] ^ expanded_key_rows[i-1][2])
                new_collumn[3] = Byte(expanded_key_rows[i-4][3] ^ expanded_key_rows[i-1][3])

                
                #print(hex(new_collumn[0].get_Byte()), end = ' ')
                #print(hex(new_collumn[1].get_Byte()), end = ' ')
                #print(hex(new_collumn[2].get_Byte()), end = ' ')
                #print(hex(new_collumn[3].get_Byte()), end = ' ')
                #print('')
                
            
            print(hex(new_collumn[0].get_Byte()), end = ' ')
            print(hex(new_collumn[1].get_Byte()), end = ' ')
            print(hex(new_collumn[2].get_Byte()), end = ' ')
            print(hex(new_collumn[3].get_Byte()), end = ' ')
            print('')


            expanded_key_rows.append(new_collumn)


        #expanded_key_collumns = np.transpose(expanded_key_collumns)
        print('---   ---') #information about expanded key
        print(len(expanded_key_rows)) #4
        print(len(expanded_key_rows[0])) #40
        print('--- finished key ---')

        expanded_key_Blocks = []

        """
        for b in range(int(len(expanded_key_rows[0])/4)):
            tmp_block_array = []
            for x in range(len(expanded_key_rows)):
                for z in range(4):
                    tmp = expanded_key_rows[x][b*4+z];
                    tmp_block_array.append(tmp.get_Byte())
                    print(hex(tmp.get_Byte()),end=' ')
                print('')
            print('--  --  --  --')
            tmp_Block = Block(tmp_block_array)
            expanded_key_Blocks.append(tmp_Block)
        """
        print('---key---')
        return expanded_key_Blocks

    def split_plaintext(self): #split the text into blocks (each block 16 chars long)
        Block_list = []
        for i in range(self.blocks):
            if(i == self.blocks-1):
                tmp_string = self.plaintext[i*16:]
            else:
                tmp_string = self.plaintext[i*16:i*16+16]
            
            tmp_Block = Block(tmp_string)
            Block_list.append(tmp_Block)

        #print('split blocks')
        #for block in Block_list:
        #    block.print_Block()

        #print('--split blocks--')
        return Block_list

    def encrypt_block(self,block):
        
        block = copy.deepcopy(block)

        #add key for 0th round
        block.add_round_key(self.expanded_key[0])

        for i in range(self.rounds - 1): #Do the encryption rounds

            block.sub_bytes()

            block.shift_rows()

            block.mix_collumns()

            block.add_round_key(self.expanded_key[i+1])


        #Do the last round
        block.sub_bytes()
        block.shift_rows()

        block.add_round_key(self.expanded_key[-1])
        #return the encrypted block
        return block

    def decrypt_block(self, block): #Same but in reverse
        block = copy.deepcopy(block)

        block.add_round_key(self.expanded_key[-1])

        block.inv_shift_rows()

        block.inv_sub_bytes()


        for i in range(self.rounds - 1,0,-1):
            block.add_round_key(self.expanded_key[i])

            block.inv_mix_collumns()

            block.inv_shift_rows()

            block.inv_sub_bytes()

        block.add_round_key(self.expanded_key[0])

        return block

    def print_plaintext(self):
        print('initial plaintext')
        for block in self.split_plaintext():
            for row in block.Matrix:
                for byte in row:
                    value = byte.get_Byte()
                    print("{0:0{1}x}".format(value,2),end='')
        print('')

    def print_init_key(self):
        print('initial key')
        self.initial_key_block.print_Block()

    def print_Message(self):
        for block in self.split_text:
            for row in block.Matrix:
                for byte in row:
                    value = byte.get_Byte()
                    print("{0:0{1}x}".format(value,2),end='')
        print('')

    def print_MessageStr(self):
        str = ""

        for block in self.split_text:
            for row in block.Matrix:
                for byte in row:
                    value = byte.get_Byte()
                    str += "{0:0{1}x}".format(value,2)
        return str

    #Functions for encryption and decryption of all modes
    def encrypt_ebc(self):

        #print('pre encryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            block = copy.deepcopy(self.encrypt_block(self.split_text[i]))
            self.split_text[i] = block
        
        #print('post encryption')
        #for block in self.split_text:
        #    block.print_Block()

    def decrypt_ebc(self):

        #print('pre decryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            block = copy.deepcopy(self.decrypt_block(self.split_text[i]))
            self.split_text[i] = block
        
        #print('post decryption')
        #for block in self.split_text:
        #    block.print_Block()

    def encrypt_cbc(self,IV):

        IV_Block = Block(IV)

        #print('pre encryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):

            self.split_text[i]^IV_Block
            for_encryption_Block = self.split_text[i]
            block = copy.deepcopy(self.encrypt_block(for_encryption_Block))
            IV_Block = copy.deepcopy(block)
            self.split_text[i] = block
        
        #print('post encryption')
        #for block in self.split_text:
        #    block.print_Block()

    def decrypt_cbc(self,IV):

        IV_Block = Block(IV)

        #print('pre decryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):

            block = copy.deepcopy(self.decrypt_block(self.split_text[i]))
            tmp_Block = copy.deepcopy(self.split_text[i])
            self.split_text[i] = block^IV_Block
            IV_Block = copy.deepcopy(tmp_Block)
        
        #print('post decryption')
        #for block in self.split_text:
        #    block.print_Block()

    def encrypt_cfb(self,IV):
        #encrypt IV with key
        #xor block
        #use xored block as new IV

        IV_Block = Block(IV)

        #print('pre encryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            encrypted_IV = copy.deepcopy(self.encrypt_block(IV_Block))
            block = copy.deepcopy(self.split_text[i]^encrypted_IV)
            IV_Block = copy.deepcopy(block)
            self.split_text[i] = copy.deepcopy(block)
        
        #print('post encryption')
        #for block in self.split_text:
        #    block.print_Block()

    def decrypt_cfb(self,IV):
        #encrypt IV with key
        #xor block
        #use xored block as new IV

        IV_Block = Block(IV)

        #print('pre decryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            encrypted_IV = copy.deepcopy(self.encrypt_block(IV_Block))
            tmpBlock = copy.deepcopy(self.split_text[i])
            block = copy.deepcopy(self.split_text[i]^encrypted_IV)
            IV_Block = copy.deepcopy(tmpBlock)
            self.split_text[i] = copy.deepcopy(block)
        
        #print('post decryption')
        #for block in self.split_text:
        #    block.print_Block()

    def encrypt_ofb(self,IV):

        IV_Block = Block(IV)

        encrypted_IV = copy.deepcopy(self.encrypt_block(IV_Block))

        #print('pre encryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            block = copy.deepcopy(self.split_text[i]^encrypted_IV)
            self.split_text[i] = copy.deepcopy(block)
        
        #print('post encryption')
        #for block in self.split_text:
        #    block.print_Block()

    def decrypt_ofb(self,IV):
        IV_Block = Block(IV)

        encrypted_IV = copy.deepcopy(self.encrypt_block(IV_Block))

        #print('pre decryption')
        #for block in self.split_text:
        #    block.print_Block()

        for i in range(len(self.split_text)):
            block = copy.deepcopy(self.split_text[i]^encrypted_IV)
            self.split_text[i] = copy.deepcopy(block)
        
        #print('post decryption')
        #for block in self.split_text:
        #    block.print_Block()
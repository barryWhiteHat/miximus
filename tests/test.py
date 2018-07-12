'''   
    copyright 2018 to the Miximus Authors

    This file is part of Miximus.

    Miximus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Miximus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Miximus.  If not, see <https://www.gnu.org/licenses/>.
'''

import sys
sys.path.insert(0, '../snarkWrapper')


from deploy import *

if __name__ == "__main__":
    tree_depth = 29
    pk_output = "../zksnark_element/pk.raw"
    vk_output = "../zksnark_element/vk.json"

    genKeys(c.c_int(tree_depth), c.c_char_p(pk_output.encode()) , c.c_char_p(vk_output.encode())) 


    miximus = deploy(tree_depth, vk_output)
    for j in range (0,16):

        nullifiers = []
        sks = []
 
        fee = 0 

        for i in range(0,1):
            nullifiers.append(genNullifier(w3.eth.accounts[i%10]))
            sk = genSalt(64)
            sks.append("0x" + sk)  

        for nullifier , sk in zip(nullifiers, sks):
            try:
                index = deposit(miximus, nullifier, sk, w3.eth.accounts[0])
            except:
                pdb.set_trace()

        for i, (nullifier , sk) in enumerate(zip(nullifiers, sks)):

            pk = genWitness(miximus, nullifier, sk, i + j, tree_depth, fee, "../zksnark_element/pk.raw")   
            withdraw(miximus, pk)
           
          
   

import sys
sys.path.insert(0, '../snarkWrapper')


from deploy import *

if __name__ == "__main__":
    tree_depth = 29
    #genKeys(c.c_int(tree_depth))

    miximus = deploy(tree_depth)

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
            pk = genWitness(miximus, nullifier, sk, i + j, tree_depth, fee)
    
            try:
                withdraw(miximus, pk)
            except:
                pdb.set_trace()

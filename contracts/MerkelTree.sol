contract MerkelTree {
    mapping (bytes32 => bool) public serials;
    mapping (bytes32 => bool) public roots;
    uint public tree_depth = 29;
    uint public no_leaves = 536870912;
    struct Mtree {
        uint cur;
        bytes32[536870912][30] leaves2;
    }

    Mtree public MT;

    event leafAdded(uint index);

    //Merkletree.append(com)
    function insert(bytes32 com) internal returns (bool res) {
        require (MT.cur != no_leaves - 1);
        MT.leaves2[0][MT.cur] = com;
        updateTree();
        leafAdded(MT.cur);
        MT.cur++;
   
        return true;
    }


    function getMerkelProof(uint index) constant returns (bytes32[29], uint[29]) {

        uint[29] memory address_bits;
        bytes32[29] memory merkelProof;

        for (uint i=0 ; i < tree_depth; i++) {
            address_bits[i] = index%2;
            if (index%2 == 0) {
                merkelProof[i] = getUniqueLeaf(MT.leaves2[i][index + 1],i);
            }
            else {
                merkelProof[i] = getUniqueLeaf(MT.leaves2[i][index - 1],i);
            }
            index = uint(index/2);
        }
        return(merkelProof, address_bits);   
    }
    
     function getSha256(bytes32 input, bytes32 sk) constant returns ( bytes32) { 
        return(sha256(input , sk)); 
    }

    function getUniqueLeaf(bytes32 leaf, uint depth) returns (bytes32) {
        if (leaf == 0x0) {
            for (uint i=0;i<depth;i++) {
                leaf = sha256(leaf, leaf);
            }
        }
        return(leaf);
    }
    
    function updateTree() internal returns(bytes32 root) {
        uint CurrentIndex = MT.cur;
        bytes32 leaf1;
        bytes32 leaf2;
        for (uint i=0 ; i < tree_depth; i++) {
            uint NextIndex = uint(CurrentIndex/2);
            if (CurrentIndex%2 == 0) {
                leaf1 =  MT.leaves2[i][CurrentIndex];
                leaf2 = getUniqueLeaf(MT.leaves2[i][CurrentIndex + 1], i);
            } else {
                leaf1 = getUniqueLeaf(MT.leaves2[i][CurrentIndex - 1], i);
                leaf2 =  MT.leaves2[i][CurrentIndex];
            }
            MT.leaves2[i+1][NextIndex] = (sha256( leaf1, leaf2));
            CurrentIndex = NextIndex;
        }
        return MT.leaves2[tree_depth][0];
    }
    
   
    function getLeaf(uint j,uint k) constant returns (bytes32 root) {
        root = MT.leaves2[j][k];
    }

    function getRoot() constant returns(bytes32 root) {
        root = MT.leaves2[tree_depth][0];
    }

}

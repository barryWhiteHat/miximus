// https://github.com/zcash-hackworks/babyzoe

contract MerkelTree {
    mapping (bytes32 => bool) public serials;
    mapping (bytes32 => bool) public roots;

    struct Mtree {
        uint cur;
        bytes32[16] leaves;
    }

    Mtree public MT;
    bytes public vk;

    function MerkelTree() {
        for (uint i = 0; i < 16; i++)
            MT.leaves[i] = 0x0;

    }


    //Merkletree.append(com)
    function insert(bytes32 com) internal returns (bool res) {
        if (MT.cur == 16) {
            return false;
        }
        MT.leaves[MT.cur] = com;
        MT.cur++;
        return true;
    }

    function getSha256(bytes32 input, bytes32 sk) constant returns ( bytes32) { 
        return(sha256(input , sk)); 
    } 

    function getLeaves() constant returns (bytes32[16]) {
        return MT.leaves;
    }

    function getTree() constant returns (bytes32[32] tree) {
        //bytes32[32] memory tree;
        bytes32 test = 0;
        uint i;
        for (i = 0; i < 16; i++)
            tree[16 + i] = MT.leaves[i];
        for (i = 16 - 1; i > 0; i--) {
            tree[i] = sha256(tree[i*2], tree[i*2+1]); 
        }
        return tree;
    }

    //Merkletree.root()
    function getRoot() constant returns(bytes32 root) {
        root = getTree()[1];
    }

}

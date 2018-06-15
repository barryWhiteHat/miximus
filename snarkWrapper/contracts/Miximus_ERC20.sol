pragma solidity ^0.4.19;

import "./Verifier.sol";
import "./ERC20/ERC20.sol";

contract Miximus {

    struct MiximusTree {
        ERC20 ercInstance;
        bool instantiated;
        mapping (bytes32 => bool) roots;
        mapping (bytes32 => bool) nullifiers;
        MTree mTree;
    }

    struct MTree {
        bool instantiated;
        uint cur;
        bytes32[16] leaves;
        mapping (bytes32 => bool) serials;
        mapping (bytes32 => bool) roots;
        bytes vk;
    }

    function insert(address _erc20Address, bytes32 com) internal returns (bool res) {
        if (miximusTrees[_erc20Address].mTree.cur == 16) {
            return false;
        }
        miximusTrees[_erc20Address].mTree.leaves[miximusTrees[_erc20Address].mTree.cur] = com;
        miximusTrees[_erc20Address].mTree.cur++;
        return true;
    }

    function getSha256(bytes32 input, bytes32 sk) constant returns ( bytes32) { 
        return(sha256(input , sk)); 
    } 

    function getLeaves(address _erc20Address) constant returns (bytes32[16]) {
        return miximusTrees[_erc20Address].mTree.leaves;
    }

    function getTree(address _erc20Address) constant returns (bytes32[32] tree) {
        //bytes32[32] memory tree;
        bytes32 test = 0;
        uint i;
        for (i = 0; i < 16; i++)
            tree[16 + i] = miximusTrees[_erc20Address].mTree.leaves[i];
        for (i = 16 - 1; i > 0; i--) {
            tree[i] = sha256(tree[i*2], tree[i*2+1]); 
        }
        return tree;
    }

    //Merkletree.root()
    function getRoot(address _erc20Address) constant returns(bytes32 root) {
        root = getTree(_erc20Address)[1];
    }
    
    // erc20 to miximus
    mapping (address => MiximusTree) miximusTrees;

    event Withdraw (address); 
    Verifier public zksnark_verify;
    function Miximus (address _zksnark_verify) {
        zksnark_verify = Verifier(_zksnark_verify);
    }

    function deposit (address _erc20Address, bytes32 leaf) payable  {
        if(!miximusTrees[_erc20Address].instantiated || !miximusTrees[_erc20Address].mTree.instantiated) {
            miximusTrees[_erc20Address].ercInstance = ERC20(_erc20Address);
            miximusTrees[_erc20Address].instantiated = true;
            miximusTrees[_erc20Address].mTree.instantiated = true;
        }
        require(miximusTrees[_erc20Address].ercInstance.transferFrom(msg.sender, address(this), 1));
        insert(_erc20Address, leaf);
        miximusTrees[_erc20Address].roots[padZero(getTree(_erc20Address)[1])] = true;
    }

    function withdraw (
            uint[2] a,
            uint[2] a_p,
            uint[2][2] b,
            uint[2] b_p,
            uint[2] c,
            uint[2] c_p,
            uint[2] h,
            uint[2] k,
            uint[] input,
            address _erc20Address
        ) returns (address) {
        require(miximusTrees[_erc20Address].instantiated);
        require(miximusTrees[_erc20Address].mTree.instantiated);
        address recipient  = nullifierToAddress(reverse(bytes32(input[2])));      
        require(miximusTrees[_erc20Address].roots[reverse(bytes32(input[0]))]);

        require(!miximusTrees[_erc20Address].nullifiers[reverse(bytes32(input[2]))]);
        require(zksnark_verify.verifyTx(a,a_p,b,b_p,c,c_p,h,k,input));
        require(miximusTrees[_erc20Address].ercInstance.transferFrom(address(this), recipient, 1));
        miximusTrees[_erc20Address].nullifiers[padZero(reverse(bytes32(input[2])))] = true;
        Withdraw(recipient);
        return(recipient);
    }

    function nullifierToAddress(bytes32 source) returns(address) {
        bytes20[2] memory y = [bytes20(0), 0];
        assembly {
            mstore(y, source)
            mstore(add(y, 20), source)
        }
        //trace(source, y[0], y[1]);
        return(address(y[0]));
    }


    // hack to side step a libshark only allows 253 bit chunks in its output
    // to overcome this we only validate the first 252 bits of the merkel root
    // and the nullifier. We set the last byte to zero.
    function padZero(bytes32 x) returns(bytes32) {
                 //0x1111111111111111111111113fdc3192693e28ff6aee95320075e4c26be03308
        return(x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0);
    }

    function reverseByte(uint a) public pure returns (uint) {
        uint c = 0xf070b030d0509010e060a020c0408000;

        return (( c >> ((a & 0xF)*8)) & 0xF0)   +  
               (( c >> (((a >> 4)&0xF)*8) + 4) & 0xF);
    }
    //flip endinaness
    function reverse(bytes32 a) public pure returns(bytes32) {
        uint r;
        uint i;
        uint b;
        for (i=0; i<32; i++) {
            b = (uint(a) >> ((31-i)*8)) & 0xff;
            b = reverseByte(b);
            r += b << (i*8);
        }
        return bytes32(r);
    }

}
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

//hash
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <sha256/sha256_ethereum.cpp>
#include <export.cpp>
#include "main.hpp"
//key gen 
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

using namespace libsnark;
using namespace libff;

typedef sha256_ethereum HashT;

// taken froim deploy.js 
// TODO: deal with leading zeros being removed in deploy.js

/*
  libff::bit_vector tree17 = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


 libff::bit_vector tree9 = { 1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 };
 libff::bit_vector tree5 = { 1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 };
 libff::bit_vector tree3 = { 1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 };
 libff::bit_vector root = {0, 1 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0};
 libff::bit_vector nullifier = {0,0, 1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 };
 libff::bit_vector secret = { 1 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,0 ,0 ,1 ,0 ,1 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,0 ,0 ,1 ,1 ,1 ,0 ,0 ,0 ,1 ,1 ,1 ,0 ,1 ,1 ,0 ,1 ,1 };
*/



template<typename FieldT, typename HashT>
class Miximus {
public:

    const size_t digest_len = HashT::get_digest_len();
    size_t tree_depth;
    protoboard<FieldT> pb;

    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker1;

    //digest_variable<FieldT> root_digest(pb, digest_len, "root_digest");
    std::shared_ptr<digest_variable<FieldT>> root_digest;
    //digest_variable<FieldT> cm(pb, digest_len, "cm_digest");
    std::shared_ptr<digest_variable<FieldT>> cm;
    //digest_variable<FieldT> sk(pb, digest_len, "sk_digest");
    std::shared_ptr<digest_variable<FieldT>> sk;
    //digest_variable<FieldT> leaf_digest(pb, digest_len, "leaf_digest");
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;

    std::shared_ptr<sha256_ethereum> cm_hash;


    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var;

    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> ml;

    pb_variable_array<FieldT> address_bits_va;
    std::shared_ptr <block_variable<FieldT>> input_variable;

    pb_variable<FieldT> ZERO;
    //we use layer 2 transaction abstration. 
    //here the depositor denotes the fee in Wei
    pb_variable<FieldT> msgSenderFee;



    pb_variable_array<FieldT> packed_inputs;
    pb_variable_array<FieldT> unpacked_inputs;

    pb_variable_array<FieldT> packed_inputs1;
    pb_variable_array<FieldT> unpacked_inputs1;


    Miximus(int _tree_depth) {
        tree_depth = _tree_depth;

        packed_inputs.allocate(pb, 1 + 1, "packed");
        packed_inputs1.allocate(pb, 1 + 1, "packed");
        msgSenderFee.allocate(pb, "msgSenderFee");
        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;
        address_bits_va.allocate(pb, tree_depth, "address_bits");

        cm.reset(new digest_variable<FieldT>(pb, 256, "cm"));
        root_digest.reset(new digest_variable<FieldT>(pb, 256, "root_digest"));
        sk.reset(new digest_variable<FieldT>(pb, 256, "sk"));
        leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf_digest"));

        //unpacked_inputs.insert(unpacked_inputs.end(), true );
        unpacked_inputs.insert(unpacked_inputs.end(), root_digest->bits.begin(), root_digest->bits.end());
        //unpacked_inputs.insert(unpacked_inputs.end(), cm->bits.begin(), cm->bits.end());

        unpacker.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs,
            packed_inputs,
            FieldT::capacity(),
            "unpacker"
        ));

        unpacked_inputs1.insert(unpacked_inputs1.end(), cm->bits.begin(), cm->bits.end());

        unpacker1.reset(new multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs1,
            packed_inputs1,
            FieldT::capacity(),
            "unpacker"
        ));

        pb.set_input_sizes(4 + 1 );

        input_variable.reset(new block_variable<FieldT>(pb, *cm, *sk, "input_variable")); 

        cm_hash.reset(new sha256_ethereum(
            pb, SHA256_block_size, *input_variable, *leaf_digest, "cm_hash"
        ));
        //sha256_ethereum g(pb, SHA256_block_size, *input_variable, *leaf_digest, "g");

        path_var.reset(new merkle_authentication_path_variable<FieldT, HashT> (pb, tree_depth, "path_var" ));

        //merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");

        ml.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(pb, tree_depth, address_bits_va, *leaf_digest, *root_digest, *path_var, ONE, "ml"));
        //merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, *leaf_digest, *root_digest, path_var, ONE, "ml");

        // generate constraints
        //root_digest.generate_r1cs_constraints();
        unpacker->generate_r1cs_constraints(true);
        unpacker1->generate_r1cs_constraints(false);
  
        generate_r1cs_equals_const_constraint<FieldT>(pb, ZERO, FieldT::zero(), "ZERO");
        cm_hash->generate_r1cs_constraints(true);
        path_var->generate_r1cs_constraints();
        ml->generate_r1cs_constraints();
    }

    void writeKeysToFile(char* pk , char* vk) {
        r1cs_constraint_system<FieldT> constraints = this->pb.get_constraint_system();

        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(this->pb.get_constraint_system());

        //save keys
        vk2json(keypair, vk);

        writeToFile(pk, keypair.pk); 
    }

    char* prove(std::vector<merkle_authentication_node> path, int address, libff::bit_vector address_bits , libff::bit_vector nullifier , libff::bit_vector secret , libff::bit_vector root, int fee, char* pk) { 
        // generate witness
        //unpacker->generate_r1cs_constraints(false);
        //std::vector<merkle_authentication_node> path(tree_depth);

        //libff::bit_vector address_bits;
        //size_t address = 0; // uint of address_bits
        //address_bits = {0,0,0,0}; // defines the ordering of hashing 
        //path = {tree3,tree5,tree9, _tree17};       
        cm->generate_r1cs_witness(nullifier);
        root_digest->generate_r1cs_witness(root);
        sk->generate_r1cs_witness(secret);
        cm_hash->generate_r1cs_witness();  
        //leaf_digest->generate_r1cs_witness(leaf);
        address_bits_va.fill_with_bits(pb, address_bits);
        assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
        pb.val(msgSenderFee) = fee;


        path_var->generate_r1cs_witness(address, path);
        ml->generate_r1cs_witness();
        unpacker->generate_r1cs_witness_from_bits();
        unpacker1->generate_r1cs_witness_from_bits();

        // make sure that read checker didn't accidentally overwrite anything 
        address_bits_va.fill_with_bits(pb, address_bits);
        unpacker->generate_r1cs_witness_from_bits();
        
        root_digest->generate_r1cs_witness(root);


        r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair;
        keypair.pk = loadFromFile<r1cs_ppzksnark_proving_key<alt_bn128_pp>> (pk);


        pb.primary_input();
        pb.auxiliary_input();

        r1cs_primary_input <FieldT> primary_input = pb.primary_input();
        r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
        r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

        auto json = proof_to_json (proof, primary_input);

        auto result = new char[json.size()];
        memcpy(result, json.c_str(), json.size() + 1);
        return result;
    }
};

void genKeys(int tree_depth, char* pkOutput, char* vkOuput) {

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c (tree_depth);
    c.writeKeysToFile(pkOutput, vkOuput );
}

void helloWorld( char* input) { 

    std::cout << input << std::endl;

}

char* prove(bool _path[][256], int _address, bool _address_bits[], int tree_depth, int fee, char* pk) { 

    libff::alt_bn128_pp::init_public_params();
    libff::bit_vector init(0,256);
    libff::bit_vector _nullifier(0,256);
    libff::bit_vector _secret(0, 256);
    libff::bit_vector _root(0,256);
    libff::bit_vector address_bits;

    std::vector<merkle_authentication_node> path(tree_depth);

    init.resize(256);

    path.resize(tree_depth);
    _nullifier.resize(256);    
    _secret.resize(256);
    _root.resize(256);
    std::cout << "tree depth: " << tree_depth << std::endl;
    for (int i =tree_depth - 1; i>=0 ; i--) {
        path[i] = init;
        for (int j =0; j<sizeof(_path[0]); j++) {
            path[i][j] = _path[i][j];
            if ( i ==0 ) {
                _nullifier[j] = _path[tree_depth][j];
                _secret[j] = _path[tree_depth+1][j];
                _root[j] = _path[tree_depth + 2][j];
            }
        } 
    }

    size_t address = 0;
    for (long level = tree_depth-1; level >= 0; level--)
    {  

        const bool computed_is_right = _address_bits[level];

        address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
        address_bits.push_back(computed_is_right);
    } 

    libff::alt_bn128_pp::init_public_params();
    Miximus<FieldT, sha256_ethereum> c(tree_depth);

    auto out = c.prove(path, address , address_bits, _nullifier, _secret, _root, fee, pk);
    return(out);
}

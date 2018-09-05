/*    
    copyright 2018 to the roll_up Authors

    This file is part of roll_up.

    roll_up is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    roll_up is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with roll_up.  If not, see <https://www.gnu.org/licenses/>.
*/


//hash
#include "roll_up_wrapper.hpp"
#include <export.cpp>

#include <roll_up.hpp>



using namespace libsnark;
using namespace libff;

typedef sha256_ethereum HashT;




#include <iostream>
void genKeys(int noTx, char* pkOutput, char* vkOuput) {
    libff::alt_bn128_pp::init_public_params();
    protoboard<FieldT> pb;

    pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;
    //make sure we constarin to zero.

    std::shared_ptr<roll_up<FieldT>> transactions;

    std::vector<std::vector<merkle_authentication_node>> path(noTx);
    path.resize(noTx);


    std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_old(noTx);
    std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_new(noTx);
    std::vector<std::shared_ptr<digest_variable<FieldT>>> new_leaf(noTx);

    std::vector<pb_variable_array<FieldT>> pub_key_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> pub_key_y_bin(noTx);
    std::vector<pb_variable_array<FieldT>> address_bits_va(noTx);
    std::vector<pb_variable_array<FieldT>> rhs_leaf(noTx);

    //signatures setup
    std::vector<pb_variable_array<FieldT>> S(noTx);
    std::vector<pb_variable_array<FieldT>> pk_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> pk_y_bin(noTx);
    std::vector<pb_variable_array<FieldT>> r_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> r_y_bin(noTx);


    for(int k = 0 ; k < noTx; k++) {

        root_digest_old[k].reset(new digest_variable<FieldT>(pb, 256, "root_digest_old"));
        root_digest_new[k].reset(new digest_variable<FieldT>(pb, 256, "root_digest_new"));
        new_leaf[k].reset(new digest_variable<FieldT>(pb, 256, "new leaf"));

        pub_key_x_bin[k].allocate(pb,256,"pub_key_x_bin");
        pub_key_y_bin[k].allocate(pb,256,"pub_key_y_bin");
        address_bits_va[k].allocate(pb, 256, "address_bits");
        rhs_leaf[k].allocate(pb,256,"pub_key_y_bin");


        S[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        pk_x_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        pk_y_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        r_x_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        r_y_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    }

/*    transactions.reset( new roll_up <FieldT> (pb, pub_key_x_bin, pub_key_y_bin, tree_depth,
                                              address_bits_va, root_digest_old, root_digest_new,
                                              path, path, rhs_leaf, S, new_leaf, r_x_bin, r_y_bin, noTx ,"Confirm tx"));

    transactions->generate_r1cs_constraints();


    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(pb.get_constraint_system());

    //save keys
    vk2json(keypair, "../keys/vk.json");

    writeToFile("../keys/pk.raw", keypair.pk);
    writeToFile("../keys/vk.raw", keypair.vk); */
} 

char* prove(bool _path[][tree_depth][256], bool _pub_key_x[][256], bool _pub_key_y[][256] , bool _root[][256],
            bool _address_bits[][tree_depth],  bool _rhs_leaf[][256], 
            bool _new_leaf[][256], bool _r_x[][256], bool _r_y[][256] , bool _S[][256], int _tree_depth, int noTx) { 

    libff::alt_bn128_pp::init_public_params();
    libff::bit_vector init(0,256);
    std::vector<libff::bit_vector> pub_key_x(noTx);
    std::vector<libff::bit_vector> pub_key_y(noTx);
    std::vector<libff::bit_vector> root(noTx);

    std::vector<libff::bit_vector> rhs_leaf_bits(noTx);
    std::vector<libff::bit_vector> new_leaf_bits(noTx);
    std::vector<libff::bit_vector> r_x_bits(noTx);
    std::vector<libff::bit_vector> r_y_bits(noTx);
    std::vector<libff::bit_vector> S_bits(noTx);


    std::vector<libff::bit_vector> address_bits(noTx);

    std::vector<std::vector<merkle_authentication_node>> path(noTx);

    init.resize(256);

    path.resize(noTx);

    pub_key_x.resize(noTx);    
    pub_key_y.resize(noTx);
    root.resize(noTx);
    rhs_leaf_bits.resize(noTx);
    new_leaf_bits.resize(noTx);

    r_x_bits.resize(noTx);
    r_y_bits.resize(noTx);
    S_bits.resize(noTx);


    for(int k = 0 ; k < noTx; k++) { 
        pub_key_x[k].resize(256);
        pub_key_y[k].resize(256);
        root[k].resize(256);
        rhs_leaf_bits[k].resize(256);
        new_leaf_bits[k].resize(256);

        r_x_bits[k].resize(256);
        r_y_bits[k].resize(256);
        S_bits[k].resize(256);

        path[k].resize(tree_depth);
        for (int i =tree_depth - 1; i>=0 ; i--) {
            path[k][i] = init;
            for (int j =0; j<sizeof(_path[k][0]); j++) {
                path[k][i][j] = _path[k][i][j];
           } 
        }

        for (int j = 0 ; j <256 ; j++) { 
            pub_key_x[k][j] = _pub_key_x[k][j];
            pub_key_y[k][j] = _pub_key_y[k][j];
            root[k][j] = _root[k][j];
            rhs_leaf_bits[k][j] = _rhs_leaf[k][j];
            new_leaf_bits[k][j] = _new_leaf[k][j];
            r_x_bits[k][j] = _r_x[k][j];
            r_y_bits[k][j] = _r_y[k][j];
            S_bits[k][j] = _S[k][j];
        } 

        size_t address = 0;
        for (long level = tree_depth-1; level >= 0; level--)
        {  
            const bool computed_is_right = _address_bits[k][level];
            address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
            address_bits[k].push_back(computed_is_right);
        } 
    }

    protoboard<FieldT> pb;

    pb_variable_array<FieldT> old_root;
    pb_variable_array<FieldT> new_root;

    pb_variable_array<FieldT> leaves_data_availability;
    pb_variable_array<FieldT> leaves_addresses_data_availability;



    old_root.allocate(pb, 2, "old_root");
    new_root.allocate(pb, 2, "new_root");



    leaves_data_availability.allocate(pb, noTx*256, "packed");
    leaves_addresses_data_availability.allocate(pb, noTx*256, "packed");

    pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "ZERO");
    pb.val(ZERO) = 0;
    //make sure we constarin to zero.

    std::shared_ptr<roll_up<FieldT>> transactions;

    std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_old(noTx);
    std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_new(noTx);
    std::vector<std::shared_ptr<digest_variable<FieldT>>> new_leaf(noTx);

    std::vector<pb_variable_array<FieldT>> pub_key_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> pub_key_y_bin(noTx);
    std::vector<pb_variable_array<FieldT>> address_bits_va(noTx);
    std::vector<pb_variable_array<FieldT>> rhs_leaf(noTx);

    //signatures setup
    std::vector<pb_variable_array<FieldT>> S(noTx);  
    std::vector<pb_variable_array<FieldT>> pk_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> pk_y_bin(noTx);
    std::vector<pb_variable_array<FieldT>> r_x_bin(noTx);
    std::vector<pb_variable_array<FieldT>> r_y_bin(noTx);


    for(int k = 0 ; k < noTx; k++) {

        root_digest_old[k].reset(new digest_variable<FieldT>(pb, 256, "root_digest_old"));
        root_digest_new[k].reset(new digest_variable<FieldT>(pb, 256, "root_digest_new"));
        new_leaf[k].reset(new digest_variable<FieldT>(pb, 256, "new leaf"));

        pub_key_x_bin[k].allocate(pb,256,"pub_key_x_bin");
        pub_key_y_bin[k].allocate(pb,256,"pub_key_y_bin");
        address_bits_va[k].allocate(pb, 256, "address_bits");
        rhs_leaf[k].allocate(pb,256,"pub_key_y_bin");


        S[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        pk_x_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        pk_y_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        r_x_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
        r_y_bin[k].allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));


        S[k].fill_with_bits(pb, S_bits[k]);

        r_x_bin[k].fill_with_bits(pb, r_x_bits[k]);
        r_y_bin[k].fill_with_bits(pb, r_y_bits[k]); 

        root_digest_old[k]->bits.fill_with_bits(pb, root[k]);
        pub_key_x_bin[k].fill_with_bits(pb, pub_key_x[k]);
        pub_key_y_bin[k].fill_with_bits(pb, pub_key_y[k]);
        address_bits_va[k] = from_bits(address_bits[k], ZERO);
        rhs_leaf[k].fill_with_bits(pb, rhs_leaf_bits[k]);
        new_leaf[k]->bits.fill_with_bits(pb,  new_leaf_bits[k]);
    } 

    transactions.reset( new roll_up <FieldT> (pb, pub_key_x_bin, pub_key_y_bin, tree_depth, 
                                              address_bits_va, root_digest_old, root_digest_new, 
                                              path, path, rhs_leaf, S, new_leaf, r_x_bin, r_y_bin, old_root, new_root, leaves_data_availability, leaves_addresses_data_availability , noTx ,"Confirm tx"));

    transactions->generate_r1cs_constraints();         

    transactions->generate_r1cs_witness();


    std::cout << "is satisfied: " << pb.is_satisfied() << std::endl;
 
    pb.primary_input();
    pb.auxiliary_input();

    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = generateKeypair(pb.get_constraint_system());

    //save keys
    vk2json(keypair, "../keys/vk.json");


    r1cs_primary_input <FieldT> primary_input = pb.primary_input();
    std::cout << "primary_input " << primary_input;
    r1cs_auxiliary_input <FieldT> auxiliary_input = pb.auxiliary_input();
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, primary_input, auxiliary_input);

    auto json = proof_to_json (proof, primary_input, false);     

    auto result = new char[json.size()];
    memcpy(result, json.c_str(), json.size() + 1);     

    return result; 
}
      

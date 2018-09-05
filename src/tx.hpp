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


#include <cassert>
#include <memory>

#include <libsnark/gadgetlib1/gadget.hpp>
#include "baby_jubjub_ecc/main.cpp"



namespace libsnark {

template<typename FieldT, typename HashT>
class tx: public gadget<FieldT> {
//greater than gadget
private:
    /* no internal variables */
public:
    pb_variable<FieldT> a;
    pb_variable<FieldT> d;

    int tree_depth;
    //intermeditate variables 


    pb_variable_array<FieldT> pub_key_x_bin;
    pb_variable_array<FieldT> pub_key_y_bin;
    std::string annotation_prefix = "roll up";

    //internal
    std::shared_ptr<HashT> public_key_hash;
    std::shared_ptr<HashT> leaf_hash;
    std::shared_ptr<HashT> message_hash;



    std::shared_ptr<digest_variable<FieldT>> lhs_leaf;
    pb_variable_array<FieldT> rhs_leaf;

    std::shared_ptr<digest_variable<FieldT>> leaf;
    std::shared_ptr<digest_variable<FieldT>> root_digest_old;
    std::shared_ptr<digest_variable<FieldT>> root_digest_calculated;
    std::shared_ptr<digest_variable<FieldT>> root_digest_new;
    std::shared_ptr<digest_variable<FieldT>> message;


    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var_old;
    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> path_var_new;

    std::shared_ptr<merkle_tree_check_update_gadget<FieldT, HashT>> ml;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> ml_update;

    std::vector<merkle_authentication_node> path_old;
    std::vector<merkle_authentication_node> path_new;
    pb_variable_array<FieldT> address_bits_va;

    std::shared_ptr<eddsa<FieldT, HashT>> jubjub_eddsa;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_pub_key_x;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_pub_key_y;

    std::shared_ptr <block_variable<FieldT>> input_variable;
    std::shared_ptr <block_variable<FieldT>> input_variable2;
    std::shared_ptr <block_variable<FieldT>> input_variable3;


    pb_variable_array<FieldT> pub_key_x;
    pb_variable_array<FieldT> pub_key_y;
    std::shared_ptr<digest_variable<FieldT>> new_leaf;

 
    pb_variable<FieldT> ZERO;
    pb_variable<FieldT> ONE_test;



    tx(protoboard<FieldT> &pb,
                   pb_variable_array<FieldT> &pub_key_x_bin, 
                   pb_variable_array<FieldT> &pub_key_y_bin,
                   int tree_depth, pb_variable_array<FieldT> address_bits_va, std::shared_ptr<digest_variable<FieldT>> root_digest_old,
                   std::shared_ptr<digest_variable<FieldT>> root_digest_new,
                   std::vector<merkle_authentication_node> path_old, std::vector<merkle_authentication_node> path_new, pb_variable_array<FieldT> rhs_leaf,
                   pb_variable_array<FieldT> S, std::shared_ptr<digest_variable<FieldT>> new_leaf, pb_variable_array<FieldT> r_x_bin, pb_variable_array<FieldT> r_y_bin,
                   const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include <tx.tcc>


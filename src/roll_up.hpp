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
#include <tx.hpp>


typedef sha256_ethereum HashT;



namespace libsnark {

template<typename FieldT>
class roll_up: public gadget<FieldT> {
//greater than gadget
private:
    /* no internal variables */
public:
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_old_root;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_new_root;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_leaf_addresses;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker_leaf_hashes;



    pb_variable<FieldT> a;
    pb_variable<FieldT> d;


    pb_variable_array<FieldT> unpacked_addresses;
    pb_variable_array<FieldT> unpacked_leaves;

    std::string annotation_prefix = "roll up";



    int noTx;
    std::vector<std::shared_ptr<tx<FieldT, HashT>>> transactions;


    roll_up(protoboard<FieldT> &pb,
                   std::vector<pb_variable_array<FieldT>> &pub_key_x_bin, 
                   std::vector<pb_variable_array<FieldT>> &pub_key_y_bin,
                   int tree_depth, std::vector<pb_variable_array<FieldT>> address_bits_va, 
                   std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_old, 
                   std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_new,
                   std::vector<std::vector<merkle_authentication_node>> path_old, std::vector<std::vector<merkle_authentication_node>> path_new,
                   std::vector<pb_variable_array<FieldT>> rhs_leaf,
                   std::vector<pb_variable_array<FieldT>> S, std::vector<std::shared_ptr<digest_variable<FieldT>>> new_leaf, 
                   std::vector<pb_variable_array<FieldT>> r_x_bin, std::vector<pb_variable_array<FieldT>> r_y_bin,
                   pb_variable_array<FieldT> old_root , pb_variable_array<FieldT> new_root, pb_variable_array<FieldT> leaves_data_availability,
                   pb_variable_array<FieldT> leaves_addresses_data_availability, 
                   int noTx,
                   const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include <roll_up.tcc>


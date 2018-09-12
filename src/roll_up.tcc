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


namespace libsnark {
    template<typename FieldT>
    roll_up<FieldT>::roll_up(protoboard<FieldT> &pb,
                   std::vector<pb_variable_array<FieldT>> &pub_key_x_bin, 
                   std::vector<pb_variable_array<FieldT>> &pub_key_y_bin,
                   int tree_depth, std::vector<pb_variable_array<FieldT>> address_bits_va, std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_old,  
                   std::vector<std::shared_ptr<digest_variable<FieldT>>> root_digest_new, std::vector<std::vector<merkle_authentication_node>> path_old, 
                   std::vector<std::vector<merkle_authentication_node>> path_new, std::vector<pb_variable_array<FieldT>> rhs_leaf,
                   std::vector<pb_variable_array<FieldT>> S, std::vector<std::shared_ptr<digest_variable<FieldT>>> new_leaf, 
                   std::vector<pb_variable_array<FieldT>> r_x_bin, std::vector<pb_variable_array<FieldT>> r_y_bin, 
                   pb_variable_array<FieldT> old_root , pb_variable_array<FieldT> new_root, 
                   pb_variable_array<FieldT> leaves_data_availability, pb_variable_array<FieldT> leaves_addresses_data_availability,
                   int noTx,
                   const std::string &annotation_prefix): gadget<FieldT>(pb, annotation_prefix) , noTx(noTx) {





    for(uint i = 0; i < noTx-1; i++) { 
        unpacked_addresses.insert(unpacked_addresses.end(), address_bits_va[i].begin(), address_bits_va[i].end()); 
        unpacked_leaves.insert(unpacked_leaves.end(), new_leaf[i]->bits.begin(), new_leaf[i]->bits.end());
    }
 


    unpacker_old_root.reset(new multipacking_gadget<FieldT>(
        pb,
        root_digest_old[0]->bits,
        old_root,
        FieldT::capacity(),
        "old root"
    ));

    unpacker_new_root.reset(new multipacking_gadget<FieldT>(
        pb,
        root_digest_new[noTx-2]->bits,
        new_root,
        FieldT::capacity(),
        "new_root"
    ));

   unpacker_leaf_addresses.reset(new multipacking_gadget<FieldT>(
        pb,
        unpacked_addresses,
        leaves_addresses_data_availability,
        FieldT::capacity(),
        "new_root"
    ));

    unpacker_leaf_hashes.reset(new multipacking_gadget<FieldT>(
        pb,
        unpacked_leaves, 
        leaves_data_availability,
        FieldT::capacity(),
        "new_root"
    ));  
                      //5 for the old root , new root
                      // noTx*2 for address, leaf
                      // noTx*2*253/256 for the left over bits
                      // that do not fit in a 253 bit field element.
    pb.set_input_sizes(6);

    transactions.resize(noTx);
    transactions[0].reset(new tx<FieldT, HashT>(pb,
           pub_key_x_bin[0], pub_key_y_bin[0], tree_depth,address_bits_va[0],root_digest_old[0], 
           root_digest_new[0],path_old[0],path_new[0], rhs_leaf[0], S[0] , new_leaf[0] , r_x_bin[0], r_y_bin[0], 
           "tx i"
       ));

    for (int i =1; i<noTx; i++) {
        transactions[i].reset(new tx<FieldT, HashT>(pb,
               pub_key_x_bin[i], pub_key_y_bin[i], tree_depth,address_bits_va[i],root_digest_new[i-1], 
               root_digest_new[i],path_old[i],path_new[i], rhs_leaf[i], S[i] , new_leaf[i] , r_x_bin[i], r_y_bin[i], 
               "tx i"
           ));
        }


    }

    template<typename FieldT>
    void roll_up<FieldT>::generate_r1cs_constraints() { 
        for (int i =0; i<noTx; i++) {
            transactions[i]->generate_r1cs_constraints();
            }
        unpacker_old_root->generate_r1cs_constraints(true);
        unpacker_new_root->generate_r1cs_constraints(true);
        unpacker_leaf_addresses->generate_r1cs_constraints(true);
        unpacker_leaf_hashes->generate_r1cs_constraints(true);
    } 


    template<typename FieldT>
    void roll_up<FieldT>::generate_r1cs_witness() { 
        for (int i =0; i<noTx; i++) { 
            transactions[i]->generate_r1cs_witness();
        }
        unpacker_old_root->generate_r1cs_witness_from_bits();
        unpacker_new_root->generate_r1cs_witness_from_bits();
        unpacker_leaf_addresses->generate_r1cs_witness_from_bits();
        unpacker_leaf_hashes->generate_r1cs_witness_from_bits();
    }
}

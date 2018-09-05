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
    template<typename FieldT, typename HashT>
    tx<FieldT,HashT>::tx(protoboard<FieldT> &pb,
                   pb_variable_array<FieldT> &pub_key_x_bin, 
                   pb_variable_array<FieldT> &pub_key_y_bin,
                   int tree_depth, pb_variable_array<FieldT> address_bits_va, std::shared_ptr<digest_variable<FieldT>> root_digest_old, 
                   std::shared_ptr<digest_variable<FieldT>> root_digest_new,
                   std::vector<merkle_authentication_node> path_old, std::vector<merkle_authentication_node> path_new, pb_variable_array<FieldT> rhs_leaf,
                   pb_variable_array<FieldT> S, std::shared_ptr<digest_variable<FieldT>> new_leaf, pb_variable_array<FieldT> r_x_bin, pb_variable_array<FieldT> r_y_bin,
                   const std::string &annotation_prefix): gadget<FieldT>(pb, annotation_prefix) ,
                   pub_key_x_bin(pub_key_x_bin), 
                   pub_key_y_bin(pub_key_y_bin) , tree_depth(tree_depth), path_old(path_old), 
                   path_new(path_new), address_bits_va(address_bits_va), rhs_leaf(rhs_leaf), 
                   root_digest_old(root_digest_old), root_digest_new(root_digest_new), new_leaf(new_leaf) {



        pb_variable<FieldT> base_x;
        pb_variable<FieldT> base_y;

        pb_variable<FieldT> a;
        pb_variable<FieldT> d;

        //public key
        pb_variable<FieldT> pub_x;
        pb_variable<FieldT> pub_y;


        base_x.allocate(pb, "base x");
        base_y.allocate(pb, "base y");

        pub_x.allocate(pb, "pub_x");
        pub_y.allocate(pb, "pub_y");


        a.allocate(pb, "a");
        d.allocate(pb, "d");

        pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
        pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

        pb.val(a) = FieldT("168700");
        pb.val(d) = FieldT("168696");


        pub_key_x.allocate(pb,2, "ZERO");
        pub_key_y.allocate(pb,2, "ZERO");

        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;


        lhs_leaf.reset(new digest_variable<FieldT>(pb, 256, "lhs_leaf"));
        leaf.reset(new digest_variable<FieldT>(pb, 256, "lhs_leaf"));

        message.reset(new digest_variable<FieldT>(pb, 256, "message digest"));
       
 
        input_variable.reset(new block_variable<FieldT>(pb, {pub_key_x_bin, pub_key_y_bin}, "input_variable")); 
        input_variable2.reset(new block_variable<FieldT>(pb, {lhs_leaf->bits, rhs_leaf}, "input_variable"));


        public_key_hash.reset(new sha256_ethereum(pb, 256, *input_variable, *lhs_leaf, "pub key hash"));
        leaf_hash.reset(new sha256_ethereum(pb, 256, *input_variable2, *leaf, "pub key hash"));
        input_variable3.reset(new block_variable<FieldT>(pb, {leaf->bits, new_leaf->bits}, "input_variable"));
        message_hash.reset(new sha256_ethereum(pb, 256, *input_variable3, *message, "pub key hash"));


        unpacker_pub_key_x.reset(new multipacking_gadget<FieldT>(
            pb,
            pub_key_x_bin, //pb_linear_combination_array<FieldT>(cm->bits.begin(), cm->bits.begin() , cm->bits.size()),
            pub_key_x,
            FieldT::capacity() + 1, 
            "pack pub key x into var" 
        ));

        unpacker_pub_key_y.reset(new multipacking_gadget<FieldT>(
            pb,
            pub_key_y_bin, //pb_linear_combination_array<FieldT>(cm->bits.begin(), cm->bits.begin() , cm->bits.size()),
            pub_key_y,
            FieldT::capacity() + 1,
            "pack pub key y into var"
        ));

        path_var_old.reset(new merkle_authentication_path_variable<FieldT, HashT> (pb, tree_depth, "path_var" ));
        path_var_new.reset(new merkle_authentication_path_variable<FieldT, HashT> (pb, tree_depth, "path_var" ));

        ml.reset(new merkle_tree_check_update_gadget<FieldT, HashT>(pb, tree_depth, address_bits_va, *leaf, *root_digest_old, *path_var_old, *new_leaf, *root_digest_new, *path_var_new, ONE, "ml"));
        jubjub_eddsa.reset(new eddsa<FieldT, HashT> (pb,a,d, pub_key_x_bin, pub_key_y_bin, base_x,base_y,r_x_bin, r_y_bin, message->bits, S));
    }

    template<typename FieldT, typename HashT>
    void tx<FieldT, HashT>::generate_r1cs_constraints() { 
        jubjub_eddsa->generate_r1cs_constraints();
       
        public_key_hash->generate_r1cs_constraints(true);
        leaf_hash->generate_r1cs_constraints(true);

        message_hash->generate_r1cs_constraints(true);

        unpacker_pub_key_x->generate_r1cs_constraints(true);
        unpacker_pub_key_y->generate_r1cs_constraints(true);

        path_var_old->generate_r1cs_constraints();
        path_var_new->generate_r1cs_constraints();

        root_digest_old->generate_r1cs_constraints();
        root_digest_new->generate_r1cs_constraints();
        ml->generate_r1cs_constraints();   

        //make sure the traget root matched the calculated root
        //for(int i = 0 ; i < 255; i++) {
        //    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, root_digest_old->bits[i], root_digest_calculated->bits[i]),
        //                   FMT(annotation_prefix, " root digests equal"));
        //} 
    } 


    template<typename FieldT, typename HashT>
    void tx<FieldT, HashT>::generate_r1cs_witness() { 
        //debug
        public_key_hash->generate_r1cs_witness();
        leaf_hash->generate_r1cs_witness();
        message_hash->generate_r1cs_witness();

        unpacker_pub_key_x->generate_r1cs_witness_from_bits();
        unpacker_pub_key_y->generate_r1cs_witness_from_bits();

        auto address = address_bits_va.get_field_element_from_bits(this->pb);

        path_var_old->generate_r1cs_witness(address.as_ulong(), path_old);
        path_var_new->generate_r1cs_witness(address.as_ulong(), path_new);

        ml->generate_r1cs_witness();
        jubjub_eddsa->generate_r1cs_witness();

        //debug
        /*
        std::cout << " leaf " ;
        for(uint i =0;i<256;i++) { 
             std::cout << " , " << this->pb.lc_val(leaf->bits[i]);
        }

        std::cout << "new leaf " ;
        for(uint i =0;i<256;i++) { 
             std::cout << " , " << this->pb.lc_val(new_leaf->bits[i]);
        }

        std::cout << "message " ;
        for(uint i =0;i<256;i++) { 
             std::cout << " , " << this->pb.lc_val(message->bits[i]);
        }

        std::cout << " pub_key_x " << this->pb.lc_val(pub_key_x[0]) << " " << this->pb.lc_val(pub_key_x[1]) << std::endl;
        std::cout << " pub_key_y " << this->pb.lc_val(pub_key_y[0]) << " " << this->pb.lc_val(pub_key_y[1]) << std::endl;   
        */
        std::cout << "pub_key_x " ;
        for(uint i =0;i<256;i++) {
             std::cout << " , " << this->pb.lc_val(pub_key_x_bin[i]);
        }


    }
}

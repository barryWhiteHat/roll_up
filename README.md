# roll_up 

[![Join the chat at https://gitter.im/barrywhitehat/roll_up](https://badges.gitter.im/barrywhitehat/roll_up.png)](https://gitter.im/barrywhitehat/roll_up?utm_source=share-link&utm_medium=link&utm_campaign=share-link)

Roll_up aggregates transactions so that they only require a single onchain transactions required to validate multiple other transactions. The snark checks the signature and applies the transaction to the the leaf that the signer owns.

Multiple users create signatures. Provers aggregates these signatures into a snark and use it to update a smart contract on the ethereum blockchain. A malicious prover who does not also have that leafs private key cannot change a leaf. Only the person who controls the private key can. 

This is intended to be the database layer of snark-dapp (snapps) where the layers above define more rules about changing and updating the leaves

`roll_up` does not make any rules about what happens in a leaf, what kind of leaves can be created and destroyed. This is the purview of 
higher level snapps. Who can add their constraints in `src/roll_up.tcc` in the function `generate_r1cs_constraints()`

## In Depth

The system is base use eddsa signatures defined in  [baby_jubjub_ecc](https://github.com/barryWhiteHat/baby_jubjub_ecc) base upon [baby_jubjub](https://github.com/barryWhiteHat/baby_jubjub). It uses sha256 padded with 512 bits input. 

The leaf is defined as follows 
```

                                        LEAF
                        +----------------^----------------+
                       LHS                               RHS
               +----------------+                
           Public_key_x    public_key_y         
```

The leaf is then injected into a merkle tree. 

A transaction updates a single leaf in the merkle tree. A transaction takes the following form. 

```
1. Public key x and y point
2. The message which is defined as the hash of the old leaf and the new leaf. 

                                      MESSAGE
                        +----------------^----------------+
                     OLD_LEAF                          NEW_LEAF

3. the point R and the integer S. 
```


In order to update the merkle tree the prover needs to aggregate together X transactions. For each transaction they check 
```
1. Takes the merkel root as input from the smart contract (if it is the first iteration) or from the merkle root from the previous 
transaction. 
2. Find the leaf that matches the message in the merkle tree. 
NOTE: If there are two messages that match, both can be updated as their is no replay protection this should be solved on the next layer
this is simply the read and write layer, we do not check what is being written here. 
3. Check that the proving key matches the owner of that leaf. 
4. Confirm that the signature is correct.
5. Confirm that that leaf is in the merkle tree. 
6. Replace is with the new leaf and calculate the new merkle root. 
7. Continue until all transactions have been included in a snark
```
The snark can then be included in a transaction to update the merkle root tracked by a smart contract. 


## Data availabilty guarrentees

It is important that each prover is able to make merkle proofs for all leaves.
If they cannot these leaves are essentially locked until that information becomes available.

In order to ensure this, we pass every updated leaf to the smart contract so that
that data will always be available. 

Thus the system has the same data availability guarrentees as ethereum.

## Scalability

Gas cost of function call: 23368
Gas cost of throwing an event with a single leaf update : 1840

Although we don't use groth16 currently. This is the cheapest proving system to our knowledge. 

groth16 confirm:  560000 including tx cost and input data is ~600000.

The gas limit is 8,000,000 per block. So we can use the rest of the gas to maintain data availability. 

8000000 - 600000  =  7400000

We find that 7400000 is the remaining gas in the block. 

So we calculate how much we can spend on data availability

7400000 / 1840 ~= 4021.73913043478

4021.73913043478 / 15 = 268 transactions per second


## Proving time

On a laptop with 7 GB of ram and 20 GB of swap space it struggles to aggragate 20 transactions per second. This is a
combination of my hardware limits and cpp code that needs to be improved. 

[Wu et al](https://eprint.iacr.org/2018/691) showed that is is possible to distribute
these computations that scales to billions of constaints. 

In order to reach the tps described above three approaches exist. 

1. Improve the cpp code similar to https://github.com/HarryR/ethsnarks/issues/3 and run it on enterprise hardware.
2. Implmenting the full distributed system described by Wu et al.
3. Specialized hardware to create these proofs. 


## Distribution

The role of prover can be distributed but it means that each will have to purchase/rent hardware in order to be able to keep up with the longest chain. 

There are a few attacks where the fastest prover is able censor all other provers by constantly updating so the all competing provers proofs are constantly out of date. 

These problem should be mitigated or solved at the consensus level. 


## Running tests 

If you want to run at noTx greater than 10 you will need more than 7GB
to add a bunch of swap space https://www.digitalocean.com/community/tutorials/how-to-add-swap-space-on-ubuntu-16-04

### Build everything 

```
mkdir keys
git submodule update --init --recursive
mkdir build
cd build
cmake .. && make
```

### Run the tests

NOTE: Make sure you have a node running so the smart contract would be deployed and validate the transaction, you can use 
`testrpc` or `ganache-cli`

```
cd ../tests/
python3 test.py
```

### Change the merkle tree depth and number of transactions to be aggregated

You'd need to update two files, and re-build the prover.

In `pythonWrapper/helper.py`

```
tree_depth = 2
noTx = 4
```

In `src/roll_up_wrapper.hpp`

```
const int tree_depth = 2;
```
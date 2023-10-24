use rand::{self}; 
use num_bigint::{BigUint,RandBigInt};

pub fn generate_random_num_in_range(lowerbound: &BigUint, upperbound: &BigUint) -> BigUint{
        let mut rng = rand::thread_rng(); 
        rng.gen_biguint_range(lowerbound, upperbound)
}


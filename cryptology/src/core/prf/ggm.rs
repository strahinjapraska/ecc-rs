use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use rand_chacha::rand_core::SeedableRng;

pub struct GGM{
    key: Option<Vec<u8>>, 
}

impl GGM{
    pub fn new() -> Self{
        Self{ key: None}
    }

    pub fn set_key(&mut self, key: &Vec<u8>){
        self.key = Some(key.to_vec())
        
    }
    pub fn evaluate(&self, x: &Vec<u8>) -> Vec<u8>{

        let key = self.key.as_ref().expect("Key is not set");
        let mut result = key.clone(); 
        let s = result.len(); 

        for &byte in x{
            for i in 0..8{
                let bit = byte>> (7-i)&1; 
                let tmp = self.g(&result); 
                let (begin, end) = if  bit == 0{
                    (0,s) 
                }else{
                    (s, 2*s)
                };
                result = tmp[begin..end].to_vec();

            }
        }
        result

    }
    fn g(&self, x: &Vec<u8>) -> Vec<u8>{
        let length = x.len(); 

        let mut hasher = Sha256::new();
        hasher.update(x); 
        let result = hasher.finalize();

        let seed: [u8; 32] = result.as_slice().try_into().expect("Invalid length"); 

        let mut rng = ChaCha20Rng::from_seed(seed); 
        let mut buffer = vec![0u8; 2*length]; 
        rng.fill_bytes(&mut buffer); 
        buffer 
    }
    

}

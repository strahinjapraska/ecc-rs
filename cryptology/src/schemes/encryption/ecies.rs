use num_bigint::BigUint;
use rand::{Rng, thread_rng}; 
use aes::Aes128;
use ccm::aead::{Aead, KeyInit, generic_array::GenericArray};
use ccm::consts::{U10,U12}; 

use crate::schemes::key_exchange::ecdhe::ECDHE; 
use crate::core::math::elliptic_curve::{EllipticCurve, Point};
use crate::schemes::kdf::kdf2::derive;


pub struct ECIES{

    pub ec: EllipticCurve, 
    pub q: BigUint, 
    pub g: Point 

}

impl ECIES{
  

    fn f(k: &String,m: &str, iv: &[u8;12]) -> String{
        
        let iv: GenericArray<u8, U12> = GenericArray::clone_from_slice(iv);
        
        let key_bytes = hex::decode(k).unwrap();
        let key_bytes = GenericArray::from_slice(&key_bytes);

        type Aesccm = ccm::Ccm<Aes128, U10, U12>; 
        let cipher = Aesccm::new(&key_bytes);

        let ciphertext = cipher.encrypt(&iv, m.as_bytes());

        return hex::encode(&ciphertext.unwrap());

    }

    fn f_inv(k: &String,c: &String, iv: &[u8;12]) -> String{
        
        let iv: GenericArray<u8, U12> = GenericArray::clone_from_slice(iv);
        
        let key_bytes = hex::decode(k).unwrap();
        let key_bytes = GenericArray::from_slice(&key_bytes);

        type Aesccm = ccm::Ccm<Aes128, U10, U12>; 
        let cipher = Aesccm::new(&key_bytes);
        let c = &*hex::decode(&c).unwrap(); 
        let ciphertext = cipher.decrypt(&iv, c).unwrap();
        
        return hex::encode(&ciphertext);

         
    }

    pub fn encrypt(&self, p_v: &Point, m: &str) -> (Point, String, String){

        let key_agreement = ECDHE{
            ec: self.ec.clone(), 
            q: self.q.clone(), 
            g: self.g.clone()
        }; 

        let (s_u, p_u) = key_agreement.generate_key_pair();

        let shared_secret = key_agreement.compute_shared_secret(p_v, &s_u);

     
        let derived_material = derive(&shared_secret.to_str_radix(16),128/8,"");
       

        let mut iv = [0u8; 12]; 
        thread_rng().fill(&mut iv);
        
     
        let c = Self::f(&derived_material, &m, &iv);

    

        (p_u, c, hex::encode(iv))


       
    }


    pub fn decrypt(&self, c: &String ,iv: &String, p_u: &Point, s_v: &BigUint) -> String{

        let key_agreement = ECDHE{
            ec: self.ec.clone(), 
            q: self.q.clone(), 
            g: self.g.clone()
        }; 

        let shared_secret = key_agreement.compute_shared_secret(p_u, s_v);


        let derived_material = derive(&shared_secret.to_str_radix(16),128/8,"");
         

        let bytes = hex::decode(&iv).unwrap();
       
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&bytes[0..12]); 

     


        Self::f_inv(&derived_material, &c, &iv)

    }

}


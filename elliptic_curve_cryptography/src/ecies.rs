use super::elliptic_curve::{EllipticCurve, Point}; 
use num_bigint::BigUint;
use super::kdf2::derive; 
use rand::{Rng, thread_rng}; 
use aes::Aes128;
use ccm::aead::{Aead, KeyInit, generic_array::GenericArray};
use ccm::consts::{U10,U12}; 

use super::ecdhe::ECDHE; 


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

        (p_u, hex::encode(iv), c)


       
    }


    pub fn decrypt(&self, c: &String ,iv: &String, p_u: &Point, s_v: &BigUint) -> String{

        let key_agreement = ECDHE{
            ec: self.ec.clone(), 
            q: self.q.clone(), 
            g: self.g.clone()
        }; 

        let shared_secret = key_agreement.compute_shared_secret(p_u, s_v);


        let derived_material = derive(&shared_secret.to_str_radix(16),128/8,"");

        let bytes = hex::decode(iv).unwrap();

        let mut iv = [0u8; 12];
        iv.copy_from_slice(&bytes[0..12]); 

        Self::f(&derived_material, &c, &iv)

    }

}

#[cfg(test)]
mod test{

    use super::*; 

    #[test]
    fn test_ecies_1(){

        let ec_p_192 = EllipticCurve{
            a: BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffefffffffffffffffc",16).expect("Failed to parse a"),
            b: BigUint::parse_bytes(b"64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",16).expect("Failed to parse b"),
            p: BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffeffffffffffffffff",16).expect("Failed to parse p")
        };

        let g = Point::Coor(BigUint::parse_bytes(b"188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",16).expect("Failed to parse gx"),
                                   BigUint::parse_bytes(b"07192b95ffc8da78631011ed6b24cdd573f977a11e794811",16).expect("Failed to parse gy"));

        let q = BigUint::parse_bytes(b"ffffffffffffffffffffffff99def836146bc9b1b4d22831",16).expect("Failed to parse q"); 

        let scheme = ECIES{
            ec: ec_p_192.clone(), 
            g: g.clone(),
            q: q.clone() 

        };

        let key_agreement = ECDHE{
            ec: ec_p_192.clone(), 
            g: g.clone(), 
            q: q.clone()
        };

        let (s_v ,p_v) = key_agreement.generate_key_pair();

        let m = "Message m"; 

        let (p_u, c, iv) = scheme.encrypt(&p_v, &m); 

        let pt = scheme.decrypt(&c, &iv, &p_u, &s_v); 

        assert_eq!(String::from_utf8_lossy(&hex::decode(pt).unwrap()),m); 

        

    }

}

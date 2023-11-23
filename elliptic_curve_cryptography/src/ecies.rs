use super::elliptic_curve::{EllipticCurve, Point}; 
use num_bigint::BigUint;
use super::kdf2::derive; 

use super::ecdhe::ECDHE; 


pub struct ECIES{

    pub ec: EllipticCurve, 
    pub q: BigUint, 
    pub g: Point 

}

impl ECIES{
  

    pub fn encrypt(&self, p_v: &Point) -> (Point, BigUint, BigUint){

        let key_agreement = ECDHE{
            ec: self.ec.clone(), 
            q: self.q.clone(), 
            g: self.g.clone()
        }; 

        let (s_u, p_u) = key_agreement.generate_key_pair();

        let shared_secret = key_agreement.compute_shared_secret(p_v, &s_u);

        let _derived_material = derive(&shared_secret.to_str_radix(16),128/8+256/8,"");

        (p_u,   BigUint::from(0u32), BigUint::from(0u32)) 


       
    }


    pub fn decrypt(&self) -> BigUint{

        todo!(); 

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
            ec: ec_p_192, 
            g,
            q 

        };

        scheme.encrypt(&Point::Coor(BigUint::from(1u32),BigUint::from(1u32))); 

        

    }

}

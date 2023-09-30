use num_bigint::{BigUint, RandBigInt}; 
use super::elliptic_curve::{EllipticCurve,Point};
use super::finite_field::FiniteField; 
use rand::{self};
use sha256::digest; 


pub struct ECDSA{
    pub ec: EllipticCurve, 
    pub g:  Point ,// a generator
    pub q:  BigUint// order of the group
}

impl ECDSA {

    pub fn generate_key_pair(&self) -> (BigUint, Point) {
        let k_priv = self.generate_random_num(&self.q); // generate private key 
        let k_pub = self.generate_pub_key(&k_priv); 
        (k_priv, k_pub) 
    }

    // r in (0, max)
    pub fn generate_random_num(&self, max: &BigUint) -> BigUint{
        let mut rng = rand::thread_rng();
        rng.gen_biguint_range(&BigUint::from(1u32),&max)

    }  

    pub fn generate_pub_key(&self, k_priv: &BigUint) -> Point{
        self.ec.scalar_mul(&k_priv,&self.g) 
    }


    // 0 < hash < max 
    pub fn generate_hash(&self,message: &str, max: &BigUint) -> BigUint{

        let digest = digest(message);
        let hash_bytes = hex::decode(&digest).expect("Couldn't convert hash to Vec<u8>");
        let hash = BigUint::from_bytes_be(&hash_bytes);
        let hash = hash % (max - BigUint::from(1u32));  
        hash + BigUint::from(1u32) 

    }
    // R = ke * A -> Rx (take x coord) <=> r 
    // s = (h(m) + d*r)*ke^(-1) (mod q)
    // (r,s)
    pub fn sign(&self, hash: &BigUint, k_priv: &BigUint, k_e: &BigUint) -> (BigUint,BigUint){

        assert!(*hash < self.q,"Hash bigger than ord of the group");
        assert!(*k_priv < self.q,"Private key bigger than ord of the group"); 
        assert!(*k_e < self.q,"Random number ke bigger than ord of the group");

        let r_point = self.ec.scalar_mul(&k_e,&self.g); 
        
        if let Point::Coor(r,_) = r_point { // check if it is coordinate 
            let s = FiniteField::mul(&r,&k_priv, &self.q ); 
            let s = FiniteField::add(&s, hash , &self.q); 
            let k_inv = FiniteField::inv_mul(&k_e,&self.q);
            let s = FiniteField::mul(&s,&k_inv, &self.q);
            return (r,s);
        }

        panic!("The random point cannot be identity"); 
    }


    // u1 = s^(-1) * h(m) (mod q)
    // u2 = s^(-1) * r (mod q)
    // P = u1 A + u2 B (mod q) = (xp, yp)
    // r == xp => verified 
    pub fn verify(&self, hash: &BigUint, k_pub: &Point, signature: &(BigUint,BigUint)) -> bool{
        
        assert!(*hash < self.q,"Hash bigger than ord of the group");
       
    
        let (r,s) = signature; 

        let s_inv = FiniteField::inv_mul(&s, &self.q); 
        let u1 = FiniteField::mul(&s_inv,hash, &self.q);
        let u2 = FiniteField::mul(&s_inv,&r, &self.q); 
        
        let u1_a= &self.ec.scalar_mul(&u1, &self.g);  
        let u2_b = &self.ec.scalar_mul(&u2, k_pub); 
        let p = &self.ec.add(&u1_a, &u2_b); 

        if let Point::Coor(xp,_) = p{
            return xp == r; 
        }

        panic!("Point P cannot be the Identity"); 



    }

}

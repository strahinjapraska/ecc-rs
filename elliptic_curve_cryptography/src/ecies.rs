use super::elliptic_curve::{EllipticCurve, Point}; 
use num_bigint::BigUint;
//use super::utils::*; 
//use super::ecdhe::ECDHE; 


pub struct ECIES{

    pub ec: EllipticCurve, 
    pub q: BigUint, 
    pub g: Point 

}

impl ECIES{
  

    pub fn encrypt(&self, _k_b: &Point) -> (Point, BigUint, BigUint){

        todo!(); 
       
    }


    pub fn decrypt(&self) -> BigUint{

        todo!(); 

    }

}



use super::elliptic_curve::{EllipticCurve, Point}; 
use num_bigint::{BigUint};
// use rand::{self}; 

pub struct ECIES{

    pub ec: EllipticCurve, 

}

impl ECIES{

    pub fn encrypt(&self) -> (Point, BigUint, BigUint){

        todo!(); 

    }

    pub fn decrypt(&self) -> BigUint{

        todo!(); 

    }

}



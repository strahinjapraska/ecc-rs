use super::elliptic_curve::{EllipticCurve, Point}; 
use num_bigint::{BigUint, RandBigInt}; 
use rand::{self}; 


pub struct ECDHE{

    pub ec: EllipticCurve, // Elliptic curve that Alice and Bob have agreed on 
    pub g: Point, // Point P also agreed on 
    pub q: BigUint, // ord  

}

impl ECDHE {
    
    
    pub fn generate_key_pair(&self) -> (BigUint,Point) {
        
        let x = self.generate_random_num(&self.q); // random x in [1...q-1]

        let p_x = self.compute_pk(&x); 

        (x, p_x)


    }

    pub fn compute_pk(&self, x: &BigUint) -> Point{

        self.ec.scalar_mul(x, &self.g) // P_x = x*P 

    }
    

    pub fn generate_random_num(&self, max: &BigUint) -> BigUint{

        let mut rng = rand::thread_rng(); 
        rng.gen_biguint_range(&BigUint::from(1u32), max)

    }

    pub fn compute_shared_secret(&self, p_y: &Point, x: &BigUint) -> BigUint {

        let p_xy = self.ec.scalar_mul(x,p_y); 


        if let Point::Coor(x_coord,_) = p_xy{
            return x_coord;
        }

        panic!("Point cannot be identity");
    } 
 
}

#[cfg(test)]
mod test{



    use super::*; 

    #[test]
    fn test_ecdhe_p_192(){

        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing

        // [P-192]
        // COUNT = 0 
        // QCAVSx = 42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0
        // QCAVSy = dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523
        // dIUT = f17d3fea367b74d340851ca4270dcb24c271f445bed9d527
        // QIUTx = b15053401f57285637ec324c1cd2139e3a67de3739234b37
        // QIUTy = f269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6
        // ZIUT = 803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0  

        let ec_p_192 = EllipticCurve{
            a: BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffefffffffffffffffc",16).expect("Failed to parse a"),
            b: BigUint::parse_bytes(b"64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",16).expect("Failed to parse b"),
            p: BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffeffffffffffffffff",16).expect("Failed to parse p")
        };

        let g = Point::Coor(BigUint::parse_bytes(b"188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",16).expect("Failed to parse gx"),
                                   BigUint::parse_bytes(b"07192b95ffc8da78631011ed6b24cdd573f977a11e794811",16).expect("Failed to parse gy"));

        let q = BigUint::parse_bytes(b"ffffffffffffffffffffffff99def836146bc9b1b4d22831",16).expect("Failed to parse q"); 

        let ecdh = ECDHE{
            ec: ec_p_192, 
            g, 
            q 
        }; 

       
        let p_a = Point::Coor(BigUint::parse_bytes(b"b15053401f57285637ec324c1cd2139e3a67de3739234b37",16).expect("Failed to parse"),
                                     BigUint::parse_bytes(b"f269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6",16).expect("Failed to parse"));    
        let a = BigUint::parse_bytes(b"f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",16).expect("Failed to parse"); 
        assert_eq!(ecdh.compute_pk(&a),p_a);

       

        let p_b = Point::Coor(BigUint::parse_bytes(b"42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",16).expect("Failed to parse"),
                                     BigUint::parse_bytes(b"dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523",16).expect("Failed to parse")); 
        let shared_secret = BigUint::parse_bytes(b"803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0", 16).expect("Failed to parse");
        assert_eq!(ecdh.compute_shared_secret(&p_b, &a),shared_secret); 


        




    }




}



    
    



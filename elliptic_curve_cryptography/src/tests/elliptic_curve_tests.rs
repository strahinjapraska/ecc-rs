
#[cfg(test)]
mod elliptic_curve_tests{
    use elliptic_curve_cryptography::elliptic_curve::*; 
    use num_bigint::BigUint;

    
    #[test]
    fn test_ec_point_add(){
        // y^2 = x^3 + 2x + 2 (mod 17) 
        let ec = EllipticCurve {
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32), 
            p: BigUint::from(17u32)
        }; 
    
        let p = Point::Coor(BigUint::from(6u32),BigUint::from(3u32)); // (6,3) 
        let q = Point::Coor(BigUint::from(5u32),BigUint::from(1u32)); // (5,1)
        let r = Point::Coor(BigUint::from(10u32),BigUint::from(6u32)); // (!0,6)

        let res = ec.add(&p,&q); 

        assert_eq!(res, r); 


    }

    #[test]
    fn test_ec_point_add_identity(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32), 
            p: BigUint::from(17u32)
        };

        let p = Point::Coor(BigUint::from(6u32),BigUint::from(3u32));
        let q = Point::Identity; 
        let r =p.clone(); 

        let res = ec.add(&p,&q); 
        assert_eq!(res,r); 

    }

    #[test]
    fn test_ec_point_add_opposite(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32),
            p: BigUint::from(17u32), 


        };

        // (5,16) + (5,1) = Identity 
        let p = Point::Coor(BigUint::from(5u32),BigUint::from(16u32)); 
        let p_prime = Point::Coor(BigUint::from(5u32),BigUint::from(1u32)); 
        let r = Point:: Identity; 

        let res = ec.add(&p,&p_prime);
        assert_eq!(r,res); 


    }

    #[test]
    fn test_ec_point_double(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32),
            p: BigUint::from(17u32), 


        };

        // (5,1) + (5,1) = (6,3)
        let p = Point::Coor(BigUint::from(5u32),BigUint::from(1u32)); 
        let r = Point::Coor(BigUint::from(6u32),BigUint::from(3u32));

        let res =  ec.double(&p);
        assert_eq!(r,res);

    }

    #[test]
    fn test_ec_point_double_identity(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32), 
            p: BigUint::from(17u32), 

        }; 

        let p = Point::Identity; 
        let r = p.clone(); 

        let res = ec.double(&p); 
        assert_eq!(r,res); 

    }

    #[test]
    fn test_ec_point_double_zero(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32), 
            p: BigUint::from(7u32)
        }; 

        let p = Point::Coor(BigUint::from(2u32),BigUint::from(0u32)); 

        let r = ec.double(&p); 
        assert_eq!(r,Point::Identity); 
    }

    #[test]
    fn test_ec_scalar_mul(){
        let ec = EllipticCurve{
            a: BigUint::from(2u32), 
            b: BigUint::from(2u32),
            p: BigUint::from(17u32), 
        };

        // 2(5,1) = (6,3)
        let p = Point::Coor(BigUint::from(5u32), BigUint::from(1u32));
        let r = Point::Coor(BigUint::from(6u32), BigUint::from(3u32));
    
        let res = ec.scalar_mul(&BigUint::from(2u32), &p);
        assert_eq!(res,r); 
    
    }

    #[test]
    fn test_ec_scalar_mul_ord(){
        let ec = EllipticCurve{

            a: BigUint::from(2u32), 
            b: BigUint::from(2u32), 
            p: BigUint::from(17u32), 
        };

        let p = Point::Coor(BigUint::from(5u32),BigUint::from(1u32)); 
        let r = Point::Identity; 

        let res = ec.scalar_mul(&BigUint::from(19u32), &p); 
        assert_eq!(r,res); 
        
    }

    #[test]
    fn test_ec_secp256k1(){

        // y^2 = x^3 + 7 
        //  p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
        //  a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        //  b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
        //  G = ( 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798,
        //        483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8 )
        //  n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141

        let p = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).expect("Can't convert p"); 
        let n = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).expect("Can't convert n");
        let g = Point::Coor(
            BigUint::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).expect("Can't convert Gx"),
            BigUint::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).expect("Can't convert Gy"));

        
        let ec_secp256k1 = EllipticCurve{
            a: BigUint::from(0u32), 
            b: BigUint::from(7u32), 
            p

        }; 

        let res = ec_secp256k1.scalar_mul(&n, &g); // n*G=I 

        assert_eq!(res,Point::Identity); 

    }
}
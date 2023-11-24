#[cfg(test)]
mod test{
    use num_bigint::BigUint;
    use cryptology::ecdsa::*; 
    use cryptology::elliptic_curve::*; 

    #[test]
    fn test_sign_verify(){

        let ecdsa = ECDSA{ 
            ec : EllipticCurve { 
                a: BigUint::from(2u32), 
                b: BigUint::from(2u32), 
                p: BigUint::from(17u32),
            },  
            g: Point::Coor(BigUint::from(5u32),BigUint::from(1u32)), 
            q: BigUint::from(19u32), 
        }; 

        let k_priv = BigUint::from(7u32); // just for unit testing because we need determinism
        let k_pub = ecdsa.generate_pub_key(&k_priv); 

        let k_e = BigUint::from(18u32); 
        let m = "Bob 1.000.000$ -> Alice"; 

        let hash = ecdsa.generate_hash(&m, &ecdsa.q);
        let signature = ecdsa.sign(&hash, &k_priv, &k_e);
      
        let verify_result = ecdsa.verify(&hash, &k_pub, &signature); 

        assert_eq!(verify_result,true);    
        
    }

    #[test]
    fn test_tamper_message(){
        let ecdsa = ECDSA{ 
            ec : EllipticCurve { 
                a: BigUint::from(2u32), 
                b: BigUint::from(2u32), 
                p: BigUint::from(17u32),
            },  
            g: Point::Coor(BigUint::from(5u32),BigUint::from(1u32)), 
            q: BigUint::from(19u32), 
        }; 

        let k_priv = BigUint::from(7u32); // just for unit testing because we need determinism
        let k_pub = ecdsa.generate_pub_key(&k_priv); 

        let k_e = BigUint::from(18u32); 
        let m = "Bob 1.000.000$ -> Alice"; 

        let hash = ecdsa.generate_hash(&m, &ecdsa.q);
        let signature = ecdsa.sign(&hash, &k_priv, &k_e);
      
        let tamper = "Bob 2.000.000$ -> Alice";
        let hash_t = ecdsa.generate_hash(&tamper, &ecdsa.q);  
        let verify_result = ecdsa.verify(&hash_t, &k_pub, &signature); 

        assert_eq!(verify_result,false);    

    }

    #[test]
    fn test_tamper_signature(){
        let ecdsa = ECDSA{ 
            ec : EllipticCurve { 
                a: BigUint::from(2u32), 
                b: BigUint::from(2u32), 
                p: BigUint::from(17u32),
            },  
            g: Point::Coor(BigUint::from(5u32),BigUint::from(1u32)), 
            q: BigUint::from(19u32), 
        }; 

        let k_priv = BigUint::from(7u32); // just for unit testing because we need determinism
        let k_pub = ecdsa.generate_pub_key(&k_priv); 

        let k_e = BigUint::from(18u32); 
        let m = "Bob 1.000.000$ -> Alice"; 

        let hash = ecdsa.generate_hash(&m, &ecdsa.q);
        let signature = ecdsa.sign(&hash, &k_priv, &k_e);
        let (r,s) = signature; 

        let tamper_signature = ( (r+BigUint::from(2u32)) % &ecdsa.q, s);  
        let verify_result = ecdsa.verify(&hash, &k_pub, &tamper_signature); 

        assert_eq!(verify_result,false);    

    }
    #[test]
    fn test_secp256_sign_verify(){
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

        let ecdsa = ECDSA{
            ec: ec_secp256k1, 
            g, 
            q: n,  
        };

        let (k_priv, k_pub) = ecdsa.generate_key_pair();

        let k_e = ecdsa.generate_random_num(&ecdsa.q);

        let m = "Bob: send 1.000.000$ -> Alice"; 
        let hash = &ecdsa.generate_hash(m, &ecdsa.q); 

        let signature = ecdsa.sign(hash, &k_priv, &k_e); 

        let verify_result = ecdsa.verify(hash, &k_pub, &signature); 

        assert_eq!(verify_result,true); 

    }

    #[test]
    fn test_secp256_tamper_message(){
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

        let ecdsa = ECDSA{
            ec: ec_secp256k1, 
            g, 
            q: n,  
        };

        let (k_priv, k_pub) = ecdsa.generate_key_pair();

        let k_e = ecdsa.generate_random_num(&ecdsa.q);

        let m = "Bob: send 1.000.000$ -> Alice"; 
        let hash = ecdsa.generate_hash(m, &ecdsa.q); 

        let signature = ecdsa.sign(&hash, &k_priv, &k_e); 

        let tamper = "Bob: send 2.000.000$ -> Alice"; 
        let hash_t = ecdsa.generate_hash(&tamper, &ecdsa.q); 

        let verify_result = ecdsa.verify(&hash_t, &k_pub, &signature); 

        assert_eq!(verify_result,false); 

    }

    #[test]
    fn test_secp256_tamper_signature(){
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

        let ecdsa = ECDSA{
            ec: ec_secp256k1, 
            g, 
            q: n,  
        };

        let (k_priv, k_pub) = ecdsa.generate_key_pair();

        let k_e = ecdsa.generate_random_num(&ecdsa.q);

        let m = "Bob: send 1.000.000$ -> Alice"; 
        let hash = ecdsa.generate_hash(m, &ecdsa.q); 

        let signature = ecdsa.sign(&hash, &k_priv, &k_e); 
        let (r,s) = signature; 

        let signature_t = ((r+BigUint::from(2u32))% &ecdsa.q,s);

        let verify_result = ecdsa.verify(&hash, &k_pub, &signature_t); 

        assert_eq!(verify_result,false); 

    }

    
}
#[cfg(test)]
mod test{

    use cryptology::schemes::key_exchange::ecdhe::ECDHE; 
    use cryptology::schemes::encryption::ecies::ECIES;
    use cryptology::core::math::elliptic_curve::{EllipticCurve,Point};
    use num_bigint::BigUint; 
    

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


        assert_eq!(String::from_utf8_lossy(&hex::decode(&pt).unwrap()),m);  
        

    }

}

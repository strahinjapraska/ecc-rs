#[cfg(test)]
mod test{
    use std::fs::File;
    use std::collections::HashMap;
    use std::io::{BufRead,BufReader};

    use num_bigint::BigUint; 

    use cryptology::core::math::elliptic_curve::{EllipticCurve,Point}; 
    use cryptology::schemes::key_exchange::ecdhe::ECDHE;    

    

    fn build_dictionary() -> HashMap<String,Vec<BigUint>> {
        let mut ec_dict = HashMap::new(); 

        ec_dict.insert("P-192".to_string(), vec![
            BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffeffffffffffffffff", 16).unwrap(),
            BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffefffffffffffffffc", 16).unwrap(),
            BigUint::parse_bytes(b"64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16).unwrap(),
            BigUint::parse_bytes(b"188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16).unwrap(),
            BigUint::parse_bytes(b"07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16).unwrap(),
            BigUint::parse_bytes(b"ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16).unwrap(),
        ]);

        ec_dict.insert("P-224".to_string(), vec![
            BigUint::parse_bytes(b"ffffffffffffffffffffffffffffffff000000000000000000000001", 16).unwrap(),
            BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", 16).unwrap(),
            BigUint::parse_bytes(b"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16).unwrap(),
            BigUint::parse_bytes(b"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16).unwrap(),
            BigUint::parse_bytes(b"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16).unwrap(),
            BigUint::parse_bytes(b"ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16).unwrap(),
        ]);

        ec_dict.insert("P-256".to_string(), vec![
            BigUint::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap(),
            BigUint::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap(),
            BigUint::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap(),
            BigUint::parse_bytes(b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16).unwrap(),
            BigUint::parse_bytes(b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16).unwrap(),
            BigUint::parse_bytes(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16).unwrap(),
        ]);

        ec_dict.insert("P-384".to_string(), vec![
            BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16).unwrap(),
            BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16).unwrap(),
            BigUint::parse_bytes(b"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16).unwrap(),
            BigUint::parse_bytes(b"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16).unwrap(),
            BigUint::parse_bytes(b"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16).unwrap(),
            BigUint::parse_bytes(b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16).unwrap(),
        ]);

        ec_dict.insert("P-521".to_string(), vec![
            BigUint::parse_bytes(b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            BigUint::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16).unwrap(),
            BigUint::parse_bytes(b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16).unwrap(),
            BigUint::parse_bytes(b"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16).unwrap(),
            BigUint::parse_bytes(b"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16).unwrap(),
            BigUint::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16).unwrap(),
        ]);

        ec_dict
    
    }
    fn get_param_as_biguint(input: &String) -> BigUint{
    
        let parts:Vec<&str> = input.split('=').collect(); 
    
        let t = parts[1].to_string(); 
        let t = t.trim(); 
    
        let r = BigUint::parse_bytes(t.as_bytes(), 16).expect("Failed to parse hex value");
    
        r 
    }

    #[test]
    fn test_nist_ecdhe(){

        let curve_dict = build_dictionary(); 
        
        let file = File::open("src/tests/ecdhe_tests/test_file.txt").expect("Failed to load test vectors");
        let reader = BufReader::new(file); 
    
        let mut current_dh: Option<ECDHE> = None; 
    
        let mut buffer: Vec<String> = Vec::new(); 
        
         for line in reader.lines(){
             if let Ok(line) = line{
    
                let line = line.trim(); 
                
                if line.starts_with("[P-") && line.ends_with("]"){
                    let curve_name = line[1..line.len()-1].to_string(); 
                
                    
                    if let Some(params) = curve_dict.get(&curve_name) {
                        let a = params.get(1).cloned().unwrap_or(BigUint::from(0u32));
                        let b = params.get(2).cloned().unwrap_or(BigUint::from(0u32));
                        let p = params.get(0).cloned().unwrap_or(BigUint::from(0u32));
                        let gx = params.get(3).cloned().unwrap_or(BigUint::from(0u32));
                        let gy = params.get(4).cloned().unwrap_or(BigUint::from(0u32));
                        let q = params.get(5).cloned().unwrap_or(BigUint::from(0u32));
                        
                        
                    let current_curve = EllipticCurve {
                            a,
                            b,
                            p,
                        };
    
                    let current_g = Point::Coor(gx,gy); 
                    let current_q = q; 
    
                    current_dh = Some(ECDHE{
                        ec: current_curve, 
                        g: current_g, 
                        q: current_q
                    });  
    
                    buffer.clear(); 
                    continue; 
    
                    }
                }
             
                if line.starts_with("COUNT"){
                    buffer.clear(); 
                    continue; 
                }
    
                buffer.push(line.to_string());
             
                if buffer.len() == 6 {
                    
                    
                    if let Some(current_dh_ref) = current_dh.as_ref(){
                        let a = get_param_as_biguint(&buffer[2]); 
                        let p_a = Point::Coor(get_param_as_biguint(&buffer[3]),get_param_as_biguint(&buffer[4]));
                        assert_eq!(current_dh_ref.compute_pk(&a),p_a); 
                      
                        let p_b = Point::Coor(get_param_as_biguint(&buffer[0]),get_param_as_biguint(&buffer[1]));
    
                        let shared_secret = get_param_as_biguint(&buffer[5]); 
    
                        assert_eq!(current_dh_ref.compute_shared_secret(&p_b, &a), shared_secret); 
                       
                    }
                   
                    
                }
           
    
            }
    
        }
    
    }

}
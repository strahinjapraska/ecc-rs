use elliptic_curve_cryptography::ecdhe::ECDHE; 
use num_bigint::BigUint;  
use elliptic_curve_cryptography::elliptic_curve::{Point,EllipticCurve}; 
use sha256::digest; 

fn main(){

    // Agree on curve P521
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf
    let ec_p_521 = EllipticCurve{

        a: BigUint::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",16).expect("Failed to parse a"),
        b: BigUint::parse_bytes(b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",16).expect("Failed to parse b"),
        p: BigUint::parse_bytes(b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",16).expect("Failed to parse p")
        
    };
   
    let g = Point::Coor(BigUint::parse_bytes(b"00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",16).expect("Failed to parse gx"),
                               BigUint::parse_bytes(b"011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",16).expect("Failed to parse gy"));

    let q = BigUint::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",16).expect("Failed to parse q"); 

    // Setup key exchange 

    let ecdh = ECDHE{
        ec: ec_p_521, 
        g, 
        q 
    }; 

    let (a,p_a) = ecdh.generate_key_pair(); // Alice kpriv, kpub
    let (b, p_b) = ecdh.generate_key_pair(); // Bob kpriv, kpub 

    let shared_secret_a = ecdh.compute_shared_secret(&p_b, &a); // Alice computes a(bP) 
    let shared_secret_b = ecdh.compute_shared_secret(&p_a, &b); // Bob computes b(aP)

    // Use hashing function to get 256 bits 
    let hash_a = digest(BigUint::to_bytes_le(&shared_secret_a));
    let hash_b = digest(BigUint::to_bytes_le(&shared_secret_b));
    
    assert_eq!(hash_a,hash_b); 



}
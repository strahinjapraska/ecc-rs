use num_bigint::BigUint; 

pub struct FiniteField{


}


impl FiniteField{

    pub fn add(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint{
        assert!(a < p, "a > p"); 
        assert!(b < p, "b > p"); 

        (a + b).modpow(&BigUint::from(1u32), &p)
    }

    pub fn mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint{
        assert!(a < p, "a > p"); 
        assert!(b < p, "b > p"); 

        (a * b).modpow(&BigUint::from(1u32), &p)
    }

    pub fn inv_add(a: &BigUint, p: &BigUint) -> BigUint{
        // r = - a (mod p)
        assert!(a < p, "a > p"); 

        p - a
    }

    pub fn inv_mul(a: &BigUint, p: &BigUint) -> BigUint{
        // r = a^(-1) (mod p) = a^(p-2) (mod p) 
        // we will use Fermat's little theorem, p must be prime  
        // a^(p-1) = 1 (mod p)
        // a^(p-2) = a^-1 (mod p)
        assert!(a < p, "a > p"); 

        a.modpow(&(p-BigUint::from(2u32)),p)

    }
    pub fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        // r = a-b (mod p) = a + (-b) (mod p)
        assert!(a < p, "a > p"); 
        assert!(b < p, "b > p"); 

        let b_inv = FiniteField::inv_add(b,p);
        FiniteField::add(a,&b_inv,p)

    }

    pub fn div(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint{
        // r =  a/b (mod p) = a*b^(-1) (mod p)
        assert!(a < p, "a > p"); 
        assert!(b < p, "b > p"); 
        
        let b_inv = FiniteField::inv_mul(b,p); 
        FiniteField::mul(a,&b_inv,p)
    }
}

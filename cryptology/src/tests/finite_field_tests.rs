#[cfg(test)]
mod finite_field_tests{ 
    use cryptology::core::math::finite_field::*;
    use num_bigint::BigUint;  
   

    #[test] 
    fn test_add_1(){
        let a: BigUint = BigUint::from(4u32); 
        let b: BigUint = BigUint::from(10u32); 
        let p: BigUint = BigUint::from(11u32); 

        let r = FiniteField::add(&a,&b,&p); 

        assert_eq!(r,BigUint::from(3u32))
    }
    
    #[test] 
    fn test_add_2(){
        let a: BigUint = BigUint::from(4u32); 
        let b: BigUint = BigUint::from(10u32); 
        let p: BigUint = BigUint::from(31u32); 

        let r = FiniteField::add(&a,&b,&p); 

        assert_eq!(r,BigUint::from(14u32))
    }

    #[test]
    fn test_mul_1(){
        let a: BigUint = BigUint::from(4u32); 
        let b: BigUint = BigUint::from(10u32); 
        let p: BigUint = BigUint::from(11u32); 

        let r = FiniteField::mul(&a,&b,&p); 

        assert_eq!(r,BigUint::from(7u32)); 
    }

    #[test]
    fn test_mul_2(){
        let a: BigUint = BigUint::from(4u32); 
        let b: BigUint = BigUint::from(10u32); 
        let p: BigUint = BigUint::from(53u32); 

        let r = FiniteField::mul(&a,&b,&p); 

        assert_eq!(r,BigUint::from(40u32)); 
    }

    #[test]
    fn test_add_inv_1(){
        let a: BigUint = BigUint::from(4u32); 
        let p: BigUint = BigUint::from(51u32); 
        
        let r: BigUint = FiniteField::inv_add(&a, &p); 

        assert_eq!(r,BigUint::from(47u32)); 
        
    }

    #[test]
    #[should_panic]
    fn test_add_inv_2(){
        let a: BigUint = BigUint::from(52u32); 
        let p: BigUint = BigUint::from(51u32); 

        FiniteField::inv_add(&a, &p); 

    }

    #[test]
    fn test_add_inv_3(){
        let a: BigUint = BigUint::from(4u32); 
        let p: BigUint = BigUint::from(51u32); 

        let a_inv: BigUint = FiniteField::inv_add(&a, &p); 

        assert_eq!(FiniteField::add(&a, &a_inv, &p), BigUint::from(0u32)); 

    }

    #[test] 
    fn test_mul_inv_1(){
        let a: BigUint = BigUint::from(4u32); 
        let p: BigUint = BigUint::from(11u32); 

        let a_inv: BigUint = FiniteField::inv_mul(&a, &p); 

        assert_eq!(FiniteField::mul(&a,&a_inv,&p),BigUint::from(1u32));
    }

    #[test] 
    fn test_div(){
        let a: BigUint = BigUint::from(5u32); 
        let p: BigUint = BigUint::from(17u32); 

        assert_eq!(FiniteField::div(&a,&a,&p),BigUint::from(1u32)); 

    }

    #[test]
    fn test_sub(){
        let a: BigUint = BigUint::from(5u32); 
        let p: BigUint = BigUint::from(17u32); 

        assert_eq!(FiniteField::sub(&a,&a,&p),BigUint::from(0u32)); 


    }

}

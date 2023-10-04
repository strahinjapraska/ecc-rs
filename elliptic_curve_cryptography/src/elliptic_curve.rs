use num_bigint::BigUint; 
use super::finite_field::FiniteField; 

#[derive(PartialEq,Clone,Debug)] // tells compiler to compare field by field 
pub enum Point{

    Coor(BigUint,BigUint),
    Identity, 
    // P(x,y)

}
pub struct EllipticCurve{
    pub a:BigUint, 
    pub b:BigUint, 
    pub p:BigUint
    // y**2 = x**3 + a*x + b (mod p ) 
}

impl EllipticCurve{

    pub fn add(&self,a: &Point, b: &Point) -> Point{
        assert!(self.is_on_curve(a),"Point a is not on curve"); 
        assert!(self.is_on_curve(b),"Point b is not on curve"); 
        assert!(*a != *b, "Points should not be the same"); 

        match(a,b) {  
            (Point::Identity, _) => b.clone(), 
            (_, Point::Identity) => a.clone(),
            (Point::Coor(x1,y1),Point::Coor(x2,y2)) => {
            
                if x1 == x2 && FiniteField::add(&y1,&y2,&self.p) == BigUint::from(0u32){

                    return Point::Identity; 
                
                }

                let numerator  = FiniteField::sub(y2,y1,&self.p); 
                let denominator = FiniteField::sub(x2,x1,&self.p); 
                let s = FiniteField::div(&numerator,&denominator,&self.p); 
                
                let(x3,y3) = self.compute_x3_y3(&s,x1,x2,y1); 

                Point::Coor(x3,y3)


            }, 
        }
    }

    pub fn double(&self,a: &Point) -> Point{
        assert!(self.is_on_curve(a),"Point a is not on a curve"); 
        

        match a {
            Point::Identity => Point::Identity, 
            Point::Coor(x1, y1) => {

                if *y1 == BigUint::from(0u32){
                    return Point::Identity;
                }
                let numerator = x1.modpow(&BigUint::from(2u32),&self.p); 
                let numerator = FiniteField::mul(&BigUint::from(3u32),&numerator,&self.p);
                let numerator = FiniteField::add(&self.a,&numerator,&self.p); 

                let denominator = FiniteField::mul(&BigUint::from(2u32),y1,&self.p); 
                
                let s = FiniteField::div(&numerator,&denominator,&self.p);

                let (x3,y3) = self.compute_x3_y3(&s,x1,x1,y1); 
               
                Point::Coor(x3,y3)
            }

        }
        

    }
    fn compute_x3_y3(&self, s: &BigUint, x1: &BigUint, x2: &BigUint, y1: &BigUint) -> (BigUint,BigUint){

        let x3 = s.modpow(&BigUint::from(2u32),&self.p); 
        let x3 = FiniteField::sub(&x3,&x1,&self.p); 
        let x3 = FiniteField::sub(&x3,x2,&self.p); 
        
        let y3 = FiniteField::sub(x1,&x3,&self.p); 
        let y3 = FiniteField::mul(&s,&y3,&self.p); 
        let y3 = FiniteField::sub(&y3, y1, &self.p); 

        (x3,y3)

    }
    pub fn scalar_mul(&self,d: &BigUint, a: &Point) -> Point{
        // For multiplication method used is Montgomery ladder 
        // B = d*A 
        let mut r0 = Point::Identity; 
        let mut r1 = a.clone();

        for i in(0..d.bits()).rev(){
            if d.bit(i){
                r0 = self.add(&r0,&r1);
                r1 = self.double(&r1);  
            }
            else{
                r1 = self.add(&r0,&r1); 
                r0 = self.double(&r0); 
            }
        }

        r0 

        
    }

    pub fn is_on_curve(&self,a: &Point) -> bool {

        match a {
            Point::Coor(x,y) => {
                    let y2 = y.modpow(&BigUint::from(2u32), &self.p); 
                    let x3 = x.modpow(&BigUint::from(3u32),&self.p); 
                    let ax = FiniteField::mul(&self.a,x,&self.p); 
                    let x3_plus_ax = FiniteField::add(&x3,&ax,&self.p); 
                    
                    y2 == FiniteField::add(&x3_plus_ax,&self.b,&self.p)

            }
            Point::Identity => true, 
        }
    }
}

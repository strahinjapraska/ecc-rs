use num_bigint::BigUint;

pub struct ChaumPedersen{

    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint

}
impl ChaumPedersen{
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint{

        if *k >= c*x {
            return (k-c*x).modpow(&BigUint::from(1u32), &self.q) ;
        }
        &self.q - (c*x - k).modpow(&BigUint::from(1u32), &self.q)

    }

    pub fn verify(&self, y1: &BigUint, y2: &BigUint, r1: &BigUint, r2: &BigUint, c: &BigUint, s: &BigUint) -> bool{
        let cond1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c,&self.p)).modpow(&BigUint::from(1u32), &self.p);
        let cond2 = *r2 == (&self.beta.modpow(s,&self.p) * y2.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        cond1 && cond2
    }
}

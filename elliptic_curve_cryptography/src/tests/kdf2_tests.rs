#[cfg(test)]
mod test{

    use elliptic_curve_cryptography::kdf2::*; 

    #[test]
    fn test_kdf2_1(){

        let x = "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08"; 
        let param1 = ""; 
        let r  = "443024c3dae66b95e6f5670601558f71"; 
        let l = (r.len()/2) as u32;

        let derived_material = derive(x,l,param1); 

        assert_eq!(r,derived_material);
    }

    #[test]
    fn test_kdf2_2(){

        let x = "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4";
        let param1 = "";
        let r  = "b6295162a7804f5667ba9070f82fa522";
        let l = (r.len()/2) as u32; 

        let derived_material = derive(x,l,param1); 

        assert_eq!(r,derived_material);
    }

    #[test]
    fn test_kdf2_3(){
        let x = "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d"; 
        let param1 = "75eef81aa3041e33b80971203d2c0c52"; 
        let r  = "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21"; 
        let l = (r.len()/2) as u32; 

        let derived_material = derive(x,l,param1); 

        assert_eq!(r,derived_material); 
    }

    #[test]
    fn test_kdf2_4(){

        let x = "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a";
        let param1 = "d65a4812733f8cdbcdfb4b2f4c191d87";
        let r = "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b";
        let l = (r.len()/2) as u32; 

        let derived_material = derive(x,l,param1); 

        assert_eq!(r,derived_material); 



    }
}
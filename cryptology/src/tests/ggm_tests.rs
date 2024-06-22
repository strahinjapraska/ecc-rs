#[cfg(test)]
mod ggm_tests{

    use cryptology::core::prf::ggm::{self, GGM};
    use hex::encode;

    #[test]
    fn test_ggm(){
        let key = b"\xf0\x9b\x8f\xbc1\x93\x9d\x19\xdc\xcf\x105\xf0\x8f%\xa6U\xb3b\xdb\xef\x80yj\x92\r\xdf\xc6\xc3\xa62\xa3".to_vec();
        let message = "hello world";
        let mut prf = GGM::new();
        prf.set_key(&key);
        let result = prf.evaluate(&message.as_bytes().to_vec());
        println!("{:?}",result)
    }
}
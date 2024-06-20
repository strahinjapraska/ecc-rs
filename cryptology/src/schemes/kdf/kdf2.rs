use sha256::digest; 

pub fn derive(x: &str ,l: u32, param1: &str) -> String{ 
    
    assert!(l > 0 , "Length must be > 0");
    let k = (l as f64/32.0).ceil() as u32;  
   
    let mut output = "".to_string(); 
    for i in 1..=k{
        let input = x.to_string() + &format!("{:08x}",i) + param1; 
        
        match hex::decode(input){
            Ok(input_bytes) => {
                let hash = digest(input_bytes);
                output+= &hash;
            }, 
            Err(e) => {
                eprintln!("Error decoding hex: {}", e);
            }
        }
     
        
    }
   

    output.truncate(2*l as usize); 

    output 
}



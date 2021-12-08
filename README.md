# letterman_email_body_parser

this is a tokio based email body parser and dkim validator, the input should not include the data end flag "\r\n.\r\n",dkim keys are cached in a tokio RwLock for fatser reads, if no dkim is provided validation returns successfull.
   
## sample code  

```rust 

use letterman_email_body_parser::{init,Config,io};

#[tokio::main]
async fn main() {

    //io is for testing this is exposed as a module so keep that in mind
    let value:String;
    match io::read_string("./gl_alt_atch.txt"){
        Ok(v)=>{value = v;},
        Err(_)=>{
            println!("failed-read_file");
            return;
        }
    }

    let hold:Vec<&str> = value.split("\r\n").collect();
  
    let conf:Config;
    match Config::new(){
        Ok(v)=>{conf = v;},
        Err(_)=>{
            println!("failed-conf");
            return;
        }
    }

    match init(hold,&conf){
        Ok(mut email)=>{
            println!("email body parsed");
            match email.validate(&conf).await{
                Ok(_)=>{
                    println!("email validated");
                },
                Err(_e)=>{
                    println!("email validation failed : {:?}",_e);
                }
            }
        },
        Err(_e)=>{
            println!("email body failed : {:?}",_e);
        }
    }

}

```

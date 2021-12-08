

pub mod io;
mod config;
mod parser;
mod part;
pub mod dkim;

//./gl_alt_atch.txt
//./sldv_atch.txt
//../letterman_tools/emails/sldv_atch.txt

pub use config::{Config,PartHandler,EmailBody,Dkim,ContentEncoding,ContentDecoded,Part};

///this is a tokio based email body parser and dkim validator, the input should not include the data end flag "\r\n.\r\n",dkim keys are cached in a tokio RwLock for fatser reads, if no dkim is provided validation returns successfull.
/// 
/// dkim validation functions are exposed for use in dkim module, all required dkim functions are functional, rsa operations are handled via openssl verifier.
/// 
/// dns queries are performed with asynresolver in trust_dns_resolver.
/// 
/// ```
/// 
/// use letterman_email_body_parser::{init,Config,io};
///
/// #[tokio::main]
/// async fn main() {
///
///     //io is for testing this is exposed as a module so keep that in mind
///     let value:String;
///     match io::read_string("./gl_alt_atch.txt"){
///         Ok(v)=>{value = v;},
///         Err(_)=>{
///             println!("failed-read_file");
///             return;
///         }
///     }
///
///     let hold:Vec<&str> = value.split("\r\n").collect();
///   
///     let conf:Config;
///     match Config::new(){
///         Ok(v)=>{conf = v;},
///         Err(_)=>{
///             println!("failed-conf");
///             return;
///         }
///     }
///
///     match init(hold,&conf){
///         Ok(mut email)=>{
///             println!("email body parsed");
///             match email.validate(&conf).await{
///                 Ok(_)=>{
///                     println!("email validated");
///                 },
///                 Err(_e)=>{
///                     println!("email validation failed : {:?}",_e);
///                 }
///             }
///         },
///         Err(_e)=>{
///             println!("email body failed : {:?}",_e);
///         }
///     }
///
/// }
/// ```
fn init(lines:Vec<&str>,config:&Config)->Result<EmailBody,&'static str>{

    let mut data_started:bool = false;
    let mut boundry_started = false;
    let mut boundaries:Vec<String> = vec![];
    let mut part_handler = PartHandler::new();
    let mut body = EmailBody::new();

    for i in lines{

        if i.contains("DKIM-Signature") && body.dkim_found == false{
            match parser::parse_only_features(&config,i){
                Ok(v)=>{
                    body.dkim.overtake(v.0,v.2);
                    body.dkim_found = true;
                },
                Err(_e)=>{
                    // println!("invalid-DKIM_Signature : {:?}",_e);
                    return Err("invalid-DKIM_Signature");
                }
            }
            match parser::parse_keyval(&config, i){
                Ok(hold)=>{
                    body.header(hold.0,hold.1);
                },
                Err(_)=>{}
            }
        } else if i.contains("Content-Type"){
            match parser::parse_content_type(&config,i){
                Ok(ct)=>{
                    if ct.0.contains("multipart"){
                        match ct.1.get("boundary"){
                            Some(b)=>{
                                boundaries.push(b.to_string());
                            },
                            None=>{
                                return Err("not_found-boundry-Content-Type");
                            }
                        }
                    }
                    match parser::parse_keyval(&config, i){
                        Ok(hold)=>{
                            if !boundry_started{
                                body.header(hold.0,hold.1);
                                body.content_type = ct;
                            } else {
                                part_handler.content_feature(hold.0,hold.1);
                                part_handler.content_type(ct);
                            }
                        },
                        Err(_)=>{}
                    }
                    data_started = false;
                },
                Err(_)=>{
                    if !data_started{   
                        return Err("failed-parse-Content-Type");
                    } else {
                        part_handler.data(i.to_string());
                    }
                }
            }
        } else if i.len() > 0 && !data_started {
            match parser::parse_keyval(&config,i){
                Ok(v)=>{
                    if boundry_started{
                        part_handler.content_feature(v.0, v.1);
                    } else {
                        body.header(v.0,v.1);
                    }
                },
                Err(_)=>{
                    return Err("failed-parse-keyval");
                }
            }
        } else if i.len() == 0{//empty flag
            data_started = true;
            boundry_started = false;
        } else if i.len() > 0{//check if data should be processed
            if data_started{
                //check if data is boundary
                match config.boundary_regex.captures(i){
                    Some(captures)=>{
                        //get boundary
                        match captures.get(1){
                            Some(boundary_m)=>{
                                let boundary = boundary_m.as_str();
                                //get boundary end flag
                                match captures.get(2){
                                    Some(c)=>{
                                        let len = c.end() - c.start();
                                        if len > 0{
                                            //boundary end
                                            match boundaries.pop(){
                                                Some(b)=>{
                                                    if b != boundary{
                                                        return Err("invalid_boundary_end-diff");
                                                    } 
                                                },
                                                None=>{
                                                    return Err("invalid_boundary_end-overflow");
                                                }
                                            }
                                        } else {
                                            //boundary start = no boundry matched
                                            boundry_started = true;
                                            part_handler.flush();
                                        }
                                    },
                                    None=>{
                                        //boundary start
                                        boundry_started = true;
                                        part_handler.flush();
                                    }
                                }//get boundary end flag
                            },
                            None=>{}
                        }//get boundary
                    },
                    None=>{
                        //data is not boundary
                        part_handler.data(i.to_string());
                    }
                }//check if data is boundary
            }//check if data should be processed
        }//if its data type

    }

    match body.parts(part_handler){
        Ok(_)=>{
            return Ok(body);
        },
        Err(_)=>{
            return Err("failed-parse_parts");
        }
    }

}
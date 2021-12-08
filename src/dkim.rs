use openssl::pkey::{PKey,Public};
use std::collections::HashMap;
use crate::{EmailBody,Config};
use crate::parser::parse_only_features;
use openssl::sign::Verifier;
use base64::decode as Base64Decode;
use openssl::hash::MessageDigest;

pub async fn init(email:&mut EmailBody,config:&Config)->Result<(),&'static str>{

    match check_basic_validation(email){
        Ok(_)=>{},
        Err(_)=>{
            return Err("basic-validation-failed");
        }
    }

    if !email.dkim_found{
        return Ok(());
    }

    let dkim_verification_string:String;
    match get_dkim_signature_string(email){
        Ok(v)=>{dkim_verification_string = v;},
        Err(_)=>{
            return Err("failed-dkim_verification_string");
        }
    }

    let signature_string:String;
    match email.dkim.features.get("b"){
        Some(v)=>{
            signature_string = v.to_string();
        },
        None=>{
            return Err("failed-get-dkim-selector");
        }
    }

    let sender:String;
    match get_sender_from_email_headers(email,config){
        Ok(v)=>{sender = v;},
        Err(_)=>{
            return Err("failed-get_sender_from_email_headers");
        }
    }

    let key_name:String;
    match get_dkim_key_name(email,&sender){
        Ok(v)=>{key_name = v;},
        Err(_)=>{
            return Err("failed-get_sender_from_email_headers");
        }
    }

    //----------------------------------
    //check if key is in buffer
    //----------------------------------

    {
        let read_lock = config.keys.read().await;
        if read_lock.contains_key(&key_name){
            match read_lock.get(&key_name){
                Some(key)=>{
                    match verify_dkim_signature(dkim_verification_string,&key,signature_string){
                        Ok(v)=>{
                            if v{
                                return Ok(());
                            } else {
                                return Err("invalid-dkim");
                            }
                        },
                        Err(_e)=>{
                            return Err("failed-get_dkim_sender_key");
                        }
                    }
                },
                None=>{}
            }
        }
    }

    //----------------------------------
    //get key from source and verify
    //----------------------------------

    let key:PKey<Public>;
    match get_dkim_sender_key(config,&key_name).await{
        Ok(v)=>{
            key = v;
        },
        Err(_e)=>{
            println!("failed-get_dkim_sender_key : {}",_e);
            return Err("failed-get_dkim_sender_key");
        }
    }

    {
        let mut write_lock = config.keys.write().await;
        write_lock.insert(key_name.clone(),key.clone());
    }

    match verify_dkim_signature(dkim_verification_string,&key,signature_string){
        Ok(v)=>{
            if v{
                return Ok(());
            } else {
                return Err("invalid-dkim");
            }
        },
        Err(_e)=>{
            return Err("failed-get_dkim_sender_key");
        }
    }

}

pub fn verify_dkim_signature(verification_string:String,key:&PKey<Public>,signature:String)->Result<bool,&'static str>{

    // println!("\n{}\n",verification_string);

    let signature_buffer:Vec<u8>;
    match Base64Decode(&signature){
        Ok(v)=>{signature_buffer = v;},
        Err(_)=>{
            return Err("failed-parse_to_u8_buffer");
        }
    }

    // println!("signature buffered");

    let mut verifier:Verifier;
    match Verifier::new(MessageDigest::sha256(), &key){
        Ok(v)=>{verifier = v;},
        Err(_)=>{
            return Err("failed-init-verifier");
        }
    }

    // println!("verifier initiated");

    match verifier.update(verification_string.as_bytes()){
        Ok(_)=>{},
        Err(_)=>{
            return Err("failed-update-verifier");
        }
    }

    // println!("verifier updated");

    match verifier.verify(&signature_buffer){
        Ok(r)=>{
            // println!("verification result : {:?}",r);
            return Ok(r);
        },
        Err(_)=>{
            return Err("failed-verify-verifier");
        }
    }

    // println!("signature buffered");

    // return Err("no_error");

}

pub async fn get_dkim_sender_key(config:&Config,key_name:&String)->Result<PKey<Public>,&'static str>{

    let mut dkim_key_string = String::new();
    let mut dkim_found = false;
    match config.resolver.txt_lookup(key_name.to_string()).await{
        Ok(lookup)=>{
            for i in lookup.iter(){
                let as_str = i.to_string();
                if as_str.contains("DKIM"){
                    dkim_found = true;
                    dkim_key_string = as_str;
                    break;
                }
            }
        },
        Err(_)=>{
            return Err("failed-txt-lookup");
        }
    }

    if !dkim_found{
        return Err("not_found-dkim_key");
    }

    let features:HashMap<String,String>;
    match parse_only_features(config,&format!("key:{}",dkim_key_string)){
        Ok(ct)=>{
            features = ct.0;
        },
        Err(_e)=>{
            println!("failed-parse-dkim_key_string : {:?}",_e);
            return Err("failed-parse-dkim_key_string");
        }
    }

    let mut key:String;
    match features.get("p"){
        Some(v)=>{
            key = String::from(v);
        },
        None=>{
            return Err("not_found-dkin-key");
        }
    }

    if !key.contains("PUBLIC KEY"){
        key = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",key);
    }

    let private_key:PKey<Public>;
    match PKey::public_key_from_pem(&key.into_bytes()){
        Ok(k)=>{
            private_key = k;
        },
        Err(e)=>{
            println!("!!! failed-parse_private_key => {:?}",e);
            return Err("failed-invalid_key");
        }
    }

    return Ok(private_key);

}

pub fn get_dkim_signature_string(email:&mut EmailBody)->Result<String,&'static str>{

    let parts:Vec<&str>;
    match email.dkim.features.get("h"){
        Some(v)=>{parts = v.split(":").collect();},
        None=>{
            return Err("not_found-h-dkim");
        }
    }

    let mut email_headers = String::new();
    for part in parts.iter(){
        // println!("part : {:?}",part);
        match email.headers.get(&part.to_string()){
            Some(v)=>{
                // email_headers.push_str(&format!("{}:{}\r\n",part,v.trim_end()));
                email_headers += part;
                email_headers += ":";
                email_headers += v.trim_end();
                email_headers += "\r\n";
                // email_headers +
            },
            None=>{
                return Err("not_found-header-dkim");
            }
        }
    }

    // println!("dkim features {:?}",email.dkim.features);

    let mut dkim_features = String::new();

    for key in email.dkim.order.iter(){
        // println!("k : {:?}",key);
        let value:String;
        match email.dkim.features.get(key){
            Some(v)=>{value = v.to_string();},
            None=>{
                return Err("failed-find_dkim_feature");
            }
        }
        if key != "b"{
            if dkim_features.len() > 0{
                dkim_features.push_str("; "); 
            }
            dkim_features.push_str(&format!("{}={}",key,value));
        } else {
            if dkim_features.len() > 0{
                dkim_features.push_str("; "); 
            }
            dkim_features += "b=";
        }
    }

    let final_build = format!("{}dkim-signature:{}",email_headers,dkim_features);

    return Ok(final_build);

}

pub fn check_basic_validation(email:&mut EmailBody)->Result<(),&'static str>{

    if !email.headers.contains_key("to"){
        return Err("not_found-to-header");
    }

    if !email.headers.contains_key("from"){
        return Err("not_found-to-header");
    }

    if !email.headers.contains_key("subject"){
        return Err("not_found-to-header");
    }

    return Ok(());

}

pub fn get_sender_from_email_headers(email:&mut EmailBody,config:&Config)->Result<String,&'static str>{

    let from:&str;
    match email.headers.get("from"){
        Some(v)=>{from = v;},
        None=>{return Err("not_found-from-header");}
    }

    match config.from_regex.captures(from){
        Some(captures)=>{
            match captures.get(2){
                Some(domain)=>{
                    return Ok(domain.as_str().to_string());
                },
                None=>{
                    return Err("failed-get_email-from_header");
                }
            }
        },
        None=>{
            return Err("failed-get_email-from_header");
        }
    }

}

pub fn get_dkim_key_name(email:&mut EmailBody,sender:&String)->Result<String,&'static str>{
    let selector:&str;
    match email.dkim.features.get("s"){
        Some(v)=>{
            selector = v;
        },
        None=>{
            return Err("failed-get-dkim-selector");
        }
    }
    return Ok(format!("{}._domainkey.{}",selector,sender));
}
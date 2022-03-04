

use crate::{EmailBody,ContentEncoding,Part,ContentDecoded};
use base64::decode as Base64Decode;
use quoted_printable::decode as QPDecode;
use quoted_printable::ParseMode as QpParseMode;

pub fn init(email:&mut EmailBody)->Result<(),&'static str>{

    loop{

        if email.parts.len() == 0{
            break;
        }

        let part = email.parts.remove(0);
        
        match parse_part(part,email){
            Ok(_)=>{},
            Err(_e)=>{
                println!("!!! failed-parse_part : {}",_e);
                return Err("failed-parse-part");
            }
        }

    }

    return Ok(());

}

fn parse_part(mut part:Part,email:&mut EmailBody)->Result<(),&'static str>{

    let mut part = part;

    let encoding:ContentEncoding;
    match part.content_features.get("Content-Transfer-Encoding"){
        Some(v)=>{
            let v = v.to_lowercase();
            if v.contains("base64"){encoding = ContentEncoding::Base64;} else 
            if v.contains("quoted-printable"){encoding = ContentEncoding::Qp;} else
            if v.contains("qp"){encoding = ContentEncoding::Qp;} else
            if v.contains("text"){encoding = ContentEncoding::String;} else
            if v.contains("string"){encoding = ContentEncoding::String;} else
            if v.contains("7bit"){encoding = ContentEncoding::String;} else
            if v.contains("8bit"){encoding = ContentEncoding::String;} else
            if v.contains("binary"){encoding = ContentEncoding::UnSupported;} 
            else {encoding = ContentEncoding::String;}
        },
        None=>{
            match email.headers.get("Content-Transfer-Encoding"){
                Some(v)=>{
                    let v = v.to_lowercase();
                    if v.contains("base64"){encoding = ContentEncoding::Base64;} else 
                    if v.contains("quoted-printable"){encoding = ContentEncoding::Qp;} else
                    if v.contains("qp"){encoding = ContentEncoding::Qp;} else
                    if v.contains("text"){encoding = ContentEncoding::String;} else
                    if v.contains("string"){encoding = ContentEncoding::String;} else
                    if v.contains("7bit"){encoding = ContentEncoding::String;} else
                    if v.contains("8bit"){encoding = ContentEncoding::String;} else
                    if v.contains("binary"){encoding = ContentEncoding::UnSupported;} 
                    else {encoding = ContentEncoding::String;}
                },
                None=>{
                    encoding = ContentEncoding::String;
                }
            }
        }
    }

    
    let mut is_string = false;
    if part.content_type.0.len() == 0{
        if email.content_type.0.len() > 0{
            if 
                email.content_type.0.contains("html") || 
                email.content_type.0.contains("text") || 
                email.content_type.0.contains("string") || 
                email.content_type.0.contains("utf-8")
            {
                is_string = true;
            }
        }
    } else {
        if 
            part.content_type.0.contains("html") || 
            part.content_type.0.contains("text") || 
            part.content_type.0.contains("string") || 
            part.content_type.0.contains("utf-8")
        {
            is_string = true;
        }
    }

    // println!("encoding : {:?} is_string : {:?} {:?}",encoding,is_string,part.content_type);

    
    let decoded:ContentDecoded;
    match encoding{
        ContentEncoding::Base64=>{
            while part.data.contains("\r\n"){
                part.data = part.data.replace("\r\n","");
            }
            while part.data.contains("\n"){
                part.data = part.data.replace("\n","");
            }
            // println!("\n\n{:?}\n\n",part.data);
            match Base64Decode(part.data.clone()){
                Ok(v)=>{
                    if is_string{
                        match String::from_utf8(v){
                            Ok(v)=>{
                                // println!("{:?}",v);
                                decoded = ContentDecoded::String(v);
                            },
                            Err(_)=>{
                                return Err("failed-parse_base64_to_string");
                            }
                        }
                    } else {
                        decoded = ContentDecoded::Base64(v);
                    }
                },
                Err(_)=>{
                    return Err("failed-decode-base64");
                }
            }
        },
        ContentEncoding::Qp=>{
            match QPDecode(part.data.clone(),QpParseMode::Strict){
                Ok(v)=>{
                    if is_string{
                        match String::from_utf8(v){
                            Ok(v)=>{
                                decoded = ContentDecoded::String(v);
                            },
                            Err(_)=>{
                                return Err("failed-parse_qp_to_string");
                            }
                        }
                    } else {
                        decoded = ContentDecoded::Qp(v);
                    }
                },
                Err(_)=>{
                    return Err("failed-decode-base64");
                }
            }
        },
        ContentEncoding::String=>{
            decoded = ContentDecoded::String(part.data.clone());
        }
        ContentEncoding::UnSupported=>{
            return Err("unsupported-content-encoding");
        }
    }

    match decoded{
        ContentDecoded::String(v)=>{
            if part.content_type.0.len() == 0{
                if email.content_type.0.contains("html"){
                    part.decoded = ContentDecoded::Html(v);
                } else {
                    part.decoded = ContentDecoded::String(v);
                }
            } else {
                if part.content_type.0.contains("html"){
                    part.decoded = ContentDecoded::Html(v);
                } else {
                    part.decoded = ContentDecoded::String(v);
                }
            }
        },
        _=>{
            part.decoded = decoded;
        }
    }

    part.data = String::new();

    match part.content_features.get("Content-Disposition"){
        Some(v)=>{
            if v.contains("attachment"){
                email.attachments.push(part);
            } else {
                email.body.push(part);
            }
        },
        None=>{
            email.body.push(part);
        }
    }

    return Ok(());

}


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
            Err(_)=>{
                return Err("failed-parse-part");
            }
        }

    }

    return Ok(());

}

fn parse_part(part:Part,email:&mut EmailBody)->Result<(),&'static str>{

    let mut part = part;

    let encoding:ContentEncoding;
    match part.content_features.get("Content-Transfer-Encoding"){
        Some(v)=>{
            let v = v.to_lowercase();
            if v.contains("base64"){encoding = ContentEncoding::Base64;} else 
            if v.contains("quoted-printable"){encoding = ContentEncoding::Qp;} else
            if v.contains("qp"){encoding = ContentEncoding::Qp;} else
            if v.contains("binary"){encoding = ContentEncoding::UnSupported;} else {
                encoding = ContentEncoding::String;
            }
        },
        None=>{
            encoding = ContentEncoding::String;
        }
    }

    match encoding{
        ContentEncoding::Base64=>{
            match Base64Decode(part.data.clone()){
                Ok(v)=>{
                    if part.content_type.0.contains("text"){
                        match String::from_utf8(v){
                            Ok(v)=>{
                                part.decoded = ContentDecoded::String(v);
                            },
                            Err(_)=>{
                                return Err("failed-parse_base64_to_string");
                            }
                        }
                    } else {
                        part.decoded = ContentDecoded::Base64(v);
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
                    if part.content_type.0.contains("text"){
                        match String::from_utf8(v){
                            Ok(v)=>{
                                part.decoded = ContentDecoded::String(v);
                            },
                            Err(_)=>{
                                return Err("failed-parse_qp_to_string");
                            }
                        }
                    } else {
                        part.decoded = ContentDecoded::Qp(v);
                    }
                },
                Err(_)=>{
                    return Err("failed-decode-base64");
                }
            }
        },
        ContentEncoding::String=>{
            part.decoded = ContentDecoded::String(part.data.clone());
        },
        ContentEncoding::UnSupported=>{
            return Err("unsupported-content-encoding");
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
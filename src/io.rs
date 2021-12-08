
use std::io::Read;
use std::fs::File;

pub fn read_string(path:&'static str)->Result<String,&'static str>{

    match read_file(path){
        Ok(d)=>{
            match String::from_utf8(d){
                Ok(v)=>{
                    return Ok(v);
                },
                Err(_)=>{
                    return Err("failed-parse-string");
                }
            }
        },
        Err(_)=>{
            return Err("failed-read_file");
        }
    }

}

pub fn read_file(path:&'static str)->Result<Vec<u8>,&'static str>{

    let mut file:File;
    match File::open(path){
        Ok(v)=>{file = v;},
        Err(_)=>{
            return Err("failed-opne-file");
        }
    }

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer){
        Ok(_)=>{},
        Err(_)=>{
            return Err("failed-read_file");
        }
    }

    return Ok(buffer);

}
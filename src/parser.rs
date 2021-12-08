
use crate::Config;
use std::collections::HashMap;

pub fn parse_only_features(config:&Config,line:&str)->Result<(HashMap<String,String>,Vec<String>,Vec<String>),&'static str>{

    let features_string:&str;
    match config.keyval_regex.captures(line){
        Some(captures)=>{
            match captures.get(2){
                Some(v)=>{features_string = v.as_str();},
                None=>{
                    return Err("failed-get-features_string");
                }
            }
        },
        None=>{
            return Err("invalid_header");
        }
    }

    let features:Vec<&str> = features_string.split(";").collect();
    let mut collect_features:HashMap<String,String> = HashMap::new();
    let mut collect_flags:Vec<String> = vec![];
    let mut collect_feature_order:Vec<String> = vec![];

    for feature in features{
        match config.feature_regex.captures(feature){
            Some(captures)=>{
                match captures.get(1){
                    Some(v)=>{
                        let k = v.as_str().to_string();
                        match captures.get(2){
                            Some(d)=>{
                                let vl = d.as_str().to_string();
                                collect_feature_order.push(k.clone());
                                match collect_features.insert(k,vl){
                                    Some(_)=>{},
                                    None=>{}
                                }
                            },
                            None=>{
                                collect_flags.push(feature.to_string());
                            }
                        }
                    },
                    None=>{
                        collect_flags.push(feature.to_string());
                    }
                }
            },
            None=>{
                collect_flags.push(feature.to_string());
            }
        }
    }

    return Ok((collect_features,collect_flags,collect_feature_order));

}

pub fn parse_content_type(config:&Config,line:&str)->
    Result<(String,HashMap<String,String>,Vec<String>),&'static str>
{

    let features_string:&str;
    match config.keyval_regex.captures(line){
        Some(captures)=>{
            match captures.get(2){
                Some(v)=>{features_string = v.as_str();},
                None=>{
                    return Err("failed-get-features_string");
                }
            }
        },
        None=>{
            return Err("invalid_header");
        }
    }

    let mut features:Vec<&str> = features_string.split(";").collect();
    let value = features.remove(0);
    let mut collect_features:HashMap<String,String> = HashMap::new();
    let mut collect_flags:Vec<String> = vec![];

    for feature in features{
        match config.feature_regex.captures(feature){
            Some(captures)=>{
                match captures.get(1){
                    Some(v)=>{
                        let k = v.as_str().to_string();
                        match captures.get(2){
                            Some(d)=>{
                                let mut vl = d.as_str().trim_end().to_string();
                                let last = vl.pop().unwrap();
                                if last == '"'{
                                    collect_features.insert(k,vl);
                                } else {
                                    vl.push(last);
                                    collect_features.insert(k,vl);
                                }
                            },
                            None=>{
                                collect_flags.push(feature.to_string());
                            }
                        }
                    },
                    None=>{
                        collect_flags.push(feature.to_string());
                    }
                }
            },
            None=>{
                collect_flags.push(feature.to_string());
            }
        }
    }

    return Ok((value.to_string(),collect_features,collect_flags));

}

pub fn parse_keyval(config:&Config,line:&str)->Result<(String,String),&'static str>{

    match config.keyval_regex.captures(line){
        Some(captures)=>{
            let key:String;
            match captures.get(1){
                Some(v)=>{key = v.as_str().trim().to_string();},
                None=>{
                    return Err("failed-get-key");
                }
            }
            let value:String;
            match captures.get(2){
                Some(v)=>{value = v.as_str().trim().to_string();},
                None=>{
                    return Err("failed-get-features_string");
                }
            }
            return Ok((key,value));
        },
        None=>{
            return Err("invalid_header");
        }
    }

}
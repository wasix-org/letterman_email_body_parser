use tokio::sync::RwLock as TokioRwLock;
use std::collections::HashMap;
use regex::Regex;
use crate::part::init as PartParser;
use crate::dkim::init as DkimInit;
use trust_dns_resolver::config::{ResolverConfig,ResolverOpts};
use trust_dns_resolver::{AsyncResolver,TokioConnection,TokioConnectionProvider};
use openssl::pkey::{PKey,Public};
use std::sync::Arc;

#[derive(Debug,Clone)]
pub struct Config{
    pub keys:Arc<TokioRwLock<HashMap<String,PKey<Public>>>>,
    pub boundary_regex:Regex,
    pub keyval_regex:Regex,
    pub feature_regex:Regex,
    pub from_regex:Regex,
    pub resolver:AsyncResolver<TokioConnection,TokioConnectionProvider>
}

impl Config{
    pub fn new()->Result<Config,&'static str>{

        let boundary_regex:Regex;
        match Regex::new(r"--([\w\d]+)([--]*)"){
            Ok(v)=>{boundary_regex = v;},
            Err(_)=>{
                return Err("failed-regex-boundary_regex");
            }
        }

        let keyval_regex:Regex;
        match Regex::new(r"([\w\d-]+)\s*:\s*([\w\d\W]+)"){
            Ok(v)=>{keyval_regex = v;},
            Err(_)=>{
                return Err("failed-regex-keyval_regex");
            }
        }

        let feature_regex:Regex;
        match Regex::new(r#"([\w\d-]+)="*([\w\s\d\D]+)"*"#){
            Ok(v)=>{feature_regex = v;},
            Err(_)=>{
                return Err("failed-regex-feature_regex");
            }
        }

        let from_regex:Regex;
        match Regex::new(r#"([\w\d_=+/*!@#$%^&*()-|]+)@([\w\d.]+)"#){
            Ok(v)=>{from_regex = v;},
            Err(_)=>{
                return Err("failed-regex-from_regex");
            }
        }

        let resolver:AsyncResolver<TokioConnection,TokioConnectionProvider>;
        match AsyncResolver::tokio(ResolverConfig::default(),ResolverOpts::default()){
            Ok(v)=>{resolver = v;},
            Err(_)=>{
                return Err("failed-build-resolver");
            }
        }

        return Ok(Config{
            keys:Arc::new(TokioRwLock::new(HashMap::new())),
            boundary_regex:boundary_regex,
            keyval_regex:keyval_regex,
            feature_regex:feature_regex,
            from_regex:from_regex,
            resolver:resolver
        });
    }
}

#[derive(Debug,Clone)]
pub struct Dkim{
    pub features:HashMap<String,String>,
    pub order:Vec<String>
}

impl Dkim{
    pub fn init()->Dkim{
        Dkim{
            features:HashMap::new(),
            order:Vec::new()
        }
    }
    pub fn overtake(&mut self,features:HashMap<String,String>,order:Vec<String>){
        let mut order = order;
        self.features = features;
        self.order.append(&mut order);
    }
}

#[derive(Debug,Clone)]
pub enum ContentEncoding{
    Base64,Qp,String,UnSupported
}

#[derive(Debug,Clone)]
pub enum ContentDecoded{
    Base64(Vec<u8>),Qp(Vec<u8>),String(String),Html(String),None
}

#[derive(Debug,Clone)]
pub struct Part{
    pub content_type:(String,HashMap<String,String>,Vec<String>),
    pub content_features:HashMap<String,String>,
    pub data:String,
    pub decoded:ContentDecoded
}

impl Part{
    pub fn new()->Part{
        Part{
            content_type:(
                String::new(),
                HashMap::new(),
                Vec::new()
            ),
            content_features:HashMap::new(),
            data:String::new(),
            decoded:ContentDecoded::None
        }
    }
    pub fn reset(&mut self){
        self.content_type = (
            String::new(),
            HashMap::new(),
            Vec::new()
        );
        self.content_features = HashMap::new();
        self.data = String::new();
        self.decoded = ContentDecoded::None;
    }
}

#[derive(Debug,Clone)]
pub struct PartHandler{
    finished:Vec<Part>,
    active:Part
}

impl PartHandler{
    pub fn content_type(&mut self,v:(String,HashMap<String,String>,Vec<String>)){self.active.content_type = v;}
    pub fn content_feature(&mut self,key:String,value:String){
        self.active.content_features.insert(key,value);
    }
    pub fn data(&mut self,v:String){
        if self.active.data.len() == 0{
            self.active.data.push_str(&v);
        } else {
            self.active.data.push_str("\n");
            self.active.data.push_str(&v);
        }
        // self.active.data.push_str(&v);
    }
    pub fn new()->PartHandler{
        PartHandler{
            finished:Vec::new(),
            active:Part::new()
        }
    }
    pub fn flush(&mut self){
        if self.active.data.len() > 0 {
            self.finished.push(self.active.clone());
        }
        self.active.reset();
    }
}

#[derive(Debug,Clone)]
pub struct EmailBody{
    pub dkim_found:bool,
    pub dkim:Dkim,
    pub headers:HashMap<String,String>,
    pub parts:Vec<Part>,
    pub body:Vec<Part>,
    pub attachments:Vec<Part>,
    pub content_type:(String,HashMap<String,String>,Vec<String>),
}

impl EmailBody{
    pub fn new()->EmailBody{
        EmailBody{
            dkim_found:false,
            dkim:Dkim::init(),
            headers:HashMap::new(),
            parts:Vec::new(),
            body:Vec::new(),
            attachments:Vec::new(),
            content_type:(
                String::new(),
                HashMap::new(),
                Vec::new()
            ),
        }
    }
    pub fn header(&mut self,key:String,value:String){
        self.headers.insert(key.to_lowercase(),value);
    }
    pub fn dkim(&mut self,value:Dkim){
        self.dkim_found = true;
        self.dkim = value;
    }
    pub fn parts(&mut self,handler:PartHandler)->Result<(),&'static str>{
        let mut handler = handler;
        handler.flush();
        self.parts = handler.finished;
        match PartParser(self){
            Ok(_)=>{
                return Ok(());
            },
            Err(_e)=>{
                println!("!!! failed-parse_parts {:?}",_e);
                return Err("failed-parse_parts");
            }
        }
    }
    pub async fn validate(&mut self,config:&Config)->Result<(),&'static str>{
        match DkimInit(self,config).await{
            Ok(_)=>{
                return Ok(());
            },
            Err(_e)=>{
                println!("failed-dkim-validate : {:?}",_e);
                return Err("failed-dkim-validate");
            }
        }
    }
}
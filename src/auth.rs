use std::{ffi::CString, io};

use pam::Converse;

pub struct DoasAuthenticator {
    pub username: String,
}

impl DoasAuthenticator {
    pub fn new(username: String) -> DoasAuthenticator {
        DoasAuthenticator { username }
    }
}

impl Converse for DoasAuthenticator {
    fn prompt_echo(&mut self, msg: &std::ffi::CStr) -> std::result::Result<std::ffi::CString, ()> {
        println!("owo {:#?}", msg);
        // print!("{}", msg.to_str().unwrap());

        // let mut input = String::new();
        // io::stdin()
        //   .read_line(&mut input)
        //   .unwrap();

        //   Ok(CString::new(input).unwrap())

        Ok(CString::new("chan").unwrap())
    }

    fn prompt_blind(&mut self, msg: &std::ffi::CStr) -> std::result::Result<std::ffi::CString, ()> {
        println!("uwu {:#?}", msg);
        let str = rpassword::prompt_password(msg.to_str().unwrap()).unwrap();
        Ok(CString::new(str).unwrap())
    }

    fn info(&mut self, msg: &std::ffi::CStr) {
        println!("{}", msg.to_str().unwrap());
    }

    fn error(&mut self, msg: &std::ffi::CStr) {
        eprintln!("{}", msg.to_str().unwrap());
    }

    fn username(&self) -> &str {
        self.username.as_str()
    }
}

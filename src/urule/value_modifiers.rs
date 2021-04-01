

pub mod endings {
    use regex::Regex;
    pub fn ends_with(field_value : &str, ending : &str) -> bool {
        field_value.ends_with(ending)
    }
    pub fn base64_offset_contains(b64 : &str, value : &str) -> bool {
        //TODO: improve
        b64.contains(value)
    }
    pub fn regex(field_value : &str, regex : &str) -> bool {
        // Cannot fail here... must be checked before
        let re: Regex = match Regex::new(regex) {
            Ok(re) => re,
            Err(e) => return false
        };
        re.is_match(field_value)
    }
}

pub mod pipes {

    pub fn to_base64(value : &str) -> String {
        base64::encode(value)
    }
}
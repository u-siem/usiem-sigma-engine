use super::super::rule::{SigmaRule, SigmaRuleDetection};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref RE_AGR: Regex = Regex::new("\\s(count|avg|max|min|sum)(?:\\(([^\\)]*)\\))?\\s+by\\s+([^\\s]+)").unwrap();
}
#[derive(Debug, Clone)]
pub enum SigmaAgrupation {
    // Count agruped by a parameter
    Count(String),
    //Count distincts parameters agruped by
    CountParamBy(String,String),
    /// Max value of a parameter in X time
    Max(String,String),
    /// The minimum value of a parameter in X time
    Min(String,String),
    /// Average number of a parameter in X time
    Avg(String,String),
    //The sum is a bit tricky, must be implemented correctly in REDIS
    Sum(String,String),
    /// No agrupation
    None
}


pub fn agrupation_from_rule(rule : &SigmaRule) -> Result<SigmaAgrupation,&'static str>{
    let detection = &rule.detection;
    let condition = detection.get("condition");
    let condition = match condition {
        None => {return Err("No condition field found")},
        Some(condition) => {
            match condition {
                SigmaRuleDetection::Condition(condition) => condition,
                _ => {return Err("Invalid condition format, not a STRING")}
            }
        }
    };

    if !condition.contains(" by ") {
        return Ok(SigmaAgrupation::None)
    }

    // Check which type of agrupation
    
    let caps = RE_AGR.captures(condition);
    match caps {
        Some(cap) => {
            let fun_name = match cap.get(1) {
                Some(fun_name) => fun_name.as_str(),
                None => return Err("Invalid function name")
            };
            let second_par = match cap.get(2) {
                Some(second_par) => second_par.as_str(),
                None => return Err("Invalid parameter")
            };
            if cap.len() == 4 {
                let agrupation_name = match cap.get(3) {
                    Some(second_par) => second_par.as_str(),
                    None => return Err("Third parameter for count invalid")
                };
                if second_par == ""{
                    return Ok(SigmaAgrupation::Count(String::from(agrupation_name)))
                }
                return match fun_name {
                    "count" =>  Ok(SigmaAgrupation::CountParamBy(String::from(second_par), String::from(agrupation_name))),
                    "max" => Ok(SigmaAgrupation::Max(String::from(second_par), String::from(agrupation_name))),
                    "min" => Ok(SigmaAgrupation::Min(String::from(second_par), String::from(agrupation_name))),
                    "avg" => Ok(SigmaAgrupation::Avg(String::from(second_par), String::from(agrupation_name))),
                    "sum" => Ok(SigmaAgrupation::Sum(String::from(second_par), String::from(agrupation_name))),
                    _ => Err("Invalid agrupation name")
                }
            }
            
            return match fun_name {
                "count" => Ok(SigmaAgrupation::Count(String::from(second_par))),
                _ => Err("Invalid agrupation name")
            }
        },
        None => Ok(SigmaAgrupation::None)
    }
}


#[cfg(test)]
mod tests {
    use super::{agrupation_from_rule, SigmaAgrupation, SigmaRuleDetection, SigmaRule};
    #[test]
    fn test_agrupation_count(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | count(username) by password"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::CountParamBy(param, agr) => {
                assert_eq!(param, "username");
                assert_eq!(agr, "password");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
    #[test]
    fn test_agrupation_count_empty(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | count() by password"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::Count(agr) => {
                assert_eq!(agr, "password");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
    #[test]
    fn test_agrupation_max(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | max(bytes) by username"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::Max(param,agr) => {
                assert_eq!(param, "bytes");
                assert_eq!(agr, "username");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
    #[test]
    fn test_agrupation_sum(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | sum(bytes) by username"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::Sum(param,agr) => {
                assert_eq!(param, "bytes");
                assert_eq!(agr, "username");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
    #[test]
    fn test_agrupation_avg(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | avg(bytes) by username"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::Avg(param,agr) => {
                assert_eq!(param, "bytes");
                assert_eq!(agr, "username");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
    #[test]
    fn test_agrupation_min(){
        let mut rule = SigmaRule::new(String::from("Test1"), String::from("Test1"), String::from("Test1"), String::from("testing"));
        let condition = SigmaRuleDetection::Condition(String::from("algo:true | min(bytes) by username"));
        rule.detection.insert(String::from("condition"), condition);

        let check = agrupation_from_rule(&rule).unwrap();
        match &check {
            SigmaAgrupation::Min(param,agr) => {
                assert_eq!(param, "bytes");
                assert_eq!(agr, "username");
            },
            _ => {
                panic!("Invalid agrupation")
            }
        };
    }
}
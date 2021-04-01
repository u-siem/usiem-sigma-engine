use super::rule::{SigmaRule, SigmaRuleDetection, SigmaValues};
use std::sync::Arc;
mod agrupation;
use agrupation::{agrupation_from_rule, SigmaAgrupation};
use std::collections::BTreeMap;
use usiem::events::SiemLog;
use usiem::events::field::{SiemField, SiemIp};
mod value_modifiers;
mod matches;

use matches::*;

pub struct SiemSigmaRule {
    rule: Arc<SigmaRule>,
    agrupation: SigmaAgrupation,
    conditions: BTreeMap<String, Option<bool>>,
}
impl Clone for SiemSigmaRule {
    // Clone before using with a log
    fn clone(&self) -> Self {
        return SiemSigmaRule {
            rule : self.rule.clone(),
            agrupation : self.agrupation().clone(),
            conditions : BTreeMap::new()
        }
    }
}

impl SiemSigmaRule {
    pub fn new(rule: Arc<SigmaRule>) -> Result<SiemSigmaRule, &'static str> {
        // Check rule first befor creating the condition Tree path
        let agrupation = match agrupation_from_rule(&rule) {
            Ok(agrupation) => agrupation,
            Err(_) => return Err("Invalid agrupation"),
        };
        //Extract conditions
        return Ok(SiemSigmaRule {
            rule,
            agrupation,
            conditions: BTreeMap::new(),
        });
    }

    pub fn category(&self) -> Option<&str> {
        let cat = &(*self.rule).logsource.category;
        if cat == "" {
            return None;
        } else {
            return Some(cat);
        }
    }
    pub fn product(&self) -> Option<&str> {
        let cat = &(*self.rule).logsource.product;
        if cat == "" {
            return None;
        } else {
            return Some(cat);
        }
    }
    pub fn service(&self) -> Option<&str> {
        let cat = &(*self.rule).logsource.service;
        if cat == "" {
            return None;
        } else {
            return Some(cat);
        }
    }
    pub fn agrupation(&self) -> &SigmaAgrupation {
        &self.agrupation
    }

    pub fn match_rule(&mut self, _log: &SiemLog) -> bool {
        //TODO: match whole rule
        false
    }
    fn match_condition(&mut self, condition: &str, log: &SiemLog) -> bool {
        //TODO: Use a proxy to cache modified log fields
        let result = match self.conditions.get(condition) {
            Some(val) => match val {
                Some(val) => return *val,
                None => {
                    let condition = match self.rule.detection.get(condition) {
                        Some(v) => v,
                        None => return false,
                    };
                    match_rule_condition(condition, log)
                }
            },
            None => return false,
        };
        // Cache value
        self.conditions.insert(condition.to_string(), Some(result));
        return result;
    }
}

fn match_rule_condition(condition: &SigmaRuleDetection, log: &SiemLog) -> bool {
    match condition {
        SigmaRuleDetection::Keywords(keywords) => {
            for keyword in keywords {
                if log.message().contains(keyword) {
                    return true;
                }
            }
            return false;
        }
        SigmaRuleDetection::Selection(map) => {
            for (key, val) in map.iter() {
                if !matches_selection(key, val, log) {
                    return false;
                }
            }
            return true;
        }
        SigmaRuleDetection::Condition(_cond) => {
            //Must not happen
            return true;
        }
    }
}

fn matches_selection(key: &str, value: &SigmaValues, log: &SiemLog) -> bool {
    let mut splited = key.split("|");
    let field_name = splited.next().unwrap_or("message");
    let log_field = match log.field(field_name) {
        Some(field) => field,
        None => match value {
            SigmaValues::Text(val) => match val {
                Some(_) => return false,
                None => return true,
            },
            _ => return false,
        },
    };

    let modifiers: Vec<&str> = splited.collect();

    let mut modified_value = log_field.to_string();
    if modifiers.len() > 1 {
        for modifier in modifiers {
            match modifier {
                "base64" => {
                    modified_value = value_modifiers::pipes::to_base64(&modified_value[..]);
                }
                _ => {}
            }
        }
    }
    if key.ends_with("|base64offset|contains") {
        match value {
            SigmaValues::Text(v) => match v {
                Some(v) => {
                    return value_modifiers::endings::base64_offset_contains(
                        &modified_value[..],
                        v,
                    );
                }
                _ => return false,
            },
            _ => return false,
        }
    } else if key.ends_with("|contains") {
        match value {
            SigmaValues::Text(val) => match val {
                Some(val) => return (&modified_value[..]).contains(val),
                None => return false,
            },
            _ => return false,
        }
    }
    match_field_value(value, log_field, &FieldComparision::Equals)
}



fn match_field_value(value : &SigmaValues, field: &SiemField, comparision: &FieldComparision) -> bool {
    match comparision {
        FieldComparision::Contains => {
            return match_contains(value, field)
        },
        FieldComparision::ContainsAll => {
            return match_contains_all(value, field)
        },
        FieldComparision::Equals => {
            return match_equals(value, field)
        },
        FieldComparision::Bigger => {
            return match_bigger(value, field)
        },
        FieldComparision::Lesser => {
            return match_lesser(value, field)
        },
        FieldComparision::BoE => {
            return match_bigger_equals(value, field)
        },
        FieldComparision::LoE => {
            return match_lesser_equals(value, field)
        },
        FieldComparision::All => {
            return match_equals_all(value, field)
        }
    }
}

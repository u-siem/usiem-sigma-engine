use super::rule::{SigmaRule};
use std::sync::Arc;
mod agrupation;
use agrupation::{agrupation_from_rule, SigmaAgrupation};

pub struct SiemSigmaRule {
    rule: Arc<SigmaRule>,
    agrupation: SigmaAgrupation,
}

impl SiemSigmaRule {
    pub fn new(rule: Arc<SigmaRule>) -> Result<SiemSigmaRule, &'static str> {
        // Check rule first befor creating the condition Tree path
        let agrupation = match agrupation_from_rule(&rule) {
            Ok(agrupation) => agrupation,
            Err(_) => return Err("Invalid agrupation")
        };
        return Ok(SiemSigmaRule { rule, agrupation });
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
}

use usiem::events::field::{SiemField, SiemIp};
use super::SigmaValues;

pub enum FieldComparision {
    Contains,
    ContainsAll,
    All,
    Bigger,
    Lesser,
    Equals,
    BoE,
    LoE,
}

pub fn match_contains_all(value : &SigmaValues, field: &SiemField) -> bool {
    match (value, field) {
        (SigmaValues::Array(list), SiemField::Text(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::Domain(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::User(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::AssetID(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        _ => return false
    }
}

pub fn match_contains(value : &SigmaValues, field: &SiemField) -> bool {
    match (value, field) {
        (SigmaValues::Text(val_text), SiemField::Text(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt.contains(val_text)
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::Domain(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt.contains(val_text)
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::User(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt.contains(val_text)
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::AssetID(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt.contains(val_text)
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Array(list), SiemField::Text(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::Domain(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::User(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::AssetID(_f)) => {
            for element in list {
                let mtch = match_contains(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        _ => return false
    }
}

pub fn match_equals(value : &SigmaValues, field: &SiemField) -> bool {
    match (value, field) {
        (SigmaValues::Text(val_text), SiemField::Text(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::Domain(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::User(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::AssetID(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Array(list), SiemField::Text(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::Domain(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::User(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Array(list), SiemField::AssetID(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        (SigmaValues::Int(numb),SiemField::U32(numb2)) => return (*numb as u32) == *numb2,
        (SigmaValues::Int(numb),SiemField::I64(numb2)) => return (*numb as i64) == *numb2,
        (SigmaValues::Int(numb),SiemField::U64(numb2)) => return (*numb as u64) == *numb2,
        (SigmaValues::Int(numb),SiemField::F64(numb2)) => return (*numb as f64) == *numb2,
        (SigmaValues::Int(numb),SiemField::IP(ip)) => {
            match ip {
                SiemIp::V4(ip) => return *ip == (*numb as u32),
                SiemIp::V6(ip) => return *ip == (*numb as u128),
            }
        }
        _ => return false
    }
}
pub fn match_equals_all(value : &SigmaValues, field: &SiemField) -> bool {
    match (value, field) {
        (SigmaValues::Text(val_text), SiemField::Text(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::Domain(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::User(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Text(val_text), SiemField::AssetID(field_txt)) => {
            match val_text {
                Some(val_text) =>  {
                    return field_txt == val_text
                },
                None => return field_txt.is_empty()
            }
        },
        (SigmaValues::Array(list), SiemField::Text(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::Domain(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::User(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Array(list), SiemField::AssetID(_f)) => {
            for element in list {
                let mtch = match_equals(element, field);
                if !mtch {
                    return false
                }
            }
            return true
        },
        (SigmaValues::Int(numb),SiemField::U32(numb2)) => return (*numb as u32) == *numb2,
        (SigmaValues::Int(numb),SiemField::I64(numb2)) => return (*numb as i64) == *numb2,
        (SigmaValues::Int(numb),SiemField::U64(numb2)) => return (*numb as u64) == *numb2,
        (SigmaValues::Int(numb),SiemField::F64(numb2)) => return (*numb as f64) == *numb2,
        (SigmaValues::Int(numb),SiemField::IP(ip)) => {
            match ip {
                SiemIp::V4(ip) => return *ip == (*numb as u32),
                SiemIp::V6(ip) => return *ip == (*numb as u128),
            }
        }
        _ => return false
    }
}

pub fn match_bigger(value : &SigmaValues, field: &SiemField) -> bool {
    match value {
        SigmaValues::Array(list) => {
            for element in list {
                let mtch = match_bigger(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        SigmaValues::Int(numb) => {
            match field {
                SiemField::U32(numb2) => return (*numb as u32) > *numb2,
                SiemField::I64(numb2) => return (*numb as i64) > *numb2,
                SiemField::U64(numb2) => return (*numb as u64) > *numb2,
                SiemField::F64(numb2) => return (*numb as f64) > *numb2,
                SiemField::IP(ip) => {
                    match ip {
                        SiemIp::V4(ip) => return *ip > (*numb as u32),
                        SiemIp::V6(ip) => return *ip > (*numb as u128),
                    }
                }
                _ => return false
            }
        },
        _ => return false
    }
}
pub fn match_lesser(value : &SigmaValues, field: &SiemField) -> bool {
    match value {
        SigmaValues::Array(list) => {
            for element in list {
                let mtch = match_lesser(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        SigmaValues::Int(numb) => {
            match field {
                SiemField::U32(numb2) => return (*numb as u32) < *numb2,
                SiemField::I64(numb2) => return (*numb as i64) < *numb2,
                SiemField::U64(numb2) => return (*numb as u64) < *numb2,
                SiemField::F64(numb2) => return (*numb as f64) < *numb2,
                SiemField::IP(ip) => {
                    match ip {
                        SiemIp::V4(ip) => return *ip < (*numb as u32),
                        SiemIp::V6(ip) => return *ip < (*numb as u128),
                    }
                }
                _ => return false
            }
        },
        _ => return false
    }
}
pub fn match_bigger_equals(value : &SigmaValues, field: &SiemField) -> bool {
    match value {
        SigmaValues::Array(list) => {
            for element in list {
                let mtch = match_bigger_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        SigmaValues::Int(numb) => {
            match field {
                SiemField::U32(numb2) => return (*numb as u32) >= *numb2,
                SiemField::I64(numb2) => return (*numb as i64) >= *numb2,
                SiemField::U64(numb2) => return (*numb as u64) >= *numb2,
                SiemField::F64(numb2) => return (*numb as f64) >= *numb2,
                SiemField::IP(ip) => {
                    match ip {
                        SiemIp::V4(ip) => return *ip >= (*numb as u32),
                        SiemIp::V6(ip) => return *ip >= (*numb as u128),
                    }
                }
                _ => return false
            }
        },
        _ => return false
    }
}
pub fn match_lesser_equals(value : &SigmaValues, field: &SiemField) -> bool {
    match value {
        SigmaValues::Array(list) => {
            for element in list {
                let mtch = match_lesser_equals(element, field);
                if mtch {
                    return true
                }
            }
            return false
        },
        SigmaValues::Int(numb) => {
            match field {
                SiemField::U32(numb2) => return (*numb as u32) <= *numb2,
                SiemField::I64(numb2) => return (*numb as i64) <= *numb2,
                SiemField::U64(numb2) => return (*numb as u64) <= *numb2,
                SiemField::F64(numb2) => return (*numb as f64) <= *numb2,
                SiemField::IP(ip) => {
                    match ip {
                        SiemIp::V4(ip) => return *ip <= (*numb as u32),
                        SiemIp::V6(ip) => return *ip <= (*numb as u128),
                    }
                }
                _ => return false
            }
        },
        _ => return false
    }
}


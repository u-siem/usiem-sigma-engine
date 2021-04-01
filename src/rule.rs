use std::collections::BTreeMap;
use serde::{ Serialize, Deserialize};

#[derive(Serialize, Debug, Deserialize)]
pub struct SigmaRule {
    /// A brief title for the rule that should contain what the rules is supposed to detect (max. 256 characters)
    pub title: String,
    /// Sigma rules should be identified by a globally unique identifier in the id attribute. For this purpose random generated UUIDs (version 4) are recommended but not mandatory. An example for this is:
    /// ```yml
    /// title: Test rule
    /// id: 929a690e-bef0-4204-a928-ef5e620d6fcc
    /// ```
    /// 
    /// Rule identifiers can and should change for the following reasons:
    /// - Major changes in the rule. E.g. a different rule logic.
    /// - Derivation of a new rule from an existing or refinement of a rule in a way that both are kept active.
    /// - Merge of rules.
    /// 
    /// To being able to keep track on relationships between detections, Sigma rules may also contain references to related rule identifiers in the related attribute. This allows to define common relationships between detections as follows:
    /// 
    /// ```yml
    /// related:
    /// - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
    ///   type: derived
    /// - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
    ///   type: obsoletes
    /// ```
    ///Currently the following types are defined:
    /// - derived: Rule was derived from the referred rule or rules, which may remain active.
    /// - obsoletes: Rule obsoletes the referred rule or rules, which aren't used anymore.
    /// - merged: Rule was merged from the referred rules. The rules may be still existing and in use.
    /// - renamed: The rule had previously the referred identifier or identifiers but was renamed for any other reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not expected that a rule with this id exists anymore.
    ///
    #[serde(default = "default_id")]
    pub id: String,
    /// A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)
    #[serde(default = "default_string")]
    pub description: String,
    /// References to the source that the rule was derived from. These could be blog articles, technical papers, presentations or even tweets.
    #[serde(default = "default_vector")]
    pub references: Vec<String>,
    /// Declares the status of the rule:
    /// - stable: the rule is considered as stable and may be used in production systems or dashboards.
    /// - test: an almost stable rule that possibly could require some fine tuning.
    /// - experimental: an experimental rule that could lead to false results or be noisy, but could also identify interesting events.
    #[serde(default = "default_status")]
    pub status: String,
    /// License of the rule according the SPDX ID specification: https://spdx.org/ids
    #[serde(default = "default_string")]
    pub license: String,
    /// Creator of the rule.
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default = "default_date")]
    pub date: String,
    ///This section describes the log data on which the detection is meant to be applied to. It describes the log source, the platform, the application and the type that is required in detection.
    ///
    ///It consists of three attributes that are evaluated automatically by the converters and an arbitrary number of optional elements. We recommend using a "definition" value in cases in which further explication is necessary.
    ///
    /// - category - examples: firewall, web, antivirus
    /// - product - examples: windows, apache, check point fw1
    /// - service - examples: sshd, applocker
    ///
    ///The "category" value is used to select all log files written by a certain group of products, like firewalls or web server logs. The automatic conversion will use the keyword as a selector for multiple indices.
    ///
    ///The "product" value is used to select all log outputs of a certain product, e.g. all Windows Eventlog types including "Security", "System", "Application" and the new log types like "AppLocker" and "Windows Defender".
    ///
    ///Use the "service" value to select only a subset of a product's logs, like the "sshd" on Linux or the "Security" Eventlog on Windows systems.
    ///
    ///The "definition" can be used to describe the log source, including some information on the log verbosity level or configurations that have to be applied. It is not automatically evaluated by the converters but gives useful advice to readers on how to configure the source to provide the necessary events used in the detection.
    ///
    ///You can use the values of 'category, 'product' and 'service' to point the converters to a certain index. You could define in the configuration files that the category 'firewall' converts to ( index=fw1* OR index=asa* ) during Splunk search conversion or the product 'windows' converts to "_index":"logstash-windows*" in ElasticSearch queries.
    pub logsource: SigmaRuleLogSource,
    /// A set of search-identifiers that represent searches on log data
    pub detection: BTreeMap<String, SigmaRuleDetection>,
    /// A list of log fields that could be interesting in further analysis of the event and should be displayed to the analyst.
    #[serde(default = "default_vector")]
    pub fields: Vec<String>,
    #[serde(default = "default_vector")]
    pub falsepositives: Vec<String>,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_vector")]
    pub tags: Vec<String>,
    #[serde(default = "default_string_tree")]
    pub parameters : BTreeMap<String,String>
}

impl SigmaRule {
    pub fn new(title : String,description : String, author : String, status : String) -> SigmaRule {
        let mut detection = BTreeMap::new();
        detection.insert(String::from("condition"), SigmaRuleDetection::Condition(String::from("")));
        return SigmaRule{
            title,
            id : String::from(""),
            description,
            references : Vec::new(),
            license : String::new(),
            status,
            author,
            date : String::from(""),
            logsource : SigmaRuleLogSource {
                category : String::from(""),
                product : String::from(""),
                service : String::from(""),
                definition : String::from("")
            },
            detection,
            fields : Vec::new(),
            falsepositives : Vec::new(),
            level : String::from(""),
            tags : Vec::new(),
            parameters : BTreeMap::new()
        }
    }
}
#[derive(Serialize, Debug, Deserialize)]
pub struct SigmaRuleLogSource {
    #[serde(default = "default_string")]
    pub category: String,
    #[serde(default = "default_string")]
    pub product: String,
    #[serde(default = "default_string")]
    pub service: String,
    #[serde(default = "default_string")]
    pub definition: String,
}

fn default_string() -> String {
    return String::from("USIEM")
}
fn default_id() -> String {
    return uuid::Uuid::new_v4().to_string();
}
fn default_vector() -> Vec<String> {
     return Vec::new()
}
fn default_string_tree() -> BTreeMap<String,String> {
    return BTreeMap::new()
}
fn default_level() -> String{
    return String::from("info")
}
fn default_status() -> String{
    return String::from("experimental")
}
fn default_author() -> String{
    return String::from("usiem")
}
fn default_date() -> String {
    return chrono::Utc::now().to_rfc3339();
}

#[derive(Serialize, Debug, Deserialize)]
#[serde(untagged)]
pub enum SigmaRuleDetection {
    /// The condition is the most complex part of the specification and will be subject to change over time and arising requirements.
    Condition(String),
    /// The lists contain strings that are applied to the full log message and are linked with a logical 'OR'.
    Keywords(Vec<String>),
    /// Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value a string or integer value. Lists of maps are joined with a logical 'OR'. All elements of a map are joined with a logical 'AND'.
    Selection(BTreeMap<String, SigmaValues>)
}

#[derive(Serialize, Debug, Deserialize)]
#[serde(untagged)]
pub enum SigmaValues {
    Text(Option<String>),
    Int(i32),
    Array(Vec<SigmaValues>),
}



#[cfg(test)]
mod tests {
    use super::{SigmaRule, SigmaRuleDetection, SigmaValues};
    use serde_json;
    use std::collections::BTreeMap;
    #[test]
    fn test_commander_listener(){
       let mut rule = SigmaRule::new(String::from("Regla numero 1"), String::from("Regla de test"),String::from("Samuel"),String::from("testing"));
       rule.detection.insert("condition".to_owned(), SigmaRuleDetection::Condition(String::from("selection")));

       let mut conditions1 = BTreeMap::new();
       conditions1.insert("EventID".to_owned(), SigmaValues::Int(4656));
       conditions1.insert("EventLog".to_owned(), SigmaValues::Text(Some("Security".to_owned())));
       conditions1.insert("ProcessName".to_owned(), SigmaValues::Text(Some("C:\\Windows\\System32\\lsass.exe".to_owned())));
       conditions1.insert("AccessMask".to_owned(), SigmaValues::Text(Some("0x705".to_owned())));
       conditions1.insert("ObjectType".to_owned(), SigmaValues::Text(Some("SAM_DOMAIN".to_owned())));
        rule.detection.insert("selection".to_owned(), SigmaRuleDetection::Selection(conditions1));
       println!("{}",serde_json::to_string(&rule).expect("No serializa"));
    }


    #[test]
    fn sysmon_rule(){
        let yml_rule = "title: Password Dumper Remote Thread in LSASS \n
id: f239b326-2f41-4d6b-9dfa-c846a60ef505 \n
description: Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage. The process in field Process is the malicious program. A single execution can lead to hundreds of events. \n
references: \n
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/WCE.htm \n
status: stable \n
author: Thomas Patzke \n
date: 2017/02/19 \n
logsource: \n
    product: windows \n
    service: sysmon \n
detection: \n
    selection: \n
        EventID: 8 \n
        TargetImage: 'C:\\Windows\\System32\\lsass.exe' \n
        StartModule: '' \n
    condition: selection \n
tags: \n
    - attack.credential_access \n
    - attack.t1003          # an old one \n
    - attack.s0005 \n
    - attack.t1003.001 \n
falsepositives: \n
    - unknown \n
level: high";
        let sigma_rule : SigmaRule = serde_yaml::from_str(yml_rule).expect("Cannot read");
        let _rule = serde_json::to_string(&sigma_rule).expect("serializing problem");
    }

    #[test]
    fn complex_sysmon_rule(){
        let yml_rule = "title: Executable in ADS\n
id: b69888d4-380c-45ce-9cf9-d9ce46e67821\n
status: experimental\n
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)\n
references:\n
    - https://twitter.com/0xrawsec/status/1002478725605273600?s=21\n
tags:\n
    - attack.defense_evasion\n
    - attack.t1027          # an old one\n
    - attack.s0139\n
    - attack.t1564.004\n
author: Florian Roth, @0xrawsec\n
date: 2018/06/03\n
modified: 2020/08/26\n
logsource:\n
    product: windows\n
    service: sysmon\n
    definition: 'Requirements: Sysmon config with Imphash logging activated'\n
detection:\n
    selection:\n
        EventID: 15\n
    filter1:\n
        Imphash: '00000000000000000000000000000000'\n
    filter2:\n
        Imphash: null\n
    condition: selection and not 1 of filter*\n
fields:\n
    - TargetFilename\n
    - Image\n
falsepositives:\n
    - unknown\n
level: critical\n";
        let sigma_rule : SigmaRule = serde_yaml::from_str(yml_rule).expect("Cannot read");
        let _rule = serde_json::to_string(&sigma_rule).expect("serializing problem");
    }
}
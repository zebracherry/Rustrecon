
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug,Clone,PartialEq,Serialize,Deserialize)]
pub enum TargetType { Linux, Windows, AD, Unknown }
impl TargetType {
    pub fn label(&self) -> &str {
        match self {
            TargetType::Linux   => "Linux",
            TargetType::Windows => "Windows",
            TargetType::AD      => "Active Directory",
            TargetType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Port {
    pub number:  u16,
    pub proto:   String,
    pub service: String,
    pub version: Option<String>,
}

#[derive(Debug,Clone,PartialEq,Serialize,Deserialize)]
pub enum FindingSeverity { Critical, High, Medium, Low, Info }
impl FindingSeverity {
    pub fn label(&self) -> &str {
        match self {
            FindingSeverity::Critical => "CRITICAL",
            FindingSeverity::High     => "HIGH",
            FindingSeverity::Medium   => "MEDIUM",
            FindingSeverity::Low      => "LOW",
            FindingSeverity::Info     => "INFO",
        }
    }
    pub fn colour(&self) -> &str {
        match self {
            FindingSeverity::Critical => "#e74c3c",
            FindingSeverity::High     => "#e67e22",
            FindingSeverity::Medium   => "#f1c40f",
            FindingSeverity::Low      => "#2ecc71",
            FindingSeverity::Info     => "#3498db",
        }
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Finding {
    pub severity:    FindingSeverity,
    pub category:    String,
    pub title:       String,
    pub detail:      String,
    pub tool:        String,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ScanResult {
    pub target:      String,
    pub target_type: TargetType,
    pub ports:       Vec<Port>,
    pub findings:    Vec<Finding>,
    pub cmd_log:     Vec<String>,
    pub manual_cmds: Vec<String>,
    pub raw:         HashMap<String,String>,
    pub started:     String,
    pub finished:    Option<String>,
}
impl ScanResult {
    pub fn new(target: &str) -> Self {
        Self {
            target:      target.to_string(),
            target_type: TargetType::Unknown,
            ports:       Vec::new(),
            findings:    Vec::new(),
            cmd_log:     Vec::new(),
            manual_cmds: Vec::new(),
            raw:         HashMap::new(),
            started:     chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            finished:    None,
        }
    }
    pub fn finalize(&mut self) {
        self.finished = Some(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
    }
}

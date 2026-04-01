use wasm_bindgen::prelude::*;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionMode {
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "workspace-write")]
    WorkspaceWrite,
    #[serde(rename = "danger-full-access")]
    DangerFullAccess,
    #[serde(rename = "prompt")]
    Prompt,
    #[serde(rename = "allow")]
    Allow,
}

impl PermissionMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read-only" => Some(Self::ReadOnly),
            "workspace-write" => Some(Self::WorkspaceWrite),
            "danger-full-access" => Some(Self::DangerFullAccess),
            "prompt" => Some(Self::Prompt),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
            Self::Prompt => "prompt",
            Self::Allow => "allow",
        }
    }
}

pub struct PermissionPolicy {
    active_mode: PermissionMode,
    tool_requirements: BTreeMap<String, PermissionMode>,
}

impl PermissionPolicy {
    pub fn new(active_mode: PermissionMode) -> Self {
        Self {
            active_mode,
            tool_requirements: BTreeMap::new(),
        }
    }

    pub fn with_tool_requirement(
        mut self,
        tool_name: String,
        required_mode: PermissionMode,
    ) -> Self {
        self.tool_requirements.insert(tool_name, required_mode);
        self
    }

    pub fn required_mode_for(&self, tool_name: &str) -> PermissionMode {
        self.tool_requirements
            .get(tool_name)
            .copied()
            .unwrap_or(PermissionMode::DangerFullAccess)
    }

    pub fn authorize(&self, tool_name: &str) -> bool {
        let current_mode = self.active_mode;
        let required_mode = self.required_mode_for(tool_name);
        
        if current_mode == PermissionMode::Allow || current_mode >= required_mode {
            return true;
        }
        
        false
    }
}

#[wasm_bindgen]
pub fn checkPermission(mode: &str, tool: &str) -> bool {
    let permission_mode = PermissionMode::from_str(mode).unwrap_or(PermissionMode::ReadOnly);
    let mut policy = PermissionPolicy::new(permission_mode);

    let required_mode = match tool {
        // Read-only diagnostic and intelligence tools
        "check_mx" | "check_spf" | "check_dmarc" | "check_dkim" | "check_dnssec" | "check_ssl" |
        "check_mta_sts" | "check_ns" | "check_caa" | "check_bimi" | "check_tlsrpt" |
        "check_http_security" | "check_dane" | "check_dane_https" | "check_svcb_https" |
        "check_lookalikes" | "scan_domain" | "compare_baseline" | "check_shadow_domains" |
        "check_txt_hygiene" | "check_mx_reputation" | "check_srv" | "check_zone_hygiene" |
        "get_benchmark" | "get_provider_insights" | "assess_spoofability" |
        "check_resolver_consistency" | "explain_finding" | "map_supply_chain" |
        "analyze_drift" | "resolve_spf_chain" | "discover_subdomains" | "map_compliance" |
        "simulate_attack_paths" => PermissionMode::ReadOnly,

        // Remediation tools that generate suggested configuration changes
        "generate_fix_plan" | "generate_spf_record" | "generate_dmarc_record" |
        "generate_dkim_config" | "generate_mta_sts_policy" | "validate_fix" |
        "generate_rollout_plan" => PermissionMode::WorkspaceWrite,

        _ => PermissionMode::DangerFullAccess,
    };

    policy = policy.with_tool_requirement(tool.to_string(), required_mode);
    policy.authorize(tool)
}

#[wasm_bindgen]
pub fn estimateTokens(text: &str) -> usize {
    text.len() / 4 + 1
}

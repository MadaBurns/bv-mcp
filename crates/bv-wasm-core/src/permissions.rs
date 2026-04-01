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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorize_read_only() {
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("read_file".to_string(), PermissionMode::ReadOnly);
        assert!(policy.authorize("read_file"));
    }

    #[test]
    fn test_deny_escalation() {
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("write_file".to_string(), PermissionMode::WorkspaceWrite);
        assert!(!policy.authorize("write_file"));
    }

    #[test]
    fn test_allow_all() {
        let policy = PermissionPolicy::new(PermissionMode::Allow);
        assert!(policy.authorize("any_tool"));
    }
}

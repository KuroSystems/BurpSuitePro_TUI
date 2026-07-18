use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRuleType {
    Include,
    Exclude,
}

impl ScopeRuleType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "exclude" => Self::Exclude,
            _ => Self::Include,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub id: i64,
    pub pattern: String,
    pub rule_type: ScopeRuleType,
    pub enabled: bool,
}

impl ScopeRule {
    pub fn include(id: i64, pattern: impl Into<String>) -> Self {
        Self {
            id,
            pattern: pattern.into(),
            rule_type: ScopeRuleType::Include,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScopeEngine {
    pub rules: Vec<ScopeRule>,
}

impl ScopeEngine {
    pub fn new(rules: Vec<ScopeRule>) -> Self {
        Self { rules }
    }

    pub fn is_in_scope(&self, uri: &str) -> bool {
        let enabled = self.rules.iter().filter(|rule| rule.enabled);
        let mut has_include = false;
        let mut included = false;

        for rule in enabled {
            let Ok(regex) = Regex::new(&rule.pattern) else {
                continue;
            };
            if rule.rule_type == ScopeRuleType::Include {
                has_include = true;
            }
            if regex.is_match(uri) {
                match rule.rule_type {
                    ScopeRuleType::Include => included = true,
                    ScopeRuleType::Exclude => return false,
                }
            }
        }

        if has_include {
            included
        } else {
            true
        }
    }

    pub fn validate(pattern: &str) -> Result<(), String> {
        Regex::new(pattern)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

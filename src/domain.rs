use std::collections::HashSet;

/// Check if a domain is allowed based on the allowed domains configuration
///
/// Supports several patterns:
/// - `*` - Allow all domains
/// - `example.com` - Exact domain match
/// - `*.example.com` - Any subdomain of example.com (but not the apex domain)
/// - `.example.com` - The apex domain or any subdomain of example.com
///
/// # Arguments
/// * `allowed` - Set of allowed domain patterns
/// * `host` - The host/domain to check
///
/// # Returns
/// `true` if the domain is allowed, `false` otherwise
pub fn is_domain_allowed(allowed: &HashSet<String>, host: &str) -> bool {
    let normalized_host = host.to_ascii_lowercase();

    // Universal wildcard allows everything
    if allowed.contains("*") {
        return true;
    }

    // Exact match (case-insensitive)
    if allowed
        .iter()
        .any(|pattern| pattern.eq_ignore_ascii_case(host))
    {
        return true;
    }

    // Check pattern matches
    for pattern in allowed {
        if is_pattern_match(pattern, &normalized_host) {
            return true;
        }
    }

    false
}

/// Check if a host matches a suffix with proper dot boundary
fn matches_suffix_with_boundary(host: &str, suffix: &str) -> bool {
    if host.ends_with(suffix) && host.len() > suffix.len() {
        let boundary_pos = host.len() - suffix.len() - 1;
        return host.as_bytes().get(boundary_pos) == Some(&b'.');
    }
    false
}

/// Check if a host matches a specific pattern
fn is_pattern_match(pattern: &str, host: &str) -> bool {
    let normalized_pattern = pattern.to_ascii_lowercase();

    // Leading dot pattern: .example.com
    // Matches apex domain or any subdomain of suffix
    if let Some(suffix) = normalized_pattern.strip_prefix('.') {
        return host == suffix || matches_suffix_with_boundary(host, suffix);
    }

    // Wildcard subdomain pattern: *.example.com
    // Matches any subdomain of suffix (but not the apex domain)
    if let Some(suffix) = normalized_pattern.strip_prefix("*.") {
        return matches_suffix_with_boundary(host, suffix);
    }

    false
}

fn normalize_patterns<I>(patterns: I) -> HashSet<String>
where
    I: IntoIterator<Item = String>,
{
    patterns
        .into_iter()
        .map(|pattern| pattern.to_ascii_lowercase())
        .collect()
}

/// Domain filter configuration
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DomainFilter {
    allowed_domains: Option<HashSet<String>>,
}

#[allow(dead_code)]
impl DomainFilter {
    /// Create a new domain filter with no restrictions (allow all)
    pub fn allow_all() -> Self {
        Self {
            allowed_domains: None,
        }
    }

    /// Create a new domain filter with specific allowed domains
    pub fn with_allowed_domains(domains: HashSet<String>) -> Self {
        Self {
            allowed_domains: Some(normalize_patterns(domains)),
        }
    }

    /// Create a domain filter from a vector of domain strings
    pub fn from_vec(domains: Vec<String>) -> Self {
        if domains.is_empty() {
            Self::allow_all()
        } else {
            Self {
                allowed_domains: Some(normalize_patterns(domains)),
            }
        }
    }

    /// Check if a domain is allowed by this filter
    pub fn is_allowed(&self, host: &str) -> bool {
        match &self.allowed_domains {
            Some(allowed) => is_domain_allowed(allowed, host),
            None => true, // No restrictions
        }
    }

    /// Check if this filter has any restrictions
    pub fn has_restrictions(&self) -> bool {
        self.allowed_domains.is_some()
    }

    /// Get the number of allowed domain patterns
    pub fn pattern_count(&self) -> usize {
        self.allowed_domains.as_ref().map_or(0, |domains| domains.len())
    }

    /// Add a domain pattern to the allowed list
    pub fn add_pattern(&mut self, pattern: String) {
        let pattern = pattern.to_ascii_lowercase();
        match &mut self.allowed_domains {
            Some(domains) => {
                domains.insert(pattern);
            }
            None => {
                let mut domains = HashSet::new();
                domains.insert(pattern);
                self.allowed_domains = Some(domains);
            }
        }
    }

    /// Remove a domain pattern from the allowed list
    pub fn remove_pattern(&mut self, pattern: &str) -> bool {
        let pattern = pattern.to_ascii_lowercase();
        match &mut self.allowed_domains {
            Some(domains) => domains.remove(&pattern),
            None => false,
        }
    }

    /// Get all allowed domain patterns
    pub fn get_patterns(&self) -> Option<&HashSet<String>> {
        self.allowed_domains.as_ref()
    }
}

impl Default for DomainFilter {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// Validate a domain pattern for common mistakes
#[allow(dead_code)]
pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Domain pattern cannot be empty".to_string());
    }

    if pattern == "*" {
        return Ok(()); // Universal wildcard is valid
    }

    // Check for invalid characters
    if pattern.contains(' ') {
        return Err("Domain pattern cannot contain spaces".to_string());
    }

    // Check for double dots
    if pattern.contains("..") {
        return Err("Domain pattern cannot contain consecutive dots".to_string());
    }

    // Check for patterns that start with dot but are not valid
    if pattern.starts_with('.') && pattern.len() == 1 {
        return Err("Single dot is not a valid domain pattern".to_string());
    }

    // Check for patterns that end with dot
    if pattern.ends_with('.') {
        return Err("Domain pattern cannot end with a dot".to_string());
    }

    // Validate wildcard patterns
    if pattern.contains('*') {
        if !pattern.starts_with("*.") {
            return Err("Wildcard (*) can only be used as '*.domain.com'".to_string());
        }

        let suffix = &pattern[2..];
        if suffix.contains('*') {
            return Err("Only one wildcard (*) is allowed per pattern".to_string());
        }

        if suffix.is_empty() {
            return Err("Wildcard pattern must have a domain after '*.'".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_domain_allowed_exact() {
        let mut set = HashSet::new();
        set.insert("example.com".to_string());

        assert!(is_domain_allowed(&set, "example.com"));
        assert!(!is_domain_allowed(&set, "a.example.com"));
        assert!(!is_domain_allowed(&set, "other.com"));
    }

    #[test]
    fn test_is_domain_allowed_exact_case_insensitive() {
        let mut set = HashSet::new();
        set.insert("Example.COM".to_string());

        assert!(is_domain_allowed(&set, "example.com"));
        assert!(is_domain_allowed(&set, "EXAMPLE.COM"));
        assert!(!is_domain_allowed(&set, "other.com"));
    }

    #[test]
    fn test_is_domain_allowed_wildcard_subdomains() {
        let mut set = HashSet::new();
        set.insert("*.example.com".to_string());

        assert!(is_domain_allowed(&set, "a.example.com"));
        assert!(is_domain_allowed(&set, "a.b.example.com"));
        assert!(!is_domain_allowed(&set, "example.com")); // Apex not allowed
        assert!(!is_domain_allowed(&set, "badexample.com"));
    }

    #[test]
    fn test_is_domain_allowed_wildcard_case_insensitive() {
        let mut set = HashSet::new();
        set.insert("*.Example.COM".to_string());

        assert!(is_domain_allowed(&set, "sub.example.com"));
        assert!(is_domain_allowed(&set, "SUB.EXAMPLE.COM"));
        assert!(!is_domain_allowed(&set, "example.com"));
    }

    #[test]
    fn test_is_domain_allowed_leading_dot_suffix() {
        let mut set = HashSet::new();
        set.insert(".example.com".to_string());

        assert!(is_domain_allowed(&set, "example.com")); // Apex allowed
        assert!(is_domain_allowed(&set, "a.example.com"));
        assert!(!is_domain_allowed(&set, "badexample.com"));
    }

    #[test]
    fn test_is_domain_allowed_any_wildcard() {
        let mut set = HashSet::new();
        set.insert("*".to_string());

        assert!(is_domain_allowed(&set, "anything.com"));
        assert!(is_domain_allowed(&set, "sub.domain"));
    }

    #[test]
    fn test_domain_filter_allow_all() {
        let filter = DomainFilter::allow_all();

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("any.domain.com"));
        assert!(!filter.has_restrictions());
        assert_eq!(filter.pattern_count(), 0);
    }

    #[test]
    fn test_domain_filter_with_restrictions() {
        let mut domains = HashSet::new();
        domains.insert("example.com".to_string());
        domains.insert("*.test.com".to_string());

        let filter = DomainFilter::with_allowed_domains(domains);

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("sub.test.com"));
        assert!(!filter.is_allowed("other.com"));
        assert!(filter.has_restrictions());
        assert_eq!(filter.pattern_count(), 2);
    }

    #[test]
    fn test_domain_filter_from_vec() {
        let domains = vec!["example.com".to_string(), "test.org".to_string()];
        let filter = DomainFilter::from_vec(domains);

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("test.org"));
        assert!(!filter.is_allowed("other.com"));
    }

    #[test]
    fn test_domain_filter_add_remove_patterns() {
        let mut filter = DomainFilter::allow_all();

        filter.add_pattern("example.com".to_string());
        assert!(filter.has_restrictions());
        assert_eq!(filter.pattern_count(), 1);

        assert!(filter.remove_pattern("example.com"));
        assert_eq!(filter.pattern_count(), 0);

        assert!(!filter.remove_pattern("nonexistent.com"));
    }

    #[test]
    fn test_validate_domain_pattern() {
        // Valid patterns
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
        assert!(validate_domain_pattern(".example.com").is_ok());
        assert!(validate_domain_pattern("*").is_ok());

        // Invalid patterns
        assert!(validate_domain_pattern("").is_err());
        assert!(validate_domain_pattern("example .com").is_err());
        assert!(validate_domain_pattern("example..com").is_err());
        assert!(validate_domain_pattern(".").is_err());
        assert!(validate_domain_pattern("example.com.").is_err());
        assert!(validate_domain_pattern("*example.com").is_err());
        assert!(validate_domain_pattern("*.*.com").is_err());
        assert!(validate_domain_pattern("*.").is_err());
    }

    #[test]
    fn test_pattern_matching_edge_cases() {
        let mut set = HashSet::new();
        set.insert("*.example.com".to_string());

        // Should not match domains that just end with the suffix
        assert!(!is_domain_allowed(&set, "notexample.com"));
        assert!(!is_domain_allowed(&set, "testexample.com"));

        // Should match proper subdomains
        assert!(is_domain_allowed(&set, "sub.example.com"));
        assert!(is_domain_allowed(&set, "a.b.c.example.com"));
    }
}

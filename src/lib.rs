pub fn analyze(source: &str) -> Vec<Finding> {
    let _ = source;
    Vec::new()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_source_has_no_findings() {
        assert!(analyze("").is_empty());
    }
}

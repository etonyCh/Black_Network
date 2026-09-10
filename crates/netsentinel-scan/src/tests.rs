#[cfg(test)]
mod tests {
    use crate::map_severity;
    use netsentinel_proto::Severity;

    #[test]
    fn test_map_severity() {
        assert!(matches!(map_severity("critical"), Severity::Critical));
        assert!(matches!(map_severity("HIGH"), Severity::High));
        assert!(matches!(map_severity("MeDiUm"), Severity::Medium));
        assert!(matches!(map_severity("low"), Severity::Low));
        assert!(matches!(map_severity("unknown"), Severity::Info));
    }
}

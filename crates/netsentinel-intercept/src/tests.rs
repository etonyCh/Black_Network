#[cfg(test)]
mod tests {
    use crate::audit::AuditLogger;
    use tempfile::NamedTempFile;
    use std::fs;

    #[test]
    fn test_audit_signature_verification() {
        let secret = "super_secret_test_key";
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(secret, temp_file.path().to_str().unwrap());

        logger.log_action("TEST_ACTION", "192.168.1.1", "operator_1").unwrap();

        let contents = fs::read_to_string(temp_file.path()).unwrap();
        let lines: Vec<&str> = contents.trim().split('\n').collect();
        assert_eq!(lines.len(), 1);

        let json_line = lines[0];
        
        // Validation positive
        assert!(AuditLogger::verify_entry(secret, json_line), "La signature doit être valide avec la bonne clé");

        // Validation négative : mauvaise clé
        assert!(!AuditLogger::verify_entry("wrong_key", json_line), "La signature ne doit pas être valide avec une mauvaise clé");

        // Validation négative : altération du payload
        let tampered_line = json_line.replace("192.168.1.1", "192.168.1.100");
        assert!(!AuditLogger::verify_entry(secret, &tampered_line), "La signature doit rejeter un payload altéré");
    }
}

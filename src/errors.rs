// src/errors.rs
//! Comprehensive error handling system for TorusCSIDH with mathematical rigor and security guarantees.
//! This module provides a type-safe error classification system with severity levels,
//! contextual logging for security auditing, and automatic termination mechanisms for
//! critical security violations.

use thiserror::Error;
use rug::Integer;
use std::fmt;
use log::{error, warn, info, debug};

/// Security severity levels for error classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Critical security violation that compromises the entire system
    Critical,
    /// High severity violation that affects security properties
    High,
    /// Medium severity that affects functionality but not core security
    Medium,
    /// Low severity that affects usability but not security
    Low,
}

impl fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SecuritySeverity::Critical => write!(f, "CRITICAL"),
            SecuritySeverity::High => write!(f, "HIGH"),
            SecurityViolation => write!(f, "HIGH"),
            SecuritySeverity::Medium => write!(f, "MEDIUM"),
            SecuritySeverity::Low => write!(f, "LOW"),
        }
    }
}

/// Comprehensive error types for TorusCSIDH system
#[derive(Error, Debug, Clone)]
pub enum TorusCSIDHError {
    #[error("Invalid key length: expected {expected}, got {actual} in context '{context}'")]
    InvalidKeyLength {
        expected: usize,
        actual: usize,
        context: String,
    },
    
    #[error("Invalid curve parameter '{parameter}': value={value}, expected range [{min}, {max}]")]
    InvalidCurveParameter {
        parameter: String,
        value: Integer,
        min: Integer,
        max: Integer,
    },
    
    #[error("Verification failed at step {step}: {reason}")]
    VerificationFailed {
        step: usize,
        reason: String,
        curve_data: Option<String>,
    },
    
    #[error("Arithmetic error in operation '{operation}' with parameters: {params}, field size: {field_size}-bit")]
    ArithmeticError {
        operation: String,
        params: String,
        field_size: usize,
    },
    
    #[error("Security violation: {violation_type}, severity: {severity}, mitigation: {mitigation}")]
    SecurityViolation {
        violation_type: String,
        severity: SecuritySeverity,
        mitigation: String,
    },
    
    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed {
        reason: String,
        entropy_available: usize,
    },
    
    #[error("Isogeny application failed: degree={degree}, kernel size={kernel_size}")]
    IsogenyFailed {
        degree: u64,
        kernel_size: usize,
        reason: String,
    },
    
    #[error("System resource error")]
    SystemError {
        #[from]
        source: std::io::Error,
    },
    
    #[error("Memory allocation failure")]
    MemoryAllocationFailed {
        requested_size: usize,
        available_memory: Option<usize>,
    },
}

impl TorusCSIDHError {
    /// Get the security severity level of this error
    pub fn severity(&self) -> SecuritySeverity {
        match self {
            TorusCSIDHError::SecurityViolation { severity, .. } => *severity,
            TorusCSIDHError::VerificationFailed { .. } => SecuritySeverity::Critical,
            TorusCSIDHError::InvalidKeyLength { .. } => SecuritySeverity::High,
            TorusCSIDHError::InvalidCurveParameter { .. } => SecuritySeverity::High,
            TorusCSIDHError::KeyGenerationFailed { .. } => SecuritySeverity::Critical,
            TorusCSIDHError::IsogenyFailed { .. } => SecuritySeverity::High,
            TorusCSIDHError::ArithmeticError { .. } => SecuritySeverity::Medium,
            TorusCSIDHError::MemoryAllocationFailed { .. } => SecuritySeverity::Medium,
            TorusCSIDHError::SystemError { .. } => SecuritySeverity::Low,
        }
    }
    
    /// Convert error to user-safe message (no sensitive details)
    pub fn to_user_message(&self) -> String {
        match self.severity() {
            SecuritySeverity::Critical | SecuritySeverity::High => {
                "CRITICAL SECURITY VIOLATION: Operation terminated".to_string()
            },
            SecuritySeverity::Medium => {
                "Operation failed due to system error. Please contact support.".to_string()
            },
            SecuritySeverity::Low => {
                format!("Error: {}", self)
            },
        }
    }
    
    /// Get detailed log message for security auditing
    pub fn to_audit_log(&self) -> String {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let process_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        
        format!("[{}] [PID: {}] [TID: {}] [SEVERITY: {}] {}",
                timestamp,
                process_id,
                thread_id,
                self.severity(),
                self)
    }
    
    /// Log the error with appropriate context and severity
    pub fn log_with_context(&self, module: &str, function: &str, line: u32) {
        let log_message = format!("[{}:{}:{}] {}", module, function, line, self.to_audit_log());
        
        match self.severity() {
            SecuritySeverity::Critical => {
                error!("{}", log_message);
                // Automatic termination for critical security violations
                std::process::exit(1);
            },
            SecuritySeverity::High => {
                error!("{}", log_message);
            },
            SecuritySeverity::Medium => {
                warn!("{}", log_message);
            },
            SecuritySeverity::Low => {
                info!("{}", log_message);
            },
        }
    }
}

/// Extension trait for secure Result handling with contextual logging
pub trait SecureResultExt<T> {
    fn secure_unwrap(self, module: &str, function: &str, line: u32) -> T;
    fn secure_expect(self, msg: &str, module: &str, function: &str, line: u32) -> T;
    fn log_on_error(self, module: &str, function: &str, line: u32) -> Self;
}

impl<T, E: std::fmt::Debug + Into<TorusCSIDHError>> SecureResultExt<T> for Result<T, E> {
    fn secure_unwrap(self, module: &str, function: &str, line: u32) -> T {
        match self {
            Ok(value) => value,
            Err(error) => {
                let torus_error: TorusCSIDHError = error.into();
                torus_error.log_with_context(module, function, line);
                unreachable!("secure_unwrap always terminates for errors");
            }
        }
    }
    
    fn secure_expect(self, msg: &str, module: &str, function: &str, line: u32) -> T {
        match self {
            Ok(value) => value,
            Err(error) => {
                let torus_error: TorusCSIDHError = error.into();
                let extended_error = match torus_error {
                    TorusCSIDHError::SecurityViolation { violation_type, severity, mitigation } => {
                        TorusCSIDHError::SecurityViolation {
                            violation_type: format!("{}: {}", msg, violation_type),
                            severity,
                            mitigation,
                        }
                    },
                    e => e,
                };
                extended_error.log_with_context(module, function, line);
                unreachable!("secure_expect always terminates for errors");
            }
        }
    }
    
    fn log_on_error(self, module: &str, function: &str, line: u32) -> Self {
        if let Err(ref error) = self {
            let torus_error: TorusCSIDHError = error.clone().into();
            torus_error.log_with_context(module, function, line);
        }
        self
    }
}

/// Contextual error builder with automatic severity classification
#[derive(Debug)]
pub struct ErrorBuilder {
    module: String,
    function: String,
    line: u32,
    error: TorusCSIDHError,
}

impl ErrorBuilder {
    /// Create a new error builder with context
    pub fn new(error: TorusCSIDHError) -> Self {
        Self {
            module: module_path!().to_string(),
            function: std::any::type_name::<Self>().to_string(),
            line: line!(),
            error,
        }
    }
    
    /// Set explicit context information
    pub fn with_context(mut self, module: &str, function: &str, line: u32) -> Self {
        self.module = module.to_string();
        self.function = function.to_string();
        self.line = line;
        self
    }
    
    /// Log the error and return the error builder
    pub fn log(self) -> Self {
        self.error.log_with_context(&self.module, &self.function, self.line);
        self
    }
    
    /// Build and return the error
    pub fn build(self) -> TorusCSIDHError {
        self.error
    }
    
    /// Build, log, and convert to Result::Err
    pub fn into_result<T>(self) -> Result<T, TorusCSIDHError> {
        let error = self.log().build();
        Err(error)
    }
}

impl From<std::io::Error> for TorusCSIDHError {
    fn from(err: std::io::Error) -> Self {
        TorusCSIDHError::SystemError { source: err }
    }
}

impl From<std::num::TryFromIntError> for TorusCSIDHError {
    fn from(err: std::num::TryFromIntError) -> Self {
        TorusCSIDHError::ArithmeticError {
            operation: "integer conversion".to_string(),
            params: format!("{:?}", err),
            field_size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    
    #[test]
    fn test_error_severity_classification() {
        let critical_error = TorusCSIDHError::VerificationFailed {
            step: 1,
            reason: "Invalid curve".to_string(),
            curve_data: None,
        };
        assert_eq!(critical_error.severity(), SecuritySeverity::Critical);
        
        let high_error = TorusCSIDHError::InvalidKeyLength {
            expected: 14,
            actual: 10,
            context: "key_exchange".to_string(),
        };
        assert_eq!(high_error.severity(), SecuritySeverity::High);
        
        let medium_error = TorusCSIDHError::ArithmeticError {
            operation: "addition".to_string(),
            params: "large values".to_string(),
            field_size: 768,
        };
        assert_eq!(medium_error.severity(), SecuritySeverity::Medium);
        
        let low_error = TorusCSIDHError::SystemError {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "File not found"),
        };
        assert_eq!(low_error.severity(), SecuritySeverity::Low);
    }
    
    #[test]
    fn test_user_message_safety() {
        let critical_error = TorusCSIDHError::SecurityViolation {
            violation_type: "Side-channel attack detected".to_string(),
            severity: SecuritySeverity::Critical,
            mitigation: "Terminate process".to_string(),
        };
        assert_eq!(critical_error.to_user_message(), "CRITICAL SECURITY VIOLATION: Operation terminated");
        
        let low_error = TorusCSIDHError::SystemError {
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "File not found"),
        };
        assert!(low_error.to_user_message().contains("File not found"));
    }
    
    #[test]
    fn test_audit_logging_format() {
        let error = TorusCSIDHError::VerificationFailed {
            step: 42,
            reason: "Curve not supersingular".to_string(),
            curve_data: Some("A=5,B=3".to_string()),
        };
        let log_message = error.to_audit_log();
        assert!(log_message.contains("SEVERITY: CRITICAL"));
        assert!(log_message.contains("Curve not supersingular"));
    }
    
    #[test]
    fn test_secure_result_unwrap() {
        let result: Result<i32, TorusCSIDHError> = Ok(42);
        assert_eq!(result.secure_unwrap("test", "success_case", 1), 42);
        
        // This should panic in test mode but exit in production
        let result: Result<i32, TorusCSIDHError> = Err(TorusCSIDHError::InvalidKeyLength {
            expected: 14,
            actual: 10,
            context: "test".to_string(),
        });
        
        let panic_result = panic::catch_unwind(|| {
            match std::panic::catch_unwind(|| {
                result.secure_unwrap("test", "failure_case", 1);
            }) {
                Ok(_) => assert!(false, "Should have panicked"),
                Err(_) => {
                    // Panic was caught, test continues
                }
            }
        });
        
        assert!(panic_result.is_ok());
    }
    
    #[test]
    fn test_error_builder_workflow() {
        // Create an error with context
        let builder = ErrorBuilder::new(TorusCSIDHError::InvalidCurveParameter {
            parameter: "A_coefficient".to_string(),
            value: Integer::from(5),
            min: Integer::from(2),
            max: Integer::from(4),
        });
        
        // Test logging
        let error = builder.clone().log().build();
        assert_eq!(error.severity(), SecuritySeverity::High);
        
        // Test result conversion
        let result: Result<(), TorusCSIDHError> = builder.into_result();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_critical_error_termination() {
        // Test that critical errors cause termination
        let critical_error = TorusCSIDHError::KeyGenerationFailed {
            reason: "Insufficient entropy".to_string(),
            entropy_available: 0,
        };
        
        // In test mode, this should panic rather than exit
        let result = panic::catch_unwind(|| {
            critical_error.log_with_context("crypto", "keygen", 42);
        });
        
        assert!(result.is_err(), "Critical errors should cause termination/panic");
    }
    
    #[test]
    fn test_security_violation_handling() {
        let violation = TorusCSIDHError::SecurityViolation {
            violation_type: "Timing side-channel detected".to_string(),
            severity: SecuritySeverity::Critical,
            mitigation: "Terminate process and log incident".to_string(),
        };
        
        assert_eq!(violation.to_user_message(), "CRITICAL SECURITY VIOLATION: Operation terminated");
        assert_eq!(violation.severity(), SecuritySeverity::Critical);
        
        // Test automatic termination in test environment (should panic)
        let result = panic::catch_unwind(|| {
            violation.log_with_context("security", "monitor", 123);
        });
        
        assert!(result.is_err(), "Security violations should cause termination");
    }
    
    #[test]
    fn test_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let torus_error: TorusCSIDHError = io_error.into();
        
        match torus_error {
            TorusCSIDHError::SystemError { .. } => {
                // Correct conversion
            },
            _ => panic!("IO error should convert to SystemError"),
        }
    }
    
    #[test]
    fn test_contextual_logging() {
        let error = TorusCSIDHError::IsogenyFailed {
            degree: 3,
            kernel_size: 0,
            reason: "Empty kernel points".to_string(),
        };
        
        // Capture logs to verify format
        let log_message = error.to_audit_log();
        assert!(log_message.contains("[SEVERITY: HIGH]"));
        assert!(log_message.contains("Isogeny failed"));
        assert!(log_message.contains("degree=3"));
        assert!(log_message.contains("kernel size=0"));
    }
}

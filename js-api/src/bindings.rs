//! JavaScript API bindings.

/// API function descriptor for JS bindings.
#[derive(Debug, Clone)]
pub struct JsApiBinding {
    pub name: String,
    pub description: String,
    pub parameters: Vec<BindingParam>,
    pub return_type: String,
}

/// Parameter descriptor for a JS API binding.
#[derive(Debug, Clone)]
pub struct BindingParam {
    pub name: String,
    pub js_type: String,
    pub description: String,
    pub optional: bool,
}

/// Create the standard JS API bindings.
pub fn standard_bindings() -> Vec<JsApiBinding> {
    vec![
        JsApiBinding {
            name: "ucx.hash".into(),
            description: "Hash data using SHA-256".into(),
            parameters: vec![BindingParam {
                name: "data".into(),
                js_type: "string|Uint8Array".into(),
                description: "Data to hash".into(),
                optional: false,
            }],
            return_type: "Promise<string>".into(),
        },
        JsApiBinding {
            name: "ucx.scan".into(),
            description: "Run a port scan on a target".into(),
            parameters: vec![
                BindingParam {
                    name: "target".into(),
                    js_type: "string".into(),
                    description: "Target hostname or IP".into(),
                    optional: false,
                },
                BindingParam {
                    name: "options".into(),
                    js_type: "object".into(),
                    description: "Scan options".into(),
                    optional: true,
                },
            ],
            return_type: "Promise<ScanResult[]>".into(),
        },
        JsApiBinding {
            name: "ucx.analyze".into(),
            description: "Analyze a binary file".into(),
            parameters: vec![BindingParam {
                name: "path".into(),
                js_type: "string".into(),
                description: "Path to the binary".into(),
                optional: false,
            }],
            return_type: "Promise<AnalysisResult>".into(),
        },
        JsApiBinding {
            name: "ucx.crypto.encrypt".into(),
            description: "Encrypt data with AES-256-GCM".into(),
            parameters: vec![
                BindingParam {
                    name: "plaintext".into(),
                    js_type: "string".into(),
                    description: "Data to encrypt".into(),
                    optional: false,
                },
                BindingParam {
                    name: "key".into(),
                    js_type: "string".into(),
                    description: "Encryption key (base64)".into(),
                    optional: false,
                },
            ],
            return_type: "Promise<string>".into(),
        },
        JsApiBinding {
            name: "ucx.crypto.decrypt".into(),
            description: "Decrypt data with AES-256-GCM".into(),
            parameters: vec![
                BindingParam {
                    name: "ciphertext".into(),
                    js_type: "string".into(),
                    description: "Data to decrypt".into(),
                    optional: false,
                },
                BindingParam {
                    name: "key".into(),
                    js_type: "string".into(),
                    description: "Decryption key (base64)".into(),
                    optional: false,
                },
            ],
            return_type: "Promise<string>".into(),
        },
        JsApiBinding {
            name: "ucx.log".into(),
            description: "Log a message to the platform log".into(),
            parameters: vec![BindingParam {
                name: "message".into(),
                js_type: "string".into(),
                description: "Message to log".into(),
                optional: false,
            }],
            return_type: "void".into(),
        },
        JsApiBinding {
            name: "ucx.report".into(),
            description: "Generate a security report".into(),
            parameters: vec![BindingParam {
                name: "data".into(),
                js_type: "object".into(),
                description: "Report data".into(),
                optional: false,
            }],
            return_type: "Promise<Report>".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bindings_count() {
        let bindings = standard_bindings();
        assert_eq!(bindings.len(), 7);
    }

    #[test]
    fn test_binding_names() {
        let bindings = standard_bindings();
        let names: Vec<&str> = bindings.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"ucx.hash"));
        assert!(names.contains(&"ucx.scan"));
        assert!(names.contains(&"ucx.crypto.encrypt"));
    }
}

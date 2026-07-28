//! Lua API bindings - exposes UCOP-X kernel APIs to Lua scripts.

/// Lua API function registration.
#[derive(Debug, Clone)]
pub struct LuaApiFunction {
    pub name: String,
    pub description: String,
    pub parameters: Vec<ApiParam>,
    pub return_type: String,
}

/// A parameter for a Lua API function.
#[derive(Debug, Clone)]
pub struct ApiParam {
    pub name: String,
    pub param_type: String,
    pub description: String,
    pub optional: bool,
}

/// Creates the standard set of UCOP-X API functions available to Lua scripts.
pub fn standard_api() -> Vec<LuaApiFunction> {
    vec![
        LuaApiFunction {
            name: "ucx.log".into(),
            description: "Log a message".into(),
            parameters: vec![ApiParam {
                name: "message".into(),
                param_type: "string".into(),
                description: "The message to log".into(),
                optional: false,
            }],
            return_type: "nil".into(),
        },
        LuaApiFunction {
            name: "ucx.hash".into(),
            description: "Compute a SHA-256 hash".into(),
            parameters: vec![ApiParam {
                name: "data".into(),
                param_type: "string".into(),
                description: "Data to hash".into(),
                optional: false,
            }],
            return_type: "string".into(),
        },
        LuaApiFunction {
            name: "ucx.scan".into(),
            description: "Execute a network scan".into(),
            parameters: vec![
                ApiParam {
                    name: "target".into(),
                    param_type: "string".into(),
                    description: "Target host or IP".into(),
                    optional: false,
                },
                ApiParam {
                    name: "port".into(),
                    param_type: "number".into(),
                    description: "Port to scan".into(),
                    optional: true,
                },
            ],
            return_type: "table".into(),
        },
        LuaApiFunction {
            name: "ucx.analyze".into(),
            description: "Analyze a file or binary".into(),
            parameters: vec![ApiParam {
                name: "path".into(),
                param_type: "string".into(),
                description: "Path to the file".into(),
                optional: false,
            }],
            return_type: "table".into(),
        },
        LuaApiFunction {
            name: "ucx.crypto.encrypt".into(),
            description: "Encrypt data with AES-256-GCM".into(),
            parameters: vec![
                ApiParam {
                    name: "data".into(),
                    param_type: "string".into(),
                    description: "Plaintext data".into(),
                    optional: false,
                },
                ApiParam {
                    name: "key".into(),
                    param_type: "string".into(),
                    description: "Base64-encoded key".into(),
                    optional: false,
                },
            ],
            return_type: "string".into(),
        },
        LuaApiFunction {
            name: "ucx.crypto.decrypt".into(),
            description: "Decrypt data with AES-256-GCM".into(),
            parameters: vec![
                ApiParam {
                    name: "data".into(),
                    param_type: "string".into(),
                    description: "Encrypted data".into(),
                    optional: false,
                },
                ApiParam {
                    name: "key".into(),
                    param_type: "string".into(),
                    description: "Base64-encoded key".into(),
                    optional: false,
                },
            ],
            return_type: "string".into(),
        },
    ]
}

/// Find an API function by name.
pub fn find_api_function(name: &str) -> Option<LuaApiFunction> {
    standard_api().into_iter().find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_api_count() {
        let api = standard_api();
        assert_eq!(api.len(), 6);
    }

    #[test]
    fn test_find_api_function() {
        let func = find_api_function("ucx.hash").unwrap();
        assert_eq!(func.return_type, "string");
        assert!(find_api_function("nonexistent").is_none());
    }
}

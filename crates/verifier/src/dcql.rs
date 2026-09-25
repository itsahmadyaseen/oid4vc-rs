//! DCQL (Digital Credentials Query Language) query builder and evaluator.

use oid4vc_types::oid4vp::{ClaimQuery, CredentialQuery, DcqlQuery};

/// Builder for constructing DCQL queries.
pub struct DcqlQueryBuilder {
    credentials: Vec<CredentialQuery>,
}

impl DcqlQueryBuilder {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    /// Add an SD-JWT VC credential query.
    pub fn add_sd_jwt_vc_query(mut self, id: &str, vct: &str, claims: Vec<(&str, bool)>) -> Self {
        let claim_queries: Vec<ClaimQuery> = claims
            .into_iter()
            .map(|(path, _mandatory)| ClaimQuery {
                path: vec![path.to_string()],
                namespace: None,
                id: Some(path.to_string()),
                values: None,
            })
            .collect();

        self.credentials.push(CredentialQuery {
            id: id.to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: Some(vct.to_string()),
            doctype: None,
            claims: if claim_queries.is_empty() {
                None
            } else {
                Some(claim_queries)
            },
        });

        self
    }

    /// Add an mdoc credential query.
    pub fn add_mdoc_query(
        mut self,
        id: &str,
        doctype: &str,
        namespace: &str,
        claims: Vec<&str>,
    ) -> Self {
        let claim_queries: Vec<ClaimQuery> = claims
            .into_iter()
            .map(|claim_name| ClaimQuery {
                path: vec![claim_name.to_string()],
                namespace: Some(namespace.to_string()),
                id: Some(claim_name.to_string()),
                values: None,
            })
            .collect();

        self.credentials.push(CredentialQuery {
            id: id.to_string(),
            format: "mso_mdoc".to_string(),
            vct: None,
            doctype: Some(doctype.to_string()),
            claims: if claim_queries.is_empty() {
                None
            } else {
                Some(claim_queries)
            },
        });

        self
    }

    /// Build the DCQL query.
    pub fn build(self) -> DcqlQuery {
        DcqlQuery {
            credentials: self.credentials,
        }
    }
}

impl Default for DcqlQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluate whether a set of disclosed claims satisfies a DCQL credential query.
///
/// Returns `true` if all required claims are present in the disclosed set.
pub fn evaluate_credential_query(
    query: &CredentialQuery,
    disclosed_claims: &std::collections::HashMap<String, serde_json::Value>,
) -> bool {
    if let Some(ref claims) = query.claims {
        for claim in claims {
            // Check if the first path element exists in the disclosed claims
            if let Some(first_path) = claim.path.first() {
                if !disclosed_claims.contains_key(first_path) {
                    return false;
                }

                // If specific values are required, check them
                if let Some(ref expected_values) = claim.values {
                    if let Some(actual_value) = disclosed_claims.get(first_path) {
                        if !expected_values.contains(actual_value) {
                            return false;
                        }
                    }
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_dcql_query_builder_sd_jwt() {
        let query = DcqlQueryBuilder::new()
            .add_sd_jwt_vc_query(
                "identity",
                "https://example.com/credentials/identity",
                vec![
                    ("given_name", true),
                    ("family_name", true),
                    ("birth_date", false),
                ],
            )
            .build();

        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].format, "dc+sd-jwt");
        assert_eq!(query.credentials[0].claims.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_dcql_query_builder_mdoc() {
        let query = DcqlQueryBuilder::new()
            .add_mdoc_query(
                "mdl",
                "org.iso.18013.5.1.mDL",
                "org.iso.18013.5.1",
                vec!["family_name", "given_name", "birth_date"],
            )
            .build();

        assert_eq!(query.credentials.len(), 1);
        assert_eq!(query.credentials[0].format, "mso_mdoc");
    }

    #[test]
    fn test_evaluate_credential_query_satisfied() {
        let query = CredentialQuery {
            id: "test".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: None,
            doctype: None,
            claims: Some(vec![ClaimQuery {
                path: vec!["given_name".to_string()],
                namespace: None,
                id: None,
                values: None,
            }]),
        };

        let mut disclosed = HashMap::new();
        disclosed.insert(
            "given_name".to_string(),
            serde_json::Value::String("John".to_string()),
        );

        assert!(evaluate_credential_query(&query, &disclosed));
    }

    #[test]
    fn test_evaluate_credential_query_not_satisfied() {
        let query = CredentialQuery {
            id: "test".to_string(),
            format: "dc+sd-jwt".to_string(),
            vct: None,
            doctype: None,
            claims: Some(vec![
                ClaimQuery {
                    path: vec!["given_name".to_string()],
                    namespace: None,
                    id: None,
                    values: None,
                },
                ClaimQuery {
                    path: vec!["family_name".to_string()],
                    namespace: None,
                    id: None,
                    values: None,
                },
            ]),
        };

        // Only one claim disclosed, but two required
        let mut disclosed = HashMap::new();
        disclosed.insert(
            "given_name".to_string(),
            serde_json::Value::String("John".to_string()),
        );

        assert!(!evaluate_credential_query(&query, &disclosed));
    }
}

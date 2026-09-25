//! Credential offer generation.
//!
//! Supports both issuer-initiated and wallet-initiated issuance flows.

use oid4vc_types::oid4vci::{
    AuthorizationCodeGrant, CredentialOffer, Grants, PreAuthorizedCodeGrant,
};
use url::Url;
use uuid::Uuid;

/// Parameters for creating a credential offer.
pub struct OfferParams {
    /// The credential configuration IDs to include in the offer.
    pub credential_configuration_ids: Vec<String>,
    /// Whether to use the authorization code flow.
    pub use_authorization_code: bool,
    /// Whether to use the pre-authorized code flow.
    pub use_pre_authorized_code: bool,
    /// Whether a transaction code (PIN) is required.
    pub require_tx_code: bool,
}

/// Create a credential offer.
///
/// Returns the offer object and optionally a pre-authorized code
/// that must be stored by the caller for later validation.
pub fn create_offer(issuer_url: &Url, params: &OfferParams) -> (CredentialOffer, Option<String>) {
    let mut grants = Grants {
        authorization_code: None,
        pre_authorized_code: None,
    };

    if params.use_authorization_code {
        grants.authorization_code = Some(AuthorizationCodeGrant {
            issuer_state: Some(Uuid::new_v4().to_string()),
            authorization_server: None,
        });
    }

    let mut pre_auth_code = None;
    if params.use_pre_authorized_code {
        let code = Uuid::new_v4().to_string();
        pre_auth_code = Some(code.clone());

        grants.pre_authorized_code = Some(PreAuthorizedCodeGrant {
            pre_authorized_code: code,
            tx_code: if params.require_tx_code {
                Some(oid4vc_types::oid4vci::TxCode {
                    input_mode: Some("numeric".to_string()),
                    length: Some(6),
                    description: Some("Please enter the 6-digit PIN".to_string()),
                })
            } else {
                None
            },
        });
    }

    let offer = CredentialOffer {
        credential_issuer: issuer_url.as_str().trim_end_matches('/').to_string(),
        credential_configuration_ids: params.credential_configuration_ids.clone(),
        grants: Some(grants),
    };

    (offer, pre_auth_code)
}

/// Encode a credential offer as a `openid-credential-offer://` URI.
///
/// This URI can be rendered as a QR code or sent via deep link.
pub fn encode_offer_uri(_issuer_url: &Url, offer: &CredentialOffer) -> String {
    let offer_json = serde_json::to_string(offer).unwrap_or_default();
    let encoded = urlencoding::encode(&offer_json);
    format!("openid-credential-offer://?credential_offer={}", encoded)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_offer_auth_code() {
        let issuer_url = Url::parse("https://issuer.example.com").unwrap();
        let params = OfferParams {
            credential_configuration_ids: vec!["IdentityCredential_SD_JWT_VC".to_string()],
            use_authorization_code: true,
            use_pre_authorized_code: false,
            require_tx_code: false,
        };

        let (offer, pre_auth) = create_offer(&issuer_url, &params);

        assert_eq!(offer.credential_configuration_ids.len(), 1);
        assert!(offer.grants.as_ref().unwrap().authorization_code.is_some());
        assert!(pre_auth.is_none());
    }

    #[test]
    fn test_create_offer_pre_authorized() {
        let issuer_url = Url::parse("https://issuer.example.com").unwrap();
        let params = OfferParams {
            credential_configuration_ids: vec!["IdentityCredential_SD_JWT_VC".to_string()],
            use_authorization_code: false,
            use_pre_authorized_code: true,
            require_tx_code: true,
        };

        let (offer, pre_auth) = create_offer(&issuer_url, &params);

        assert!(pre_auth.is_some());
        let grant = offer
            .grants
            .as_ref()
            .unwrap()
            .pre_authorized_code
            .as_ref()
            .unwrap();
        assert!(grant.tx_code.is_some());
    }

    #[test]
    fn test_encode_offer_uri() {
        let issuer_url = Url::parse("https://issuer.example.com").unwrap();
        let (offer, _) = create_offer(
            &issuer_url,
            &OfferParams {
                credential_configuration_ids: vec!["test".to_string()],
                use_authorization_code: true,
                use_pre_authorized_code: false,
                require_tx_code: false,
            },
        );

        let uri = encode_offer_uri(&issuer_url, &offer);
        assert!(uri.starts_with("openid-credential-offer://"));
    }
}

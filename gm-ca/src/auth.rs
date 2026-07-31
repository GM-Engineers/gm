//! Bearer Token authentication interceptor for the CA gRPC service.
//!
//! This module provides a `BearerTokenInterceptor` that validates the
//! `authorization` metadata header on incoming gRPC requests. Requests
//! without a valid `Bearer <token>` header are rejected with
//! `Status::unauthenticated`.

use subtle::ConstantTimeEq;
use tonic::{Request, Status, service::Interceptor};
use zeroize::ZeroizeOnDrop;

/// Minimum token length in bytes (after "Bearer " prefix removal).
/// 32 bytes = 256 bits of entropy, sufficient to resist brute-force attacks.
const MIN_TOKEN_BYTES: usize = 32;

/// A gRPC interceptor that validates Bearer Token authentication.
///
/// Checks the `authorization` metadata header for a `Bearer <token>` value
/// matching the expected token. Uses constant-time comparison to prevent
/// timing side-channel attacks.
#[derive(ZeroizeOnDrop)]
pub struct BearerTokenInterceptor {
    expected_token: Vec<u8>,
}

impl Clone for BearerTokenInterceptor {
    fn clone(&self) -> Self {
        Self {
            expected_token: self.expected_token.clone(),
        }
    }
}

impl BearerTokenInterceptor {
    /// Create a new interceptor with the expected bearer token.
    ///
    /// Returns an error if the token is shorter than 32 bytes, as weak tokens
    /// are vulnerable to brute-force attacks.
    pub fn new(token: String) -> Result<Self, String> {
        if token.len() < MIN_TOKEN_BYTES {
            return Err(format!(
                "CA_AUTH_TOKEN must be at least {} bytes, got {}. \
                 Generate with: openssl rand -hex 32",
                MIN_TOKEN_BYTES,
                token.len()
            ));
        }
        Ok(Self {
            // Store the full "Bearer <token>" form for comparison
            expected_token: format!("Bearer {}", token).into_bytes(),
        })
    }
}

impl Interceptor for BearerTokenInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let auth_header = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(header) => {
                let header_bytes = header.as_bytes();
                // Constant-time comparison to prevent timing attacks
                if header_bytes.ct_eq(&self.expected_token).into() {
                    Ok(request)
                } else {
                    Err(Status::unauthenticated("Invalid bearer token"))
                }
            }
            None => Err(Status::unauthenticated(
                "Missing authorization header. \
                 Set the 'authorization' metadata to 'Bearer <token>'.",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    // Token long enough to pass minimum length requirement (>= 32 bytes)
    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn make_request(auth_value: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        if let Some(val) = auth_value {
            let meta: MetadataValue<_> = val.parse().unwrap();
            req.metadata_mut().insert("authorization", meta);
        }
        req
    }

    #[test]
    fn test_valid_bearer_token() {
        let mut interceptor = BearerTokenInterceptor::new(TEST_TOKEN.to_string()).unwrap();
        let req = make_request(Some("Bearer 0123456789abcdef0123456789abcdef"));
        assert!(interceptor.call(req).is_ok());
    }

    #[test]
    fn test_invalid_bearer_token() {
        let mut interceptor = BearerTokenInterceptor::new(TEST_TOKEN.to_string()).unwrap();
        let req = make_request(Some("Bearer wrong-token-0123456789abcdef01234"));
        let result = interceptor.call(req);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_missing_authorization_header() {
        let mut interceptor = BearerTokenInterceptor::new(TEST_TOKEN.to_string()).unwrap();
        let req = make_request(None);
        let result = interceptor.call(req);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_wrong_scheme() {
        let mut interceptor = BearerTokenInterceptor::new(TEST_TOKEN.to_string()).unwrap();
        let req = make_request(Some("Basic dXNlcjpwYXNz"));
        let result = interceptor.call(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_token() {
        let mut interceptor = BearerTokenInterceptor::new(TEST_TOKEN.to_string()).unwrap();
        let req = make_request(Some("Bearer "));
        let result = interceptor.call(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_too_short() {
        let result = BearerTokenInterceptor::new("short".to_string());
        match result {
            Err(err) => assert!(err.contains("at least 32 bytes")),
            Ok(_) => panic!("expected error for short token"),
        }
    }
}

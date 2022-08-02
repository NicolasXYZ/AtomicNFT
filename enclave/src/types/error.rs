use sgx_types::sgx_status_t;
use std::string::String;

use hkdf::InvalidLength;

quick_error! {
    #[derive(Debug)]
    pub enum CryptoError {
        XorNotEqualLength
        KeyError
        SgxCryptoLibError(err: sgx_status_t) {
            description(err.as_str())
            display("Error {}", err)
            from()
            cause(err)
        }
        Other(err: String) {
            description(err)
            display("Aggregation error {}", err)
            from()
        }
        HKDFErr {
            from(InvalidLength)
            display("InvalidLength")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum DcNetError {
        Crypto(err: CryptoError) {
            from()
            description("crypto error")
            display("crypto error: {}", err)
            cause(err)
        }
        AggregationError(err: &'static str) {
            description(err)
            display("Aggregation error {}", err)
            from()
        }
    }
}

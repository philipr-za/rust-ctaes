# rust-ctaes

A Rust FFI wrapper for CTAES library from <https://github.com/bitcoin-core/ctaes>

The CTAES Library provides a constant time implementation of the AES algorithm. For completeness
this crate provides the interface to the AES-ECB methods, but they should not be used. Rather,
use the AES-CBC methods.

The crate also provides a Padding utility implementation to help the user prepare, pad and unpad
buffers. Zero Padding and PKCS7 padding implementations are provided
# ecc-rs

Implementation of Elliptic Curves Cryptography in Rust, study project, don't use for real world crypto.

General testing: 

<code>cargo test</code> for all tests 

<code>cargo test --test test_name --release</code> test name can be: finite_field_tests, elliptic_curve_tests, ecdsa_tests, ecdhe_tests

1. Elliptic curve in Weierstress form y^2 = x^3 + ax + b over Finite Field Fp
2. <b>ECDSA</b>(Elliptic Curve Digital Signature Algorithm)

3. <b>ECDHE</b>(Ellpitic Curve Diffie Hellman Ephemeral,  with cofactor h = 1, more on this http://www.secg.org/sec1-v2.pdf,
   implementation from the book <b>Elliptic Curves: Number Theory and Cryptography, 2nd Edition, Lawrence C. Washington, Page 170</b> 

- To run the demo: 

<code> cargo build</code>

<code> cargo run --bin ecdhe_demo </code>
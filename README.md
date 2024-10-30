# ecception

Implementation of Elliptic Curve Cryptography library in Rust.

1. <b>Elliptic curves</b> in Weierstress form y^2 = x^3 + ax + b over Finite Field(Fp) 
2. <b>ECDSA</b>(Elliptic Curve Digital Signature Algorithm)
3. <b>ECDHE</b>(Ellpitic Curve Diffie Hellman Ephemeral [1] (use Elliptic curves with cofactor h = 1, e.g. NIST P-521 [3], more on this [2])
4. <b>ECIES</b> (Elliptic Curve Integrated Encryption Scheme, [4]
5. <b>KDF2</b> (Key derivation function 2), [5]
6. <b>Chaum Pedersen </b>
7. <b>GGM</b>(The Goldreich-Goldwasser-Micali Construction)[9]


Run all tests: 

```bash
cargo test
```

For individual tests: <b>test_name</b> options = finite_field_tests, elliptic_curve_tests, ecdsa_tests, ecdhe_test, ecies_tests, chaum_pedersen_tests, kdf2_tests
```bash 
cargo test --test test_name --release
```

<b>Resources</b>: 
1. Elliptic Curves: Number Theory and Cryptography, 2nd Edition, Lawrence C. Washington, https://www.iacr.org/books/2010_tf_Washington_ECC.pdf
2. SEC 1: Elliptic Curve Cryptography, http://www.secg.org/sec1-v2.pdf
3. NIST P-512 parameters,  https://neuromancer.sk/std/nist/P-521
4. A Survey of the Elliptic Curve Integrated Encryption Scheme, https://www.researchgate.net/publication/255970113_A_Survey_of_the_Elliptic_Curve_Integrated_Encryption_Scheme
5. DRAFT ISO/IEC 18033-2, https://www.shoup.net/iso/std4.pdf
6. https://github.com/conz27/crypto-test-vectors/tree/master
7. https://www.rfc-editor.org/rfc/rfc5114.txt
8. https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
9. https://crypto.stanford.edu/pbc/notes/crypto/ggm.html

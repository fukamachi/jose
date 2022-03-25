# jose

[![Quicklisp dist](http://quickdocs.org/badge/jose.svg)](http://quickdocs.org/jose/)
[![Build Status](https://travis-ci.org/fukamachi/jose.svg?branch=master)](https://travis-ci.org/fukamachi/jose)
[![Coverage Status](https://coveralls.io/repos/fukamachi/jose/badge.svg?branch=master)](https://coveralls.io/r/fukamachi/jose)

A JSON Object Signing and Encryption (JOSE) implementation for Common Lisp.

## Usage

### HMAC

```common-lisp
(defvar *key* (ironclad:ascii-string-to-byte-array "my$ecret"))

(defvar *token*
  (jose:encode :hs256 *key* '(("hello" . "world"))))

*token*
;=> "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.Vr0VKL9WHX9lUPWzrE0DX4fEvl0_CgnKlzI2mWiro8E"

(jose:decode :hs256 *key* *token*)
;=> (("hello" . "world"))
;   (("alg" . "HS256") ("typ" . "JWT"))

;; Decoding without signature verification.
(jose:inspect-token *token*)
;=> (("hello" . "world"))
;   (("alg" . "HS256") ("typ" . "JWT"))
;   #(142 123 175 222 84 4 134 19 70 182 50 209 29 113 176 40 82 42 241 90 230 91
;     176 235 254 57 221 93 97 220 6 101)
```

### RSA

For RSA algorithm, the key must be an instance of Ironclad public/private key, that can be generated with `ironclad:generate-key-pair`.

To read from OpenSSH key files, use [cl-ssh-keys](https://github.com/dnaeon/cl-ssh-keys). To parse ASN.1 keys, [asn1](https://github.com/fukamachi/asn1) library will help.

```common-lisp
(defvar *private-key*
  (ironclad:generate-key-pair :rsa :num-bits 2048))

(defvar *token*
  (jose:encode :rs256 *private-key* '(("hello" . "world"))))
```

## Supported Algorithms

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* PS256
* PS384
* PS512
* none

## See Also

* [JOSE Working Group](https://datatracker.ietf.org/wg/jose/about/)

## Author

* Eitaro Fukamachi (e.arrows@gmail.com)

## Copyright

Copyright (c) 2017 Eitaro Fukamachi (e.arrows@gmail.com)

## License

Licensed under the BSD 2-Clause License.

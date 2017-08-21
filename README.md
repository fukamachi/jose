# jose

[![Quicklisp dist](http://quickdocs.org/badge/jose.svg)](http://quickdocs.org/jose/)
[![Build Status](https://travis-ci.org/fukamachi/jose.svg?branch=master)](https://travis-ci.org/fukamachi/jose)
[![Coverage Status](https://coveralls.io/repos/fukamachi/jose/badge.svg?branch=master)](https://coveralls.io/r/fukamachi/jose)

A JSON Object Signing and Encryption (JOSE) implementation for Common Lisp.

## Usage

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

## Recommendation

The original [Ironclad](https://github.com/froydnj/ironclad) doesn't generate a portable signature and cannot verify tokens which is made by other libraries.

If Jose has to exchange JWTs with other libraries, using my fork of Ironclad is recommended.

* https://github.com/fukamachi/ironclad

## Author

* Eitaro Fukamachi (e.arrows@gmail.com)

## Copyright

Copyright (c) 2017 Eitaro Fukamachi (e.arrows@gmail.com)

## License

Licensed under the BSD 2-Clause License.

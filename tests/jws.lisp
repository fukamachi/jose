(defpackage #:jose/tests/jws
  (:use #:cl
        #:rove
        #:jose/jws))
(in-package #:jose/tests/jws)

(defvar *secret*
  (map '(simple-array (unsigned-byte 8) (*))
       #'char-code "secret"))

(deftest test-verify-token
  (let ((token
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (multiple-value-bind (validp payload headers)
        (jose/jws:verify :hs256 *secret* token)
      (ok validp)
      (ok (vectorp payload))
      (ok (consp headers)))))

(deftest test-not-enough-segments
  (let ((token
          "eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (signals
            (jose/jws:verify :hs256 *secret* token)
            'jose/errors:jws-invalid-format))))

(deftest test-header-invalid-padding
  (let ((token
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9A.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (not (jose/jws:verify :hs256 *secret* token)))))

(deftest test-header-not-json
  (let ((token
          "dGVzdA.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (signals
            (jose/jws:verify :hs256 *secret* token)
            'jose/errors:jws-invalid-format))))

(deftest test-claims-invalid-padding
  (let ((token
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AeyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (not (jose/jws:verify :hs256 *secret* token)))))

(deftest test-claims-not-json
  (let ((token
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.dGVzdA.3MkJVAT-b30XkB4EwrYeqShkwa_GrHcJ1fp8xD1MoYk"))
    (ok (jose/jws:verify :hs256 *secret* token))))

(defvar *public-key*
  (asdf:system-relative-pathname :jose #P"tests/keys/rsa-pub.pem"))
(defvar *private-key*
  (asdf:system-relative-pathname :jose #P"tests/keys/rsa-priv.pem"))

(deftest test-rsa
  (let ((token
          (jose/jws:sign :rs256 (pem:read-from-file *private-key*) "test")))
    (ok (jose/jws:verify :rs256 (pem:read-from-file *public-key*) token))))

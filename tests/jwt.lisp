(defpackage #:jose/tests/jwt
  (:use #:cl
        #:rove
        #:jose/jwt))
(in-package #:jose/tests/jwt)

(defvar *secret*
  (map '(simple-array (unsigned-byte 8) (*))
       #'char-code "secret"))

(deftest test-number-keys-not-int
  (dolist (key '("iat" "nbf" "exp"))
    (let ((token
            (jose/jwt:encode :hs256 *secret* `((,key . "test")))))
      (ok (signals
              (jose/jwt:decode :hs256 *secret* token)
              'jose/errors:jwt-claims-error)))))

(deftest test-nbf
  (let ((token
          (jose/jwt:encode :hs256 *secret*
                           `(("nbf" . ,(- (- (get-universal-time) 2208988800) 1000))))))
    (ok (jose/jwt:decode :hs256 *secret* token))))

(deftest test-nbf-in-future
  (let ((token
          (jose/jwt:encode :hs256 *secret*
                           `(("nbf" . ,(+ (- (get-universal-time) 2208988800) 1000))))))
    (ok (signals
            (jose/jwt:decode :hs256 *secret* token)
            'jose/errors:jwt-claims-not-yet-valid))
    (ok (handler-bind ((jose/errors:jwt-claims-not-yet-valid #'continue))
          (jose/jwt:decode :hs256 *secret* token)))))

(deftest test-exp
  (let ((token
          (jose/jwt:encode :hs256 *secret*
                           `(("exp" . ,(+ (- (get-universal-time) 2208988800) 1000))))))
    (ok (jose/jwt:decode :hs256 *secret* token))))

(deftest test-exp-in-past
  (let ((token
          (jose/jwt:encode :hs256 *secret*
                           `(("exp" . ,(- (- (get-universal-time) 2208988800) 1000))))))
    (ok (signals
            (jose/jwt:decode :hs256 *secret* token)
            'jose/errors:jwt-claims-expired))
    (ok (handler-bind ((jose/errors:jwt-claims-expired #'continue))
          (jose/jwt:decode :hs256 *secret* token)))))

(deftest test-skip-verify
  (multiple-value-bind (claims headers)
      (jose/jwt:decode :hs256 *secret*
                       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.3MkJVAT-b30XkB4EwrYeqShkwa_GrHcJ1fp8xD1MoYk"
                       :verifyp nil)
    (ok (equal claims '(("a" . "b"))))
    (ok (equal headers '(("typ" . "JWT") ("alg" . "HS256"))))))

(defsystem "jose"
  :class :package-inferred-system
  :version "0.1.0"
  :author "Eitaro Fukamachi"
  :license "BSD 2-Clause"
  :description "JSON Object Signing and Encryption (JOSE) implementation"
  :depends-on ("jose/main")
  :in-order-to ((test-op (test-op "jose/tests"))))

(defsystem "jose/tests"
  :class :package-inferred-system
  :depends-on ("rove"
               "jose/tests/jws"
               "jose/tests/jwt")
  :perform (test-op (o c) (symbol-call :rove '#:run c)))

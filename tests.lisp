(defpackage #:jose/tests
  (:use #:cl)
  (:import-from #:rove)
  (:import-from #:jose/tests/jws))
(in-package #:jose/tests)

(defmethod asdf:perform :after ((op asdf:test-op) (system (eql (asdf:find-system :jose/tests))))
  (rove:run system))

(defpackage #:jose/errors
  (:use #:cl)
  (:export #:jose-error
           #:jws-error
           #:jwt-error
           #:jws-verification-error
           #:jws-invalid-format
           #:jwt-claims-error
           #:jwt-claims-not-yet-valid
           #:jwt-claims-expired))
(in-package #:jose/errors)

(define-condition jose-error (error) ())

(define-condition jws-error (jose-error) ())
(define-condition jwt-error (jose-error) ())

(define-condition jws-verification-error (jws-error)
  ((token :initarg :token)))
(define-condition jws-invalid-format (jws-error)
  ((token :initarg :token)))

(define-condition jwt-claims-error (jwt-error)
  ((key :initarg :key)
   (value :initarg :value)))
(define-condition jwt-claims-not-yet-valid (jwt-claims-error) ())
(define-condition jwt-claims-expired (jwt-claims-error) ())

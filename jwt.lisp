(defpackage #:jose/jwt
  (:use #:cl
        #:jose/errors)
  (:import-from #:jose/jws)
  (:import-from #:jonathan
                #:to-json
                #:<jonathan-error>)
  (:import-from #:trivial-utf-8
                #:utf-8-bytes-to-string)
  (:import-from #:alexandria
                #:ensure-list)
  (:import-from #:assoc-utils
                #:aget)
  (:export #:encode
           #:inspect-token
           #:decode))
(in-package #:jose/jwt)

(defun encode (algorithm key claims &key headers)
  (jose/jws:sign algorithm key (jojo:to-json claims :from :alist) :headers headers))

(defun now ()
  (- (get-universal-time) 2208988800))

(defun check-iat (claims)
  (let ((iat (assoc "iat" claims :test #'string=)))
    (when iat
      (unless (integerp (cdr iat))
        (error 'jwt-claims-error :key "iat" :value (cdr iat))))))

(defun check-nbf (claims)
  (let ((nbf (assoc "nbf" claims :test #'string=)))
    (when nbf
      (unless (integerp (cdr nbf))
        (error 'jwt-claims-error :key "nbf" :value (cdr nbf)))
      (when (< (now) (cdr nbf))
        (cerror "Ignore nbf" 'jwt-claims-not-yet-valid)))
    t))

(defun check-exp (claims)
  (let ((exp (assoc "exp" claims :test #'string=)))
    (when exp
      (unless (integerp (cdr exp))
        (error 'jwt-claims-error :key "exp" :value (cdr exp)))
      (when (< (cdr exp) (now))
        (cerror "Ignore exp" 'jwt-claims-expired)))
    t))

(defun check-iss (claims issuer)
  (let ((issuers (ensure-list issuer)))
    (when issuers
      (unless (find (aget claims "iss") issuers :test #'equal)
        (error 'jwt-claims-error :key "iss" :value (aget claims "iss"))))
    t))

(defun check-aud (claims audience)
  (let ((audiences (ensure-list audience)))
    (when audiences
      (unless (find (aget claims "aud") audiences :test #'equal)
        (error 'jwt-claims-error :key "aud" :value (aget claims "aud"))))
    t))

(defun check-sub (claims subject)
  (let ((subjects (ensure-list subject)))
    (when subjects
      (unless (find (aget claims "sub") subjects :test #'equal)
        (error 'jwt-claims-error :key "sub" :value (aget claims "sub"))))
    t))

(defun check-jti (claims)
  (let ((jti (assoc "jti" claims :test #'string=)))
    (when jti
      (unless (stringp (cdr jti))
        (error 'jwt-claims-error :key "jti" :value (cdr jti))))
    t))

(defun check-claims (claims &key issuer audience subject)
  (check-iat claims)
  (check-nbf claims)
  (check-exp claims)
  (check-iss claims issuer)
  (check-aud claims audience)
  (check-sub claims subject)
  (check-jti claims))

(defun inspect-token (token)
  "Decodes the TOKEN without signature verification."
  (multiple-value-bind (headers payload signature)
      (jose/jws:decode-token token)
    (let ((claims (handler-case
                      (jojo:parse (utf-8-bytes-to-string payload)
                                  :as :alist)
                    (jojo:<jonathan-error> ()
                      (error 'jws-invalid-format
                             :token token)))))
      (values claims headers signature))))

(defun decode (algorithm key token
               &key
                 issuer
                 audience
                 subject)
  (multiple-value-bind (payload headers)
      (jose/jws:verify algorithm key token)
    (let ((claims (nreverse
                   (handler-case
                       (jojo:parse (utf-8-bytes-to-string payload)
                                   :as :alist)
                     (jojo:<jonathan-error> ()
                       (error 'jws-invalid-format
                              :token token))))))
      (check-claims claims
                    :issuer issuer
                    :audience audience
                    :subject subject)
      (values claims headers))))

(defpackage #:jose/jws
  (:use #:cl
        #:jose/base64
        #:jose/errors)
  (:import-from #:ironclad)
  (:import-from #:jonathan
                #:to-json
                #:parse)
  (:import-from #:alexandria
                #:alist-hash-table)
  (:import-from #:split-sequence
                #:split-sequence)
  (:import-from #:assoc-utils
                #:aget)
  (:export #:sign
           #:verify))
(in-package #:jose/jws)

(defun hmac-sign-message (digest-spec secret-key message &key (start 0) (end (length message)))
  (let ((hmac (ironclad:make-hmac secret-key digest-spec)))
    (ironclad:update-hmac hmac message :start start :end end)
    (ironclad:hmac-digest hmac)))

(defun rsa-sign-message (digest-spec private-key message &key (start 0) (end (length message)))
  (ironclad:sign-message private-key
                         (ironclad:digest-sequence digest-spec message
                                                   :start start :end end)))

(defun hmac-verify-signature (digest-spec verification-key message signature
                              &key (start 0) (end (length message)))
  (equalp (hmac-sign-message digest-spec verification-key message
                             :start start :end end)
          signature))

(defun rsa-verify-signature (digest-spec public-key message signature
                             &key (start 0) (end (length message)))
  (ironclad:verify-signature public-key
                             (ironclad:digest-sequence digest-spec message :start start :end end)
                             signature))

(defun encode-headers (algorithm additional-headers)
  (base64url-encode
   (jojo:to-json
    (alist-hash-table
     `(,@additional-headers
       ("typ" . "JWT")
       ("alg" . ,(if (eq algorithm :none)
                     "none"
                     (symbol-name algorithm))))
     :test 'equal))))

(defun get-signature (algorithm key message &key (start 0) (end (length message)))
  (let ((message (ironclad:ascii-string-to-byte-array message :start start :end end)))
    (ecase algorithm
      (:hs256
       (hmac-sign-message :sha256 key message :start start :end end))
      (:hs384
       (hmac-sign-message :sha384 key message :start start :end end))
      (:hs512
       (hmac-sign-message :sha512 key message :start start :end end))
      (:rs256
       (rsa-sign-message :sha256 key message :start start :end end))
      (:rs384
       (rsa-sign-message :sha384 key message :start start :end end))
      (:rs512
       (rsa-sign-message :sha512 key message :start start :end end))
      (:none ""))))

(defun sign (algorithm key payload &key headers)
  (let* ((encoded-headers (encode-headers algorithm headers))
         (encoded-payload (base64url-encode payload))
         (message (format nil "~A.~A" encoded-headers encoded-payload)))
    (format nil "~A.~A"
            message
            (base64url-encode (get-signature algorithm key message)))))

(defun %verify-message (algorithm key message signature &key (start 0) (end (length message)))
  (ecase algorithm
    (:hs256
     (hmac-verify-signature :sha256 key message signature :start start :end end))
    (:hs384
     (hmac-verify-signature :sha384 key message signature :start start :end end))
    (:hs512
     (hmac-verify-signature :sha512 key message signature :start start :end end))
    (:rs256
     (rsa-verify-signature :sha256 key message signature :start start :end end))
    (:rs384
     (rsa-verify-signature :sha384 key message signature :start start :end end))
    (:rs512
     (rsa-verify-signature :sha512 key message signature :start start :end end))
    (:none (zerop (length signature)))))

(defun check-alg (headers algorithm)
  (equal (aget headers "alg")
         (if (eq algorithm :none)
             "none"
             (symbol-name algorithm))))

(defun verify (algorithm key token)
  (destructuring-bind (&optional headers payload signature &rest rest)
      (split-sequence #\. token)
    (unless (and headers
                 payload
                 signature
                 (null rest))
      (error 'jws-invalid-format :token token))
    (macrolet ((safety (&body body)
                 `(handler-case (progn ,@body)
                    (error () (error 'jws-invalid-format :token token)))))
      (let ((message-end (- (length token) (length signature) 1)))
        (let ((message (safety
                        (ironclad:ascii-string-to-byte-array
                         token
                         :start 0 :end message-end)))
              (headers (safety (jojo:parse (base64url-decode headers :octets nil) :as :alist)))
              (payload (safety (base64url-decode payload)))
              (signature (safety (base64url-decode signature))))
          (values
           (and (%verify-message algorithm key message signature
                                 :start 0 :end message-end)
                (check-alg headers algorithm))
           payload
           headers))))))

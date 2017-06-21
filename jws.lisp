(defpackage #:jose/jws
  (:use #:cl
        #:jose/errors)
  (:import-from #:ironclad)
  (:import-from #:jonathan
                #:to-json)
  (:import-from #:cl-base64
                #:string-to-base64-string
                #:usb8-array-to-base64-string
                #:base64-string-to-string
                #:base64-string-to-usb8-array)
  (:import-from #:alexandria
                #:alist-hash-table)
  (:import-from #:split-sequence
                #:split-sequence)
  (:export #:sign
           #:verify))
(in-package #:jose/jws)

(defun hmac-sign-message (digest-spec secret-key message)
  (let ((hmac (ironclad:make-hmac secret-key digest-spec)))
    (ironclad:update-hmac hmac message)
    (ironclad:hmac-digest hmac)))

(defun rsa-sign-message (digest-spec private-key message)
  (ironclad:sign-message private-key
                         (ironclad:digest-sequence digest-spec message)))

(defun hmac-verify-signature (digest-spec verification-key message signature)
  (equalp (hmac-sign-message digest-spec verification-key message) signature))

(defun rsa-verify-signature (digest-spec public-key message signature)
  (ironclad:verify-signature public-key
                             (ironclad:digest-sequence digest-spec message)
                             signature))

(defun encode-headers (algorithm additional-headers)
  (string-to-base64-string
   (jojo:to-json
    (alist-hash-table
     `(,@additional-headers
       ("typ" . "JWT")
       ("alg" . ,(if (eq algorithm :none)
                     "none"
                     (symbol-name algorithm))))
     :test 'equal))))

(defun encode-payload (payload)
  (etypecase payload
    (string (string-to-base64-string payload))
    ((array (unsigned-byte 8) (*)) (usb8-array-to-base64-string payload))))

(defun get-signature (algorithm key message)
  (let ((message (ironclad:ascii-string-to-byte-array message)))
    (ecase algorithm
      (:hs256
       (hmac-sign-message :sha256 key message))
      (:hs384
       (hmac-sign-message :sha384 key message))
      (:hs512
       (hmac-sign-message :sha512 key message))
      (:rs256
       (rsa-sign-message :sha256 key message))
      (:rs384
       (rsa-sign-message :sha384 key message))
      (:rs512
       (rsa-sign-message :sha512 key message))
      (:none ""))))

(defun sign (algorithm key payload &key headers)
  (let* ((encoded-headers (encode-headers algorithm headers))
         (encoded-payload (encode-payload payload))
         (message (format nil "~A.~A" encoded-headers encoded-payload)))
    (format nil "~A.~A"
            message
            (usb8-array-to-base64-string (get-signature algorithm key message)))))

(defun verify (algorithm key token)
  (destructuring-bind (&optional headers payload signature &rest rest)
      (split-sequence #\. token)
    (unless (and headers
                 payload
                 signature
                 (null rest))
      (error 'jws-invalid-format :token token))
    (let ((message
            (ironclad:ascii-string-to-byte-array
             (subseq token 0 (- (length token) (length signature) 1))))
          (signature (base64-string-to-usb8-array signature)))
      (values
       (ecase algorithm
         (:hs256
          (hmac-verify-signature :sha256 key message signature))
         (:hs384
          (hmac-verify-signature :sha384 key message signature))
         (:hs512
          (hmac-verify-signature :sha512 key message signature))
         (:rs256
          (rsa-verify-signature :sha256 key message signature))
         (:rs384
          (rsa-verify-signature :sha384 key message signature))
         (:rs512
          (rsa-verify-signature :sha512 key message signature))
         (:none (zerop (length signature))))
       (base64-string-to-string payload)
       (base64-string-to-string headers)))))

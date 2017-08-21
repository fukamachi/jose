(defpackage #:jose/jws
  (:use #:cl
        #:jose/base64
        #:jose/errors)
  (:import-from #:ironclad)
  (:import-from #:jonathan
                #:to-json
                #:parse)
  (:import-from #:split-sequence
                #:split-sequence)
  (:import-from #:assoc-utils
                #:aget)
  (:export #:sign
           #:verify
           #:decode-token))
(in-package #:jose/jws)

(defun hmac-sign-message (digest-spec secret-key message &key (start 0) (end (length message)))
  (let ((hmac (ironclad:make-hmac secret-key digest-spec)))
    (ironclad:update-hmac hmac message :start start :end end)
    (ironclad:hmac-digest hmac)))

(defun rsa-sign-message (digest-spec private-key message &key (start 0) (end (length message)) pss)
  (if pss
      (ironclad:sign-message private-key
                             message
                             :start start :end end
                             :pss digest-spec)
      (ironclad:sign-message private-key
                             (ironclad:digest-sequence digest-spec message
                                                       :start start :end end))))

(defun hmac-verify-signature (digest-spec verification-key message signature
                              &key (start 0) (end (length message)))
  (equalp (hmac-sign-message digest-spec verification-key message
                             :start start :end end)
          signature))

(defun rsa-verify-signature (digest-spec public-key message signature
                             &key (start 0) (end (length message)) pss)
  (handler-case
      (if pss
          (ironclad:verify-signature public-key
                                     message
                                     signature
                                     :start start :end end
                                     :pss digest-spec)
          (ironclad:verify-signature public-key
                                     (ironclad:digest-sequence digest-spec message :start start :end end)
                                     signature))
    (error (e)
      (warn "~A" e)
      nil)))

(defun encode-headers (algorithm additional-headers)
  (base64url-encode
   (jojo:to-json
    `(,@additional-headers
      ("alg" . ,(if (eq algorithm :none)
                    "none"
                    (symbol-name algorithm)))
      ("typ" . "JWT"))
    :from :alist)))

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
      (:ps256
       (rsa-sign-message :sha256 key message :start start :end end :pss t))
      (:ps384
       (rsa-sign-message :sha384 key message :start start :end end :pss t))
      (:ps512
       (rsa-sign-message :sha512 key message :start start :end end :pss t))
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
    (:ps256
     (rsa-verify-signature :sha256 key message signature :start start :end end :pss t))
    (:ps384
     (rsa-verify-signature :sha384 key message signature :start start :end end :pss t))
    (:ps512
     (rsa-verify-signature :sha512 key message signature :start start :end end :pss t))
    (:none (zerop (length signature)))))

(defun check-alg (headers algorithm)
  (equal (aget headers "alg")
         (if (eq algorithm :none)
             "none"
             (symbol-name algorithm))))

(defun decode-token (token)
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
      (let ((headers (safety (nreverse
                              (jojo:parse (base64url-decode headers :as :string) :as :alist))))
            (payload (safety (base64url-decode payload)))
            (signature (safety (base64url-decode signature))))
        (values headers
                payload
                signature)))))

(defun verify (algorithm key token)
  (multiple-value-bind (headers payload signature)
      (decode-token token)
    (let* ((message-end (position #\. token :from-end t))
           (message
             (ironclad:ascii-string-to-byte-array token
                                                  :start 0 :end message-end)))
      (unless (and (%verify-message algorithm key message signature
                                    :start 0 :end message-end)
                   (check-alg headers algorithm))
        (cerror "Skip signature verification"
                'jws-verification-error :token token))

      (values payload headers))))

(defpackage #:jose/base64
  (:use #:cl)
  (:import-from #:cl-base64
                #:integer-to-base64-string
                #:string-to-base64-string
                #:usb8-array-to-base64-string
                #:base64-string-to-integer
                #:base64-string-to-usb8-array
                #:base64-string-to-string)
  (:export #:base64url-encode
           #:base64url-decode))
(in-package #:jose/base64)

(defun add-padding (input)
  (let ((rem (mod (length input) 4)))
    (if (< 0 rem)
        (let ((res (make-array (+ (length input) (- 4 rem))
                               :element-type 'character
                               :initial-element base64::*uri-pad-char*)))
          (replace res input)
          res)
        input)))

(deftype octets (&optional (len '*)) `(simple-array (unsigned-byte 8) (,len)))

(defun base64url-encode (input)
  (string-right-trim
   (list base64::*uri-pad-char*)
   (etypecase input
     (integer
      (integer-to-base64-string input :uri t))
     (string
      (string-to-base64-string input :uri t))
     (octets
      (usb8-array-to-base64-string input :uri t)))))

(defun base64url-decode (input &key (as :octets))
  (check-type input string)
  (ecase as
    (:octets (base64-string-to-usb8-array (add-padding input) :uri t))
    (:string (base64-string-to-string (add-padding input) :uri t))
    (:integer (base64-string-to-integer (add-padding input) :uri t))))

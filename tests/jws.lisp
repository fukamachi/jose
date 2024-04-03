(defpackage #:jose/tests/jws
  (:use #:cl
        #:rove
        #:pem
        #:jose/jws))
(in-package #:jose/tests/jws)

(defvar *secret*
  (map '(simple-array (unsigned-byte 8) (*))
       #'char-code "secret"))

(deftest test-verify-token
  (let ((token
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (multiple-value-bind (payload headers)
        (jose/jws:verify :hs256 *secret* token)
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
    (ok (signals
            (jose/jws:verify :hs256 *secret* token)
            'jose/errors:jws-invalid-format))))

(deftest test-header-not-json
  (let ((token
          "dGVzdA.eyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (signals
            (jose/jws:verify :hs256 *secret* token)
            'jose/errors:jws-invalid-format))))

(deftest test-claims-invalid-padding
  (let ((token
          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AeyJhIjoiYiJ9.jiMyrsmD8AoHWeQgmxZ5yq8z0lXS67_QGs52AzC8Ru8"))
    (ok (signals
            (jose/jws:verify :hs256 *secret* token)
            'jose/errors:jws-invalid-format))))

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

;; You may be interested in this site: http://kjur.github.io/jsjws/mobile/tool_jwt.html
(deftest test-rsa-verify-with-reference-vector
  (let ((token256 "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyODU0ODIzMSwiZXhwIjoxNTI4NTUxODMxLCJpYXQiOjE1Mjg1NDgyMzEsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.Krl4oBv0ErVDq9bXKHQXYyoTi-jAohWkXAnuHtc5VrYmxmeq1ss4dsJYR27vJrJ7XWNVOa0ttpcI1BPk1J3S2FL4sOCkoeHI03tNB6a7VIeEZnSn2BWv_ISfH3RktyV4I8doA5Rpc0UXePlWYfQasr-qhXzxXPoD254IB-Xzji0tgiE4apCE9WT6m2yIwVF6YcVg_h_sfIDTFlOZEAq9NW6bcxRztEgQOnsCiBUMwlNLsOi3tRNwvbDN1yDL9jurFUjxoYY8F53XfEaxFIeejQTdCXs2taO5jATD65gtkuX4f8iIFZvH_SC4cNIg0wvRaG0xebJPCq33ExwNiMAutg")
        (token384 "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyODU0ODMzOSwiZXhwIjoxNTI4NTUxOTM5LCJpYXQiOjE1Mjg1NDgzMzksImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.DY_FKB8c5lufKSA80D4Yb6ahaXcfNDlW9YDNka9ZAOKM2FbI4nR7XCwqjH66FDY0UDgBnpWrmXGLuP5aPU9yGM04mUr__dcQPYRBwoxmmnimuSBBVtYXbTNxdcIAP6ZBlYct3YRnAyZcl-MnFbQZ8FXxD1hHs_wyNcx2QgO267JGlqjRMAZK0g04wM2YU0v-BUdz5Q6c0j4fXDGs-qOGqGgacuYisFheiw2RF2yayd4ruvupfliGMgOXlgeIZ2kX3TjNulHM5YPOeUhwWn6lWY4QW9m-RWtTKS4S8gB-nK9ZsU6iIZvvibr3LezIdvrqR8qju0P28EDvDfslCN_ynw")
        (token512 "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyODU0ODQzMywiZXhwIjoxNTI4NTUyMDMzLCJpYXQiOjE1Mjg1NDg0MzMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.VOB7j5eC_0G_zC6AXjKh-KIZPzol8PLJvzctQcp9Zwufsg7iRgVwad-hCGRUWYefOtwJAf8Kc4jpCIWP5iihKFfeKhk8_s2xh4DOr9SuVd5xR2SH7-Yh0Z7dm54JUpDVBNYPbLi0jwzslqAOqm4h7aOmOed4SGyCkRW9xx8KK_IV2h-tCgySn10pXlanq8UQtLeeBHXNBfcpzY2oyGPFz_RQ1Cz0K0t_rf1Gdruokfk8P2WjBSigrRWjfplAxiiMvJv9KwZt0smomGyK-qm_93TsdWH2UnVj-vHFHdHDdM4gEalsrt3eliICDnZ5EJj3NBm41yuy_ei3qASF7pOS-Q")
        (token256-3920 "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyODYwMDIzMiwiZXhwIjoxNTI4NjAzODMyLCJpYXQiOjE1Mjg2MDAyMzIsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.qJPkVWZgrJ73avNHYD0ZX2cv7pXJUD6as7xgXA8yANpztQFOCQc5ZiBuAdPQ0n1e50xHZ0g9ozOCUcNvpXcjnIoB-vvFgg17wrf-jMfeLRBSnwRcUJrB11WwZyl6IxexqSnptJsetLQtda4CSDuZ6kGPvoLEWs93gA_m9BvZ1HhiArlwbHtSPcKvYfv36FnJyfJRCqbycNPzvDiViSh5Fy_yKJicd-1mYi98b0Hpguf6vP0TtF48fl7w3_UG1SOYd0BaRuE7mOheenY5U-iGDnRoU-g7yibSIkdnXYr6kyQihrzpf2e_TnpYbGvYU42CqZthGZu2e0GwtTKV800cmkxUk_SzruGCxafwDa-o9lY9hgZEg8sQKd_tCW4A_Gc8JvPxktQWnDMzTs94a8PQyD0eCcz-jwhTVMqj2k1PnJT4yXUKKAfRPTfcOZZHfV0mbzkZoRRsn_p8KvVAcWYMq2BYOWge50tjD5ycdP08VEkigCMKLYE0ySkmd3TlZEqy-v4GeeSmMaRyBv8MEY9GptKpELIHMLsCbeCx7MlRPBUPA5wTqGbs59FSWLd9QPtuDQ4PSlEd7DKt7LdivM1EXiQa1dPJ6a_L3h2-HOusckdciJP8azMw197g6jsbcR06eO_ZOzI-HdrH7A")
        (rsa-3920bits (asdf:system-relative-pathname :jose #P"tests/keys/rsa-3920bits-pub.pem"))
        (token256-3925 "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTUyODU5OTI5NywiZXhwIjoxNTI4NjAyODk3LCJpYXQiOjE1Mjg1OTkyOTcsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.E5MwImyxmWnzlGXs_QYK_vVn6mlrLVb1w-L4OCayMJpTpgvklwM-PXHVXQ-Vup2fVY7Y0yuDyhXVoKcsok8YOiEgHO_h_CP2P9BCCyWXqTrd_5LaItWBfidAXNW9ot0K-1DwdMJjofR-OeOfNiT9yQuo0NvKtpoq_QcBlQklAQ7vOUKwzLMLXTMlDDneG6AmKFdQgwsUclmJOzyU9_3l-p7s0y9d1nqzAEFdMDnEmRR-8MwCIRRKyQmuG2gl2SBK5_dGdOqZxr0VEAD0SB-uyycGUR6-p8Tw5KMo4_641pjIXXjpFvJ6q_imwfgA1VOJQ4KCAjSORMQgQbEI2ATDKbPE-WDPcwdbrQwGIvaUsMQtZrbYCFRPLCriqHXebzLvbGdfV8QvlTkm-26zlPcgLn9K6STHPigdFlH8_vAahInTrGhOtLPALW4psxVkCZ7e81ZoSHcwuc4Tue2YCEVxTL2GUMA-LPc2szm7e9zUltguQacW95VpUmoOuTCYvDnrw7iYnvvg4cPhibvx1Xkqt6mN0oHc5VB8cN-iL8cF_wz0T2yk7rFTtNYrpLn1NbOvg1TlfSojyLNz2KwilQSx5-Htg_HPr7UnLBQzidDbF9v_lBIamksaEp6xLvMNqBXb3RdeReXvoGZH4Ps")
        (rsa-3925bits (asdf:system-relative-pathname :jose #P"tests/keys/rsa-3925bits-pub.pem")))
    (ok (jose/jws:verify :rs256 (pem:read-from-file *public-key*) token256))
    (ok (jose/jws:verify :rs384 (pem:read-from-file *public-key*) token384))
    (ok (jose/jws:verify :rs512 (pem:read-from-file *public-key*) token512))
    (ok (jose/jws:verify :rs256 (pem:read-from-file rsa-3920bits) token256-3920))
    ;; This test SHOULD be ok, but it failed miserably because of key size not to be a multiples of 8?
    (ok (signals
         (jose/jws:verify :rs256 (pem:read-from-file rsa-3925bits) token256-3925)
         'jose/errors:jws-verification-error))))

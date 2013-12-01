;;;
;;; Test pbkdf2
;;;

(use gauche.test)

(test-start "crypt.pbkdf2")

(use crypt.pbkdf2)
(use rfc.sha)

(test-module 'crypt.pbkdf2)

(use util.digest)

(test* "RFC6070 case 1"
       "0c60c80f961f0e71f3a9b524af6012062fe037a6"
       (digest-hexify (pbkdf2-digest-string "password" "salt" 1 :key-length 20 :hasher <sha1>)))

(test* "RFC6070 case 2"
       "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
       (digest-hexify (pbkdf2-digest-string "password" "salt" 2 :key-length 20 :hasher <sha1>)))

(test* "RFC6070 case 3"
       "4b007901b765489abead49d926f721d065a429c1"
       (digest-hexify (pbkdf2-digest-string "password" "salt" 4096 :key-length 20 :hasher <sha1>)))

;;FIXME too many time.
;; (test* "RFC6070 case 4"
;;        "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
;;        (digest-hexify (pbkdf2-digest-string "password" "salt" 16777216 :key-length 20 :hasher <sha1>)))

(test* "RFC6070 case 5"
       "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
       (digest-hexify (pbkdf2-digest-string "passwordPASSWORDpassword" "saltSALTsaltSALTsaltSALTsaltSALTsalt" 4096 :key-length 25 :hasher <sha1>)))

(test* "RFC6070 case 6"
       "56fa6aa75548099dcc37d7f03425e0c3"
       (digest-hexify (pbkdf2-digest-string "pass\0word" "sa\0lt" 4096 :key-length 16 :hasher <sha1>)))

;; If you don't want `gosh' to exit with nonzero status even if
;; test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)





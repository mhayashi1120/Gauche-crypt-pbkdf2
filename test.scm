;;;
;;; Test pbkdf2
;;;

(use gauche.test)

(test-start "crypt.pbkdf2")

(use crypt.pbkdf2)

(test-module 'crypt.pbkdf2)

;; If you don't want `gosh' to exit with nonzero status even if
;; test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)





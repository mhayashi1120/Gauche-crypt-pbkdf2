;;;
;;; Test pbkdf2
;;;

(use gauche.test)

(test-start "crypt.pbkdf2")
(use crypt.pbkdf2)
(test-module 'crypt.pbkdf2)

(use text.csv)
(use util.match)
(use rfc.sha)
(use util.digest)

(debug-print-width #f)

(define (csv-reader file)
  (let* ([reader (make-csv-reader #\,)]
         [ip (open-input-file file)])
    (cut reader ip)))

(let ([reader (csv-reader "hoge.csv")])
  (generator-map
   (match-lambda
    [(salt password iterate-text hash-name)

     (let* ([hasher (eval (string->symbol (format "<~a>" hash-name)) (current-module))]
            [iterations (x->number iterate-text)])
       #?= (digest-hexify (pbkdf2-digest-string salt password iterations :hasher hasher)))])
   reader))

(use rfc.sha)


;; If you don't want `gosh' to exit with nonzero status even if
;; test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)





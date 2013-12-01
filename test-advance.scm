(use gauche.test)

(test-start "crypt.pbkdf2 Advance Test")

(debug-print-width #f)

(use text.csv)
(use util.match)
(use rfc.sha)
(use util.digest)
(use crypt.pbkdf2)
(use gauche.process)

(define (csv-reader file)
  (let* ([reader (make-csv-reader #\,)]
         [ip (open-input-file file)])
    (cut reader ip)))

(define *rubylib-dir* (car *argv*))

(let ([reader (csv-reader "test/data.csv")])
  (generator-map
   (match-lambda
    [(salt password iterate-text hash-name)
     (let* ([hasher-name (string->symbol (format "<~a>" hash-name))]
            [hasher (eval hasher-name (current-module))]
            [iterations (x->number iterate-text)])
       (let ([ruby (process-output->string
                    `(ruby "-I" ,*rubylib-dir*
                           "test/advance-test.rb" ,salt ,password ,iterations ,hash-name))]
             [gauche (digest-hexify (pbkdf2-digest-string salt password iterations :hasher hasher))])
         (test* "test" ruby gauche)))])
   reader))


(test-end)

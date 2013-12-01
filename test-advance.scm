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

(when (= (length *argv*) 0)
  (error "Unable get ruby library"))

(define *rubylib-dir* (car *argv*))

(let ([reader (csv-reader "test/data.csv")])
  (generator-map
   (match-lambda
    [(password salt iterate-text hash-name len-text)
     (and-let* ([hasher-name (string->symbol (format "<~a>" hash-name))]
                ;; TODO sha384, sha512 is not working.
                ;;     There are differences between ruby and gauche hmac implementation..
                [(not (memq hasher-name '(sha384 sha512)))]
                [hasher (eval hasher-name (current-module))]
                [iterations (x->number iterate-text)]
                [len (and (#/^[0-9]+$/ len-text) (x->number len-text))])
       (test* (format "~a ~a ~a <~a>" password salt iterations hash-name)
              (process-output->string
               `(ruby "-I" ,*rubylib-dir*
                      "test/advance-test.rb" ,password ,salt ,iterations ,hash-name ,@(if len (list len) '())))
              (digest-hexify (pbkdf2-digest-string
                              password salt iterations
                              :hasher hasher :key-length len))))])
   reader))


(test-end)

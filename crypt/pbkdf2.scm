(define-module crypt.pbkdf2
  (extend util.digest)
  (use binary.pack)
  (use gauche.uvector)
  (use rfc.hmac)
  (use rfc.sha)
  (export
   pbkdf2-digest-string))
(select-module crypt.pbkdf2)

;; http://en.wikipedia.org/wiki/PBKDF2

(define (stringify x)
  (cond [(string? x) x]
        [(u8vector? x) (u8vector->string x)]
        [else (error "Not a supported type")]))

(define (string-xor s1 s2)
  (u8vector->string
   (u8vector-xor
    (string->u8vector s1)
    (string->u8vector s2))))

(define (hasher-length hasher)
  (string-length (digest-string hasher "")))

;; PBKDF2

(define (pbkdf2-digest-string salt password iterations :key [hasher <sha256>]
                               [key-length (hasher-length hasher)])
  (when (< iterations 1)
    (error "argument out of range:" iterations))

  (cond
   [(not key-length)
    (set! key-length (hasher-length hasher))]
   [(> key-length #xffffffff)           ; Greather than 4 byte int
    (error "key-length too large")])

  (with-output-to-string
    (cut pbkdf2-digest2 (stringify salt) (stringify password) hasher iterations key-length)))

(define (pbkdf2-digest2 salt pass hasher iterations keylen)

  (define (PRF data)
    (hmac-digest-string data :key pass :hasher hasher))

  (define (iterate Ui i)
    (if (>= i iterations)
      Ui
      (string-xor Ui (iterate (PRF Ui) (+ i 1)))))

  (define (INT32BE n)
    (with-output-to-string (cut pack "N" `(,n))))

  (define (F out i)
    (when (< out keylen)
      (let* ([Uiv (string-append salt (INT32BE i))]
             [U (iterate (PRF Uiv) 1)]
             [end (min (string-length U) (- keylen out))]
             [str (string-copy U 0 end)])
        (display str)
        (F (+ out end) (+ i 1)))))

  (F 0 1))

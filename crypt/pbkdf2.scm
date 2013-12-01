(define-module crypt.pbkdf2
  (extend util.digest)
  (use binary.pack)
  (use gauche.uvector)
  (use rfc.hmac)
  (use rfc.sha)
  (export
   pbkdf2-digest pbkdf2-digest-string))
(select-module crypt.pbkdf2)

;; Password-Based Key Derivation Functions

;; http://en.wikipedia.org/wiki/PBKDF2

;; PBKDF2: http://www.ietf.org/rfc/rfc2898.txt
;; PBKDF2 Test: http://www.ietf.org/rfc/rfc6070.txt

;; To pass the u8vector to hmac function
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

(define (pbkdf2-digest-0 password salt hasher iterations keylen)

  (define (PRF data)
    (hmac-digest-string data :key password :hasher hasher))

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

(define (pbkdf2-digest-string password salt iterations :key (hasher <sha256>)
                              (key-length (hasher-length hasher)))
  (when (< iterations 1)
    (error "argument out of range:" iterations))

  (cond
   [(not key-length)
    (set! key-length (hasher-length hasher))]
   [(> key-length #xffffffff)           ; Greather than 4 byte int
    (error "key-length too large")])

  (with-output-to-string
    (cut pbkdf2-digest password salt hasher iterations key-length)))

(define (pbkdf2-digest password salt hasher iterations keylen)
  (pbkdf2-digest-0
   (stringify password) (stringify salt)
   hasher iterations keylen))


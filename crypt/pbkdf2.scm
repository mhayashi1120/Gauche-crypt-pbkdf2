;;;
;;; pbkdf2.scm - Password-Based Key Derivation Functions (RFC 2898 PBKDF2)
;;;
;;;   Copyright (c) 2013 Masahiro Hayashi <mhayashi1120@gmail.com>
;;;
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;
;;;   3. Neither the name of the authors nor the names of its contributors
;;;      may be used to endorse or promote products derived from this
;;;      software without specific prior written permission.
;;;
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

;; http://en.wikipedia.org/wiki/PBKDF2

;; PBKDF2: http://www.ietf.org/rfc/rfc2898.txt
;; PBKDF2 Test: http://www.ietf.org/rfc/rfc6070.txt

(define-module crypt.pbkdf2
  (use binary.pack)
  (use gauche.uvector)
  (use rfc.hmac)
  (use rfc.sha)
  (export
   pbkdf2-digest pbkdf2-digest-string))
(select-module crypt.pbkdf2)

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

(define (pbkdf2-digest-string password salt iterations . args)
  (with-output-to-string
    (cut apply pbkdf2-digest password salt iterations args)))

(define (pbkdf2-digest password salt iterations
                       :key (hasher <sha256>) (key-length (hasher-length hasher)))
  (when (< iterations 1)
    (error "argument out of range:" iterations))

  (cond
   [(not key-length)
    (set! key-length (hasher-length hasher))]
   [(> key-length #xffffffff)           ; Greather than 4 byte int
    (error "key-length too large")])

  (pbkdf2-digest-0
   (stringify password) (stringify salt)
   hasher iterations key-length))


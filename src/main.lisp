(uiop:define-package :cl-argon2
  (:use :cl :cffi)
  (:export 
           #:argon2-hash-encoded
           #:verify-password
           #:generate-salt
           #:argon2-error))

(in-package :cl-argon2)

;; load the libargon2 shared library
(define-foreign-library libargon2
  (:darwin (:or "libargon2.1.dylib" "libargon2.dylib"))
  (:unix (:or "libargon2.so.1" "libargon2.so"))
  (:windows "argon2.dll")
  (t (:default "libargon2")))


(use-foreign-library libargon2)


(defcenum argon2-type
  (:argon2d 0)   ; maximizes resistance against GPU cracking attacks
  (:argon2i 1)   ; optimized to resist side-channel attacks
  (:argon2id 2)  ; hybrid version  (recommended)
  )

; version number
(defconstant +argon2-version+ #x13 )

(define-condition argon2-error (error)
  ((message :initarg :message :reader argon2-error-message)
   (code :initarg :code :reader argon2-error-code))
  (:report (lambda (condition stream)
             (format stream "Argon2 error ~D: ~A"
                     (argon2-error-code condition)
                     (argon2-error-message condition)))))

;; bind to the error message function
(defcfun ("argon2_error_message" %argon2-error-message) :string
  (error-code :int))


(defun generate-salt (&optional (length 16))
  "Generate a cryptographically secure random salt of specified length"
  (ironclad:random-data length))


;; bind to the main hashing function
(defcfun ("argon2_hash" %argon2-hash) :int
  (t-cost :uint32)   ; number of iterations
  (m-cost :uint32)   ; memory usage in KB
  (parallelism :uint32)  ; number of threads
  (pwd :pointer) ; password pointer
  (pwdlen :size)  ; password length
  (salt :pointer) ; salt pointer
  (saltlen :size) ; salt length
  (hash :pointer) ; output hash pointer
  (hashlen :size) ; output hash length
  (encoded :pointer) ; encoded hash string pointer
  (encodedlen :size) ; encoded string length
  (type argon2-type) ; which argon2 variant to use
  (version :uint32) ; argon2 version number
  )

;; helper function to check return values and signal errors
(defun check-error (ret)
  "Convert Argon2 error codes into conditions"
  (unless (zerop ret)
    (error 'argon2-error
           :code ret
           :message (%argon2-error-message ret)))
  ret)


;; high level hashing function

(defun argon2-hash-encoded (password salt &key 
                                          (type :argon2id)
                                          (t-cost 3)
                                          (m-cost 65536) ; 64MB
                                          (parallelism 4)
                                          (hash-len 32))
  "Hash a password using Argon2, returning an encoded string"
  (let* ((pwd-vec (babel:string-to-octets password))
         (encoded-len 1024))
    (with-foreign-objects ((pwd :uint8 (length pwd-vec))
                          (salt-ptr :uint8 (length salt))
                          (hash :uint8 hash-len)
                          (encoded :char encoded-len))
      ;; Copy password and salt to C memory
      (dotimes (i (length pwd-vec))
        (setf (mem-aref pwd :uint8 i) (aref pwd-vec i)))
      (dotimes (i (length salt))
        (setf (mem-aref salt-ptr :uint8 i) (aref salt i)))
      
      ;; Do the actual hashing
      (check-error
       (%argon2-hash t-cost
                     m-cost
                     parallelism
                     pwd (length pwd-vec)
                     salt-ptr (length salt)
                     hash hash-len
                     encoded encoded-len
                     type
                     +argon2-version+))
      
      ;; Return both the encoded string and raw hash as array
      (values (foreign-string-to-lisp encoded)
              (let ((result (make-array hash-len 
                                       :element-type '(unsigned-byte 8))))
                (dotimes (i hash-len)
                  (setf (aref result i) (mem-aref hash :uint8 i)))
                result)))))



;; Bind verify functions for each variant
(defcfun ("argon2i_verify" %argon2i-verify) :int
  (encoded :string)
  (pwd :pointer)
  (pwdlen :size))

(defcfun ("argon2d_verify" %argon2d-verify) :int
  (encoded :string)
  (pwd :pointer)
  (pwdlen :size))

(defcfun ("argon2id_verify" %argon2id-verify) :int
  (encoded :string)
  (pwd :pointer)
  (pwdlen :size))

;; Bind generic verify function
(defcfun ("argon2_verify" %argon2-verify) :int
  (encoded :string)
  (pwd :pointer)
  (pwdlen :size)
  (type argon2-type))

;; High-level verification function
(defun verify-password (encoded-hash password &key (type :argon2id))
  "Verify a password against an encoded hash string"
  (let ((pwd-vec (babel:string-to-octets password)))
    (with-foreign-object (pwd :uint8 (length pwd-vec))
      ;; Copy password to C memory
      (dotimes (i (length pwd-vec))
        (setf (mem-aref pwd :uint8 i) (aref pwd-vec i)))
      
      ;; Call appropriate verification function based on type
      (let ((result 
             (case type
               (:argon2i (%argon2i-verify encoded-hash pwd (length pwd-vec)))
               (:argon2d (%argon2d-verify encoded-hash pwd (length pwd-vec)))
               (:argon2id (%argon2id-verify encoded-hash pwd (length pwd-vec)))
               (t (error "Unknown Argon2 type: ~A" type)))))
        ;; Return t for success (0), nil for failure
        (zerop result)))))


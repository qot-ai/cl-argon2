(defpackage cl-argon2/tests/main
  (:use :cl
        :cl-argon2
        :rove))
(in-package :cl-argon2/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :cl-argon2)' in your Lisp.

(deftest salt-generation-test
  (testing "Salt generation"
           (let ((salt1 (generate-salt))
                 (salt2 (generate-salt)))
             (ok (= 16 (length salt1))
                 "Default salt length should be 16 bytes")
             (ok (= 32 (length (generate-salt 32)))
                 "Custom salt length should work")
             (ng (equalp salt1 salt2)
                 "Different calls should generate different salts")
             (ok (typep salt1 '(simple-array (unsigned-byte 8) (*)))
                 "Salt should be a byte array"))))


(deftest basic-hash-test
  (testing "Basic password hashing"
    (let* ((password "test-password")
           (salt (generate-salt))
           (encoded-hash (argon2-hash-encoded password salt)))
      ;; should return a string
      (ok (stringp encoded-hash)
          "Hash should return a string")
      ;; should contain argon2 identifier
      (ok (cl-ppcre:scan "\\$argon2id\\$" encoded-hash)
          "Hash should contain argon2id identifier")
      ;; should contain version
      (ok (cl-ppcre:scan "v=19" encoded-hash)
          "Hash should contain version number"))))

(deftest hash-variants-test
  (testing "Different Argon2 variants"
    (let ((password "test-password")
          (salt (generate-salt)))
      (ok (stringp (argon2-hash-encoded password salt :type :argon2i))
          "Argon2i should work")
      (ok (stringp (argon2-hash-encoded password salt :type :argon2d))
          "Argon2d should work")
      (ok (stringp (argon2-hash-encoded password salt :type :argon2id))
          "Argon2id should work")
      )))

(deftest verify-password-test
  (testing "Password verification"
    (let* ((password "my-secure-password")
           (salt (generate-salt))
           (encoded-hash (argon2-hash-encoded password salt)))
      
      ;; Test correct password
      (ok (verify-password encoded-hash password)
          "Correct password should verify successfully")
      
      ;; Test wrong password
      (ng (verify-password encoded-hash "wrong-password")
          "Wrong password should fail verification")
      
      ;; Test with explicit type
      (let ((hash-i (argon2-hash-encoded password salt :type :argon2i)))
        (ok (verify-password hash-i password :type :argon2i)
            "Argon2i verification should work"))
      
      ;; Test with null byte in password
      (let* ((special-pwd "test\0test")
             (special-hash (argon2-hash-encoded special-pwd salt)))
        (ok (verify-password special-hash special-pwd)
            "Should handle null bytes in password")))))

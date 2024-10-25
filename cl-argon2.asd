(defsystem "cl-argon2"
  :version "0.0.1"
  :author ""
  :license ""
  :depends-on ("cl-ppcre"
               "babel"
               "ironclad"
               "rove"
               "cl-ppcre"
               "cffi")
  :components ((:module "src"
                :components
                ((:file "main"))))
  :description ""
  :in-order-to ((test-op (test-op "cl-argon2/tests"))))

(defsystem "cl-argon2/tests"
  :author ""
  :license ""
  :depends-on ("cl-argon2"
               "rove")
  :components ((:module "tests"
                :components
                ((:file "main"))))
  :description "Test system for cl-argon2"
  :perform (test-op (op c) (symbol-call :rove :run c)))

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/qot-ai/cl-argon2)

# CL-ARGON2
Common Lisp bindings for the Argon2 password hashing algorithm using CFFI.

## Prerequisites
You need to have Argon2 installed on your system:

#### macOS
```bash
brew install argon2
```
#### Ubuntu/Debian
```bash
sudo apt-get install libargon2-dev
```
#### Arch Linux
```bash
sudo pacman -S argon2
```
## Installation

First, make sure you have Quicklisp installed.

Clone this repository to your Quicklisp local-projects directory:

```bash
cd ~/quicklisp/local-projects
git clone https://github.com/qot-ai/cl-argon2
```

Load the system in your Lisp REPL:

```lisp
(ql:quickload :cl-argon2)
```

## Dependencies
The system depends on:

- cffi 
- babel 
- ironclad 
- rove 

These will be automatically installed by Quicklisp when loading the system.

## Usage

### Basic password hashing and verification:

```lisp
(defvar *hash* 
  (cl-argon2:argon2-hash-encoded 
    "my-secure-password" 
    (cl-argon2:generate-salt)))

;; Verify correct password
(cl-argon2:verify-password *hash* "my-secure-password") ; => T

;; Verify wrong password
(cl-argon2:verify-password *hash* "wrong-password") ; => NIL
```
#### Custom Parameters
You can customize the hashing parameters:

```lisp
(cl-argon2:argon2-hash-encoded 
  "password"
  (cl-argon2:generate-salt)
  :t-cost 4          ; time cost
  :m-cost 131072     ; memory cost (in KB, 128MB)
  :parallelism 8     ; parallelism factor
  :type :argon2id)   ; argon2 variant (can be :argon2i, :argon2d, or :argon2id)
```
#### Default parameters:

```
t-cost: 3
m-cost: 65536 (64MB)
parallelism: 4
type: :argon2id
```

## Running Tests

```lisp
(asdf:test-system :cl-argon2)
```
## License
MIT
## Security Recommendations

- Always use a fresh random salt for each password
- The defaults are secure for most use cases
- Argon2id is the recommended variant (default)
- Store the complete encoded hash string returned by argon2-hash-encoded
- Never store raw passwords

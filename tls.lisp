;;;; OpenSSL alien bindings and TLS socket support for SBCL
;;;;
;;;; Copyright (c) Jeffrey Massung
;;;;
;;;; This file is provided to you under the Apache License,
;;;; Version 2.0 (the "License"); you may not use this file
;;;; except in compliance with the License.  You may obtain
;;;; a copy of the License at
;;;;
;;;;    http://www.apache.org/licenses/LICENSE-2.0
;;;;
;;;; Unless required by applicable law or agreed to in writing,
;;;; software distributed under the License is distributed on an
;;;; "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
;;;; KIND, either express or implied.  See the License for the
;;;; specific language governing permissions and limitations
;;;; under the License.
;;;;

(defpackage :tls
  (:use :cl :sb-alien :sb-ext :sb-gray :sb-sys)
  (:export
   #:init-openssl

   ;; creating a socket and use it
   #:make-tls-stream
   #:with-tls-stream))

(in-package :tls)

;;; ----------------------------------------------------

(defparameter *libssl*
  #+os-windows "libssl-1_1-x64"
  #+os-macosx "libssl.dylib"
  #+os-linux "libssl.1.1.so"
  "Platform-specific OpenSSL dynamic library.")

;;; ----------------------------------------------------

(defparameter *libcrypto*
  #+os-windows "libcrypto-1_1-x64"
  #+os-macosx "libcrypto.dylib"
  #+os-linux "libcrypto.so"
  "Platform-specific crypto and BIO library for OpenSSL.")

;;; ----------------------------------------------------

(eval-when (:load-toplevel :execute)
  (load-shared-object *libssl*)
  (load-shared-object *libcrypto*))

;;; ----------------------------------------------------

(defclass tls-stream (fundamental-binary-input-stream
                      fundamental-binary-output-stream)
  ((ctx :initarg :ctx :reader tls-ctx)
   (bio :initarg :bio :reader tls-bio)

   ;; When reading from TLS, read into a large buffer that can be
   ;; used as a bivalent stream.
   (read-buffer :initform (make-array 4096 :element-type '(unsigned-byte 8)))

   ;; The number of bytes read from the buffer and the total number
   ;; of bytes available to be read.
   (read-pos  :initform 0)
   (read-size :initform 0)

   ;; The number of bytes read from the socket.
   (socket-pos :initform 0))
  (:documentation "A secure read/write stream."))

;;; ----------------------------------------------------

(define-condition ssl-error (error)
  ((text :initarg :reader :reader ssl-error-reason))
  (:documentation "An SSL error message."))

;;; ----------------------------------------------------

(define-alien-type ssl-settings (* t))
(define-alien-type ssl-bio (* t))
(define-alien-type ssl-ctx (* t))
(define-alien-type ssl-method (* t))

;;; ----------------------------------------------------

(define-alien-routine "OPENSSL_init_ssl" int (opts int) (settings ssl-settings))

;;; ----------------------------------------------------

(define-alien-routine "TLS_client_method" ssl-method)

;;; ----------------------------------------------------

(define-alien-routine "SSL_CTX_new" ssl-ctx (method ssl-method))
(define-alien-routine "SSL_CTX_free" void (context ssl-ctx))

;;; ----------------------------------------------------

(define-alien-routine "BIO_new_ssl_connect" ssl-bio (context ssl-ctx))
(define-alien-routine "BIO_free_all" void (bio ssl-bio))
(define-alien-routine "BIO_ctrl" long (bio ssl-bio) (cmd int) (larg long) (parg (* t)))
(define-alien-routine "BIO_test_flags" int (bio ssl-bio) (flags int))
(define-alien-routine "BIO_read" int (bio ssl-bio) (buf (* unsigned-char)) (len int))
(define-alien-routine "BIO_write" int (bio ssl-bio) (buf (* unsigned-char)) (len int))

;;; ----------------------------------------------------

(define-alien-routine "ERR_clear_error" void)
(define-alien-routine "ERR_get_error" long)
(define-alien-routine "ERR_reason_error_string" c-string (err long))

;;; ----------------------------------------------------

(defun init-openssl ()
  "Initialize OpenSSL with default settings."
  (plusp (openssl-init-ssl #x200000 (int-sap 0))))

;;; ----------------------------------------------------

(defun make-tls-stream (host &optional (port 443))
  "Create a secure connection with a host and return it."
  (let* ((hostname (make-alien-string (format nil "~a:~a" host port)))
         (method (tls-client-method))
         (context (ssl-ctx-new method))
         (bio (bio-new-ssl-connect context)))

    ;; attempt to connect and perform the handshake
    (unwind-protect
         (if (and (plusp (bio-ctrl bio 100 0 hostname))
                  (plusp (bio-ctrl bio 101 0 (int-sap 0))))
             (make-instance 'tls-stream :ctx context :bio bio)
           (let ((err (err-get-error)))
             (error 'ssl-error :reason (err-reason-error-string err))))
      (free-alien hostname))))

;;; ----------------------------------------------------

(defmethod slurp ((sock tls-stream))
  "Refill the buffer with more data from the socket. Returns bytes read."
  (with-slots (bio read-buffer read-pos read-size socket-pos)
      sock
    (when (open-stream-p sock)
      (with-pinned-objects (read-buffer)
        (let* ((sap (vector-sap read-buffer))
               (n (bio-read bio sap (length read-buffer))))
          (incf socket-pos n)
          (setf read-pos 0
                read-size n))))))

;;; ----------------------------------------------------

(defmethod stream-element-type ((sock tls-stream))
  "All secure socket streams are octets."
  '(unsigned-byte 8))

;;; ----------------------------------------------------

(defmethod open-stream-p ((sock tls-stream))
  "Non-nil if the stream is open and connected."
  (and (tls-bio sock)
       (tls-ctx sock)))

;;; ----------------------------------------------------

(defmethod close ((sock tls-stream) &key abort)
  "Close the connection and free the SSL context object."
  (declare (ignore abort))
  (with-slots (bio ctx)
      sock
    (unwind-protect
         (progn
           (bio-free-all bio)
           (ssl-ctx-free ctx))
      (setf bio nil
            ctx nil))))

;;; ----------------------------------------------------

(defmethod stream-file-position ((sock tls-stream) &optional pos-spec)
  "Return the number of bytes read from the socket."
  (if pos-spec
      nil
    (slot-value sock 'socket-pos)))

;;; ----------------------------------------------------

(defmethod stream-read-byte ((sock tls-stream))
  "Read a single byte from the stream."
  (with-slots (read-buffer read-pos read-size)
      sock
    (when (>= read-pos read-size)
      (unless (slurp sock)
        (return-from stream-read-byte :eof)))
    (prog1 (aref read-buffer read-pos)
      (incf read-pos))))

;;; ----------------------------------------------------

(defmethod stream-read-sequence ((sock tls-stream) seq &optional (start 0) end)
  "Destructively modify the sequence with bytes read from the socket."
  (when (null end)
    (setf end (length seq)))

  ;; read until all bytes have been read
  (with-slots (read-buffer read-pos read-size)
      sock
    (loop
       with bytes-to-read = (- end start)

       ;; keep reading until there are no bytes left to read
       until (zerop bytes-to-read)
       do (let ((n (min (- read-size read-pos) bytes-to-read)))
            (replace seq
                     read-buffer
                     :start1 start
                     :end1 end
                     :start2 read-pos
                     :end2 (+ read-pos n))

            ;; advance where to read from and tally what's left
            (incf start n)
            (incf read-pos n)
            (decf bytes-to-read n)

            ;; need to slurp more bytes?
            (unless (< read-pos read-size)
              (slurp sock)))

       ;; return the final sequence
       finally (return start))))

;;; ----------------------------------------------------

(defmethod stream-write-byte ((sock tls-stream) byte)
  "Write a single byte to the secure socket."
  (with-alien ((buf unsigned-char byte))
    (let ((n (bio-write (tls-bio sock) buf 1)))
      (when (plusp n) byte))))

;;; ----------------------------------------------------

(defmethod stream-write-sequence ((sock tls-stream) seq &optional (start 0) end)
  "Write the sequence of bytes to the secure socket."
  (with-pinned-objects (seq)
    (let ((buf (sap+ (vector-sap seq) start))
          (len (- (or end (length seq)) start)))
      (prog1 seq
        (bio-write (tls-bio sock) buf len)))))

;;; ----------------------------------------------------

(defmethod stream-read-char ((sock tls-stream))
  "Return the next character in the stream or :eof."
  (let ((byte (stream-read-byte sock)))
    (if (eq byte :eof)
        :eof
      (code-char byte))))

;;; ----------------------------------------------------

(defmethod stream-peek-char ((sock tls-stream))
  "Try and peek at the next character in the stream."
  (let ((char (stream-read-char sock)))
    (if (eq char :eof)
        :eof
      (prog1 char
        (decf (slot-value sock 'read-pos))))))

;;; ----------------------------------------------------

(defmethod stream-unread-char ((sock tls-stream) character)
  "Undo the last call to stream-read-char."
  (with-slots (read-buffer read-pos)
      sock
    (when (plusp read-pos)
      (decf read-pos)

      ;; ensure the character unread is the same as what's in the buffer
      (assert (char= (aref read-buffer read-pos) character)))))

;;; ----------------------------------------------------

(defmethod stream-read-line ((sock tls-stream))
  "Read the next line from the stream, return it along with EOF flag."
  (let* ((at-eof nil)
         (line (with-output-to-string (s)
                 (loop
                    for c = (stream-read-char sock)
                    until (or (eq c #\newline)
                              (and (eq c :eof)
                                   (setf at-eof t)))
                    do (write-char c s)))))
    (values line at-eof)))

;;; ----------------------------------------------------

(defmethod stream-write-char ((sock tls-stream) character)
  "Write a character - as octets - to the socket."
  (let ((octets (string-to-octets (string character))))
    (when (stream-write-sequence sock octets) character)))

;;; ----------------------------------------------------

(defmethod stream-write-string ((sock tls-stream) string &optional (start 0) end)
  "Write the string - as octets - to the socket."
  (let ((octets (string-to-octets (if (and (zerop start) (null end))
                                      string
                                    (subseq string start end)))))
    (when (stream-write-sequence sock octets) string)))

;;; ----------------------------------------------------

(defmethod stream-advance-to-column ((sock tls-stream) column)
  "Write blank spaces so the next character write will be at the given column."
  (declare (ignore column))
  nil)

;;; ----------------------------------------------------

(defmethod stream-start-line-p ((sock tls-stream))
  "T if the socket is at the start of a line."
  nil)

;;; ----------------------------------------------------

(defmethod stream-line-length ((sock tls-stream))
  "Sockets have no line length."
  nil)

;;; ----------------------------------------------------

(defmethod stream-line-column ((sock tls-stream))
  "Sockets have no column number."
  nil)

;;; ----------------------------------------------------

(defmacro with-tls-stream ((sock host &optional (port 443)) &body body)
  "Create a secure socket, connect, execute a body, and close it."
  `(let ((,sock (make-tls-stream ,host ,port)))
     (unwind-protect
          (progn ,@body)
       (close ,sock))))

;;; ----------------------------------------------------

(defun test ()
  "Hit https://httpbin.org/get to validate that SSL works."
  (with-tls-stream (s "httpbin.org")
    (flet ((write-newline ()
             (write-char #\return s)
             (write-char #\linefeed s)))
      (write-string "GET /get HTTP/1.1" s)
      (write-newline)
      (write-string "Host: httpbin.org" s)
      (write-newline)
      (write-newline))
    (do ((line (read-line s)
               (read-line s)))
        ((< (length line) 2))
      (print line))))

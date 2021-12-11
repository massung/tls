# TLS Socket Stream for SBCL

The `tls` package uses [OpenSSL][openssl] to create a secure, socket connection to a remote host, perform the handshake, and act as a bivelant, gray stream for [SBCL][sbcl].

Aside from [SBCL][sbcl], it has other dependencies.

## Quickstart

Before anything else, [OpenSSL][openssl] needs to be initialized:

    CL-USER > (tls:init-openssl)
    T

After [OpenSSL][openssl] has been initialized, you can then either use `make-tls-stream` to create a connection to a secure host or use the macro `with-tls-stream` to create (and close when done) the connection. Each of these takes the hostname as a parameter along with an optional port, which defaults to 443.

    CL-USER > (tls:make-tls-stream "httpbin.org")
    #<TLS::TLS-STREAM {1003EF4413}>

Once you have a secure stream, simply use any of the Common Lisp functions available to read-from or write-to it (e.g. `write-byte`, `read-line`, etc).

When you're done with the stream, remember to `close` it.

    CL-USER > (close *)
    NIL

## MacOS X and OpenSSL

On MacOS X, the default libcrypto is a stub library programmed to fail with the error: `loading libcrypto in an unsafe way`.

In order to fix this, I recommend using [Homebrew][brew] to install [LibreSSL][libressl].

Once installed, you'll need to update your `PATH` to use that version and add symbolic links to the dynamic libraries into `/usr/local/lib`:

    export PATH=$(brew --prefix)/opt/libressl/bin:$PATH

    ln -s $(brew--prefix)/opt/libressl/lib/libssl.dylib /usr/local/lib
    ln -s $(brew--prefix)/opt/libressl/lib/libcrypto.dylib /usr/local/lib

## Notes

Under-the-hood the streams are octet (byte) streams. Because this package's primary use is for HTTPS, when using functions like `read-char` and `read-line`, the bytes read are assumed to be ASCII characters (1 byte = 1 character). If you need to decode the bytes, then use `read-byte` or `read-sequence` and then `sb-ext:octets-to-string`.

If you'd like to test the package, evaluate `tls::test`:

    CL-USER > (tls::test)


[openssl]: https://www.openssl.org/
[sbcl]: http://sbcl.org/
[brew]: https://brew.sh/
[libressl]: https://www.libressl.org/

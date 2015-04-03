package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// secureReader handles decryption of data using the NaCl
// box asymmetric crypto system.
type SecureReader struct {
	io.Reader
	priv, pub *[32]byte
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return SecureReader{
		Reader: r,
		priv:   priv,
		pub:    pub,
	}
}

// Read implements the io.Reader interface on secureReader
func (sr SecureReader) Read(p []byte) (n int, err error) {
	nonce := new([24]byte)
	encrypted := make([]byte, 32000)

	// TODO - We need to figure out how to handle what happens if this
	// doesn't read in full
	n, err = sr.Reader.Read(encrypted)
	if err != nil {
		return 0, err
	}

	copy(nonce[:], encrypted[0:24])
	encrypted = encrypted[24:n]

	// TODO - Figure out what the first parameter actually does
	decrypted, ok := box.Open(make([]byte, 0), encrypted, nonce, sr.pub, sr.priv)
	if !ok {
		return 0, errors.New("Unable to decrypt message")
	}

	for i := 0; i < len(decrypted); i++ {
		p[i] = decrypted[i]
	}

	return len(decrypted), nil
}

// secureWriter handles encryption of data using the NaCl
// box asymmetric crypto sytem.
type SecureWriter struct {
	io.Writer
	priv, pub *[32]byte
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return SecureWriter{
		Writer: w,
		priv:   priv,
		pub:    pub,
	}
}

// Write implements the io.Writer interface on secureWriter.
func (sw SecureWriter) Write(p []byte) (n int, err error) {
	// TODO - Figure out what this actually does
	out := make([]byte, 0)

	nonce := new([24]byte)
	n, err = rand.Read(nonce[:])
	if n < 24 {
		return 0, errors.New("Unable to get 24 bytes of randomnness for nonce")
	} else if err != nil {
		return 0, err
	}

	result := box.Seal(out, p, nonce, sw.pub, sw.priv)
	result = append(nonce[:], result...)

	return sw.Writer.Write(result)
}

// secureConn is a lightweight net.conn that encrypts outgoing data
// and decrypts incoming data using the NaCl box asymmetric cryptosystem.
type SecureConn struct {
	io.Writer
	io.Reader
	net.Conn
}

// NewSecureConn instantiates a new SecureConn
func NewSecureConn(priv, pub *[32]byte, c net.Conn) io.ReadWriteCloser {
	return SecureConn{
		Writer: NewSecureWriter(c, priv, pub),
		Reader: NewSecureReader(c, priv, pub),
		Conn:   c,
	}
}

// Write calls the underlying Writer's write method
func (sc SecureConn) Write(p []byte) (n int, err error) {
	return sc.Writer.Write(p)
}

// Read calls the underlying Reader's read method
func (sc SecureConn) Read(p []byte) (n int, err error) {
	return sc.Reader.Read(p)
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	// Connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Generate the private/public key pair
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Perform the handshake
	serverPub := new([32]byte)
	_, err = io.ReadFull(conn, serverPub[:])
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(pub[:])
	if err != nil {
		return nil, err
	}

	return NewSecureConn(priv, serverPub, conn), nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			_, err := conn.Write(pub[:])
			if err != nil {
				log.Println("Error writing key: ", err)
				conn.Close()
				return
			}

			clientPub := new([32]byte)
			_, err = io.ReadFull(conn, clientPub[:])
			if err != nil {
				log.Println("Error reading key: ", err)
				conn.Close()
				return
			}

			sc := NewSecureConn(priv, clientPub, conn)

			message := make([]byte, 32000)
			n, err := sc.Read(message)
			if err != nil {
				log.Println("Error reading message: ", err)
				conn.Close()
				return
			}
			message = message[:n]

			_, err = sc.Write(message)
			if err != nil {
				log.Println("Error writing message: ", err)
				conn.Close()
				return
			}
		}(conn)
	}
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}

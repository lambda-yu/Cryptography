package main

/*
struct Keys{
	char *publicKey;
	char *privateKey;
};
*/
import "C"
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
)

//export generatekey
func generatekey(keySize int) C.struct_Keys {
	// Generatekey generate private key and public key
	keys := C.struct_Keys{}
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		keys.publicKey = nil
		keys.privateKey = nil
		return keys
	}
	// 私钥
	private := x509.MarshalPKCS1PrivateKey(privateKey)
	private_block := &pem.Block{
		Type:  "private rsa key",
		Bytes: private,
	}
	private_buffer := new(bytes.Buffer)
	err = pem.Encode(private_buffer, private_block)
	if err != nil {
		keys.publicKey = nil
		keys.privateKey = nil
		return keys
	}
	PublicKey := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	public_block := &pem.Block{
		Type:  "public rsa key",
		Bytes: PublicKey,
	}
	public_buffer := new(bytes.Buffer)
	err = pem.Encode(public_buffer, public_block)
	if err != nil {
		keys.publicKey = nil
		keys.privateKey = nil
		return keys
	}
	keys.publicKey = C.CString(public_buffer.String())
	keys.privateKey = C.CString(private_buffer.String())
	return keys
}

func ReadKey(key []byte) (interface{}, interface{}) {
	// ReadKey 读取密钥，自动判断公私钥, 自动判断是密钥还是路径
	block, _ := pem.Decode(key)
	if strings.Index(block.Type, "private") != -1 || strings.Index(block.Type, "PRIVATE") != -1 {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "parse private key error"
		}
		return key, nil
	} else if strings.Index(block.Type, "public") != -1 || strings.Index(block.Type, "PUBLIC") != -1 {
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, "parse public key error"
		}
		return key, nil
	} else {
		return nil, "read key error"
	}

}

func ReadKeyFromPath(key []byte) (interface{}, interface{}) {
	// ReadKey 从指定路径读取密钥，自动判断公私钥
	file, err := os.Open(string(key[:]))
	if err != nil {
		return nil, "open file error"
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, "open file error"
	}
	keyBuf := make([]byte, fileInfo.Size())

	_, err = file.Read(keyBuf)
	if err != nil {
		return nil, "open file error"
	}
	block, _ := pem.Decode(keyBuf)

	if strings.Index(block.Type, "private") != -1 {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "parse private key error"
		}
		return key, "nil"
	} else if strings.Index(block.Type, "public") != -1 {
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, "parse public key error"
		}
		return key, nil
	} else {
		return nil, "read key error"
	}

}

//export RsaEncrypt
func RsaEncrypt(plainText , public_key *C.char) *C.char {
	// RsaEncrypt 公钥加密,分段加密
	publicKey_str := []byte(C.GoString(public_key))
	key, err := ReadKey(publicKey_str)
	if err != nil {
		return C.CString("Read key error")
	}
	publicKey := key.(*rsa.PublicKey)
	var cipherBuffer = bytes.Buffer{}
	seq := 100
	index := 0
	plainText_str := C.GoString(plainText)
	for ; index < len(plainText_str)-seq; index += seq {
		data := plainText_str[index : index+seq]
		encryptData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(data))
		if err != nil {
			return C.CString("Encrypt key error")
		}
		cipherBuffer.Write(encryptData)
	}
	data := plainText_str[index:len(plainText_str)]
	encryptData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(data))
	if err != nil {
		return C.CString("Encrypt key error")
	}
	cipherBuffer.Write(encryptData)
	return C.CString(base64.StdEncoding.EncodeToString(cipherBuffer.Bytes()))
}

// RsaDecrypt 私钥解密
//export RsaDecrypt
func RsaDecrypt(cipherText , keyPath *C.char) *C.char {
	privateKey_str := []byte(C.GoString(keyPath))
	key, err := ReadKey(privateKey_str)
	if err != nil {
		return C.CString("Read key error")
	}
	privateKey := key.(*rsa.PrivateKey)
	plain := []byte{}
	cipherText_str, _ := base64.StdEncoding.DecodeString(C.GoString(cipherText))

	for i := 0; i < len(cipherText_str); i += privateKey.Size() {
		encryptData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(cipherText_str[i:i+1*privateKey.Size()]))
		if err != nil {
			return C.CString(err.Error())
		}
		plain = append(plain, encryptData...)
	}
	return C.CString(string(plain))
}

func main() {
}

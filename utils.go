package proj2

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib

	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
	"fmt"
)

func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func hash(message []byte) []byte {
	hash, _ := userlib.HMACEval(make([]byte, 16), message)
	return hash
}

func printSlice(slice []byte) {
	print("Length:", len(slice), "\n")
	for _, n := range slice {
		fmt.Printf("%2x", n)
	}
	print("\n")
}

func encryptPrivateKey(purpose string, privateKey userlib.PrivateKeyType, masterKey []byte) ([]byte, error) {
	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, err
	}
	symKey, err := userlib.HashKDF(masterKey, []byte(purpose))
	if err != nil {
		return nil, err
	}

	symKey = symKey[:16]
	iv := userlib.RandomBytes(16)
	return userlib.SymEnc(symKey, iv, privateKeyBytes), nil
}

func decryptPrivateKey(purpose string, encryptedPrivate, masterKey []byte) (privateKey userlib.PrivateKeyType, err error) {
	symKey, err := userlib.HashKDF(masterKey, []byte(purpose))
	if err != nil {
		return privateKey, err
	}
	symKey = symKey[:16]

	marshalledPrivate := userlib.SymDec(symKey, encryptedPrivate)
	json.Unmarshal(marshalledPrivate, &privateKey)
	err = nil
	return
}

func (userdata *User) storeEncryptedKey(filename, target string, key []byte) (err error) {
	// TODO: change this index
	index, err := json.Marshal([][]byte{
		[]byte(userdata.Username),
		[]byte(target),
		[]byte(filename),
	})
	if err != nil {
		return err
	}
	// TODO: also change the recipientKey
	recipientKey := hash(append([]byte(target+filename), userdata.Password...))[:16]
	uuid := bytesToUUID(hash(index))

	iv := userlib.RandomBytes(16)
	encryptedKey := userlib.SymEnc(recipientKey, iv, key)

	macKey, err := userlib.HashKDF(recipientKey, []byte("mac"))
	if err != nil {
		return err
	}
	macKey = macKey[:16]
	mac, err := userlib.HMACEval(macKey, key)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid, append(mac, encryptedKey...))
	return nil
}

func (userdata *User) asymEncrypt(username string, message []byte) (encryptedMessage []byte, err error) {
	publicKey, ok := userlib.KeystoreGet(username + "p")
	if !ok {
		return nil, errors.New(username + "'s PK not found")
	}

	ciphertext, err := userlib.PKEEnc(publicKey, message)
	if err != nil {
		return nil, err
	}

	signature, err := userlib.DSSign(userdata.SignKey, message)
	if err != nil {
		return nil, err
	}

	return append(signature, ciphertext...), nil
}

func (userdata *User) asymDecrypt(username string, encryptedMessage []byte) (message []byte, ok bool, err error) {
	signature := encryptedMessage[:256]
	ciphertext := encryptedMessage[256:]

	privateKey := userdata.DecKey

	verifyKey, ok := userlib.KeystoreGet(username + "d")
	if !ok {
		return nil, false, errors.New("sharer's verification key not found")
	}

	message, err = userlib.PKEDec(privateKey, ciphertext)
	if err != nil {
		return nil, false, err
	}

	err = userlib.DSVerify(verifyKey, message, signature)
	if err != nil {
		return nil, false, err
	}

	return message, true, nil
}

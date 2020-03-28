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

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

type User struct {
	Username   string
	Password   string
	PrivateKey userlib.PrivateKeyType
	SignKey    userlib.DSSignKeyType
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// InitUser - You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// Hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	userdataptr = &userdata

	userdata.Username = username
	userdata.Password = password

	UUID := bytesToUUID(hash([]byte(username)))
	salt := userlib.RandomBytes(16)
	data := hash(append(salt, password...))
	value := append(salt, data...)

	masterKey := userlib.Argon2Key([]byte(password), salt, 16)

	macKey, err := userlib.HashKDF(masterKey, []byte("mac"))
	if err != nil {
		return nil, err
	}
	mac, err := userlib.HMACEval(macKey[:16], value)
	if err != nil {
		return nil, err
	}

	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	userlib.KeystoreSet(username+"p", publicKey)
	userlib.KeystoreSet(username+"d", verifyKey)

	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, err
	}

	signKeyBytes, err := json.Marshal(signKey)
	if err != nil {
		return nil, err
	}

	pkKey, err := userlib.HashKDF(masterKey, []byte("private key"))
	if err != nil {
		return nil, err
	}

	skKey, err := userlib.HashKDF(masterKey, []byte("sign key"))
	if err != nil {
		return nil, err
	}

	pkKey = pkKey[:16]
	iv := userlib.RandomBytes(16)
	encryptedPrivate := userlib.SymEnc(pkKey, iv, privateKeyBytes)
	encryptedSign := userlib.SymEnc(skKey, iv, signKeyBytes)

	// this is to verify that the user exists later with getuser
	// we need to make it so that if this is valid, then the private key is revealed
	entry, err := json.Marshal([][]byte{mac, value, encryptedPrivate, encryptedSign})
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(UUID, entry)
	return &userdata, nil
}

func hash(message []byte) []byte {
	hash, _ := userlib.HMACEval(make([]byte, 16), message)
	return hash
}

// GetUser - This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	UUID := bytesToUUID(hash([]byte(username)))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return nil, errors.New("user does not exist")
	}
	var contents [][]byte
	err = json.Unmarshal(entry, &contents)
	if err != nil {
		return nil, err
	}

	mac := contents[0]
	value := contents[1]
	encryptedPrivate := contents[2]
	encryptedSign := contents[3]

	salt := make([]byte, 16, 16+len(password))
	copy(salt, value[:16])
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)
	macKey, err := userlib.HashKDF(masterKey, []byte("mac"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	pkKey, err := userlib.HashKDF(masterKey, []byte("private key"))
	if err != nil {
		return nil, err
	}
	pkKey = pkKey[:16]

	marshalledPrivate := userlib.SymDec(pkKey, encryptedPrivate)
	var privateKey userlib.PrivateKeyType
	json.Unmarshal(marshalledPrivate, &privateKey)

	skKey, err := userlib.HashKDF(masterKey, []byte("sign key"))
	if err != nil {
		return nil, err
	}
	skKey = skKey[:16]

	marshalledSign := userlib.SymDec(skKey, encryptedSign)
	var signKey userlib.SignKeyType
	json.Unmarshal(marshalledSign, &signKey)

	validation, _ := userlib.HMACEval(macKey, value)
	if !userlib.HMACEqual(mac, validation) {
		return nil, errors.New("data has been corrupted")
	}

	data := value[16:]
	// this part is not working even though they are same when we print
	if userlib.HMACEqual(data, hash(append(salt, password...))) {
		var userdata User
		userdataptr = &userdata
		userdata.Username = username
		userdata.Password = password
		userdata.PrivateKey = privateKey
		userdata.SignKey = signKey
		return userdataptr, nil
	}

	return nil, errors.New("invalid password")
}
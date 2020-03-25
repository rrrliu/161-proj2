package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

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

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
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

// User - The structure definition for a user record
type User struct {
	Username string
	Password string
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

	macKey := userlib.Argon2Key([]byte(password), salt, 16)
	mac, _ := userlib.HMACEval(macKey, value)

	userlib.DatastoreSet(UUID, append(mac, value...))
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
	userentry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return nil, errors.New("user does not exist")
	}
	mac := userentry[:64]
	value := userentry[64:]
	salt := make([]byte, 16, 16+len(password))
	copy(salt, value[:16])
	macKey := userlib.Argon2Key([]byte(password), salt, 16)
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
		return userdataptr, nil
	}

	return nil, errors.New("invalid password")
}

func printSlice(slice []byte) {
	print("Length:", len(slice), "\n")
	for _, n := range slice {
		fmt.Printf("%2x", n)
	}
	print("\n")
}

// StoreFile - This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	username := []byte(userdata.Username)
	password := []byte(userdata.Password)
	printSlice(data)

	UUID := bytesToUUID(hash(append(username, filename...)))
	salt := userlib.RandomBytes(16)
	k, err := userlib.HMACEval(salt, append(salt, password...))
	k = k[:16]
	if err != nil {
		panic(err)
	}

	var file [][]byte
	iv := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(k, iv, data)
	value := append(salt, encryptedData...)

	newKey, err := userlib.HashKDF(k, []byte("mac"))
	if err != nil {
		panic(err)
	}
	macKey := newKey[:16]
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		panic(err)
	}

	file = append(file, append(mac, value...))

	fileToBytes, err := json.Marshal(file)
	if err != nil {
		panic(err)
	}
	userlib.DatastoreSet(UUID, fileToBytes)
}

// AppendFile - This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	UUID := bytesToUUID(hash(append(username, filename...)))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return errors.New("file does not exist")
	}
	var file [][]byte
	err = json.Unmarshal(entry, &file)
	if err != nil {
		return err
	}

	// instead of generating a new k with a new salt, try to find the k that was initially used
	salt := userlib.RandomBytes(16)
	k, err := userlib.HMACEval(salt, append(salt, password...))
	k = k[:16]
	if err != nil {
		return err
	}

	iv := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(k, iv, data)
	value := append(salt, encryptedData...)

	newKey, err := userlib.HashKDF(k, []byte("mac"))
	if err != nil {
		return err
	}
	macKey := newKey[:16]
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return err
	}

	file = append(file, append(mac, value...))

	fileToBytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(UUID, fileToBytes)

	return nil
}

// LoadFile - This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	UUID := bytesToUUID(hash(append(username, filename...)))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return nil, errors.New("file does not exist")
	}

	var file [][]byte
	err = json.Unmarshal(entry, &file)
	if err != nil {
		return nil, err
	}

	for _, current := range file {
		mac := current[:64]
		value := current[64:]
		salt := make([]byte, 16, 16+len(password))
		copy(salt, value[:16])
		encryptedData := value[16:]

		k, err := userlib.HMACEval(salt, append(salt, password...))
		k = k[:16]
		if err != nil {
			panic(err)
		}
		currentData := userlib.SymDec(k, encryptedData)

		newKey, err := userlib.HashKDF(k, []byte("mac"))
		if err != nil {
			panic(err)
		}
		macKey := newKey[:16]
		validation, err := userlib.HMACEval(macKey, currentData)
		if err != nil {
			panic(err)
		}

		if !userlib.HMACEqual(mac, validation) {
			return nil, errors.New("data has been corrupted")
		}

		data = append(data, currentData...)
	}

	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// ShareFile - Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// ReceiveFile - Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// RevokeFile - Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}

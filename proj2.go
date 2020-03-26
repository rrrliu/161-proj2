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
	Username   string
	Password   string
	PrivateKey userlib.PrivateKeyType
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
	userlib.KeystoreSet(username, publicKey)

	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(16)
	pkKey, err := userlib.HashKDF(masterKey, []byte("private key"))
	if err != nil {
		return nil, err
	}
	pkKey = pkKey[:16]
	encryptedPrivate := userlib.SymEnc(pkKey, iv, privateKeyBytes)

	// this is to verify that the user exists later with getuser
	// we need to make it so that if this is valid, then the private key is revealed
	entry, err := json.Marshal([][]byte{mac, value, encryptedPrivate})
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

// OWNED - If the file was created by this user
const OWNED = 0

// SHARED - If the file has been shared with the user
const SHARED = 1

// StoreFile - This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	username := []byte(userdata.Username)

	UUID := bytesToUUID(hash(append(username, filename...)))
	salt := userlib.RandomBytes(16)

	var file [][]byte
	file = append(file, []byte{OWNED})
	file = append(file, salt)

	fileToBytes, err := json.Marshal(file)
	if err != nil {
		panic(err)
	}
	userlib.DatastoreSet(UUID, fileToBytes)

	userdata.AppendFile(filename, data)
}

// AppendFile - This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	uuid := bytesToUUID(hash(append(username, filename...)))
	entry, exists := userlib.DatastoreGet(uuid)
	if !exists {
		return errors.New("file does not exist")
	}
	var file [][]byte
	err = json.Unmarshal(entry, &file)
	if err != nil {
		return err
	}

	owned := true

	// this loop will no longer be necessary with proper indexing--read comment in ReceiveFile
	for file[0][0] != SHARED {
		owned = false
		uuid := bytesToUUID(file[1])
		entry, exists := userlib.DatastoreGet(uuid)
		if !exists {
			return errors.New("file does not exist")
		}
		var file [][]byte
		err = json.Unmarshal(entry, &file)
		if err != nil {
			return err
		}
	}

	// determine the k value
	// we need a flag to determine if the person owns the file or not, which we'll change in the loop above
	// if not owned file, then calculate k by decrypting with private key
	// otherwise calculate k as below
	// then run the helper
	if owned {
		salt := file[1]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		k = k[:16]
		if err != nil {
			return err
		}
		return appendHelper(file, k, uuid)

	} else {
		// PROBLEM: Our specifier requires knowledge of the file owner, but we cannot obtain that information here
		// As such, we must change the format of our specifier/index where we store SymEnc(pk, k)

		// recipientKey := userdata.PrivateKey
		// specifier := [][]byte{username, []byte(username), []byte(filename)}
		// index, err := json.Marshal(specifier)
		// if err != nil {
		// 	return err
		// }

		//
	}
	return err
}
func appendHelper(file [][]byte, k []byte, uuid uuid.UUID) (err error) {

	data := file[2]
	iv := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(k, iv, data)

	newKey, err := userlib.HashKDF(k, []byte("mac"))
	if err != nil {
		return err
	}
	macKey := newKey[:16]
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return err
	}

	file = append(file, append(mac, encryptedData...))

	fileToBytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid, fileToBytes)

	return nil
}

// LoadFile - This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

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
	salt := file[0]
	k, err := userlib.HMACEval(salt, append(salt, password...))
	k = k[:16]

	for _, current := range file[1:] {
		mac := current[:64]
		encryptedData := current[64:]

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
func (userdata *User) ShareFile(filename string, recipient string) (accessToken string, err error) {

	// THREE THINGS:
	// 1. we need to have two cases for whether the person sharing owns the file or not
	// 2. we need to make sure the person owning keeps record of who she shared to, so that
	//    she can revoke access (i.e., update k for everyone else except the revoked person)
	// 3. we gotta add a mac to ensure that the access token wasn't tampered with

	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	UUID := bytesToUUID(hash(append(username, filename...)))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return "", errors.New("file does not exist")
	}

	var file [][]byte
	err = json.Unmarshal(entry, &file)
	if err != nil {
		return "", err
	}

	// THING 2 begins here

	// CASE 1: THEY OWN FILE, must check file[0][0]
	// THING 1 in this case

	// this would become file[1]
	salt := file[0]
	k, err := userlib.HMACEval(salt, append(salt, password...))
	if err != nil {
		return "", err
	}

	// CASE 2: THEY DON'T OWN FILE, must check file[0][0]
	// they need to calculate k using their own access token

	// THING 2 ends here

	recipientKey := hash(append([]byte(recipient+filename), password...))[:16]
	iv := userlib.RandomBytes(16)

	// must include these three fields so that it is unique
	index, err := json.Marshal([][]byte{username, []byte(recipient), []byte(filename)})
	if err != nil {
		return "", err
	}

	encryptedKey := userlib.SymEnc(recipientKey, iv, k)
	userlib.DatastoreSet(bytesToUUID(hash(index)), encryptedKey)
	publicKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("recipient's PK not found")
	}

	encryptedMessage, err := userlib.PKEEnc(publicKey, append(recipientKey, index...))
	if err != nil {
		return "", err
	}
	// THING 3 at the end
	accessToken = string(encryptedMessage)

	return
}

// ReceiveFile - Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken string) error {

	// HOW SHARING WILL WORK
	// - let's say that alice shared to bob, then bob shared to cathy
	// - alice's file is called "A", bob names his version "B", and cathy names hers "C", but they all
	//   reference alice's file, "A"
	// DATABASE:
	// KEY: hash("alice" + "A")            VAL: [0, salt, SymEnc(key_a, mac + chunk, mac + chunk...])
	// KEY: hash("bob" + "B")              VAL: [1, mac + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key_a)
	// KEY: hash("cathy" + "C")            VAL: [1, mac + accessToken_c]

	// We have accessToken_i := PKEnc(PK_i, [key_i, [og_user, i, filename]]) for all direct children i of owner
	//                                                ^ aka index2
	//     and accessToken_j := PKEnc(PK_j, [key_i, [og_user, i, filename]]) for all descendants j of direct children i
	//                                                ^ aka index2
	// - bob's access token will include his recipientKey backed with alice's password as well as
	//   the index where he can find his symmetric key encrypted k
	// - cathy's access token will include bob's recipientKey backed with alice's password as well as
	//   the index where she can find his symmetric key encrypted k
	// - any of bob's eventual descendants will have to use bob's recipientKey
	// - any of cathy's eventual descendants will ALSO have to use bob's recipientKey, since cathy's "gang leader" is bob

	return nil
}

// RevokeFile - Removes target user's access.
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {

	// main idea: generate a new salt, recreate a new master key, and update
	//            the encrypted master key entry for every direct child except
	//            the encrypted master key entry of targetUsername

	// say we have          alice
	//                      /   \
	//                    bob  doug
	//                     |
	//                    cathy

	// - in our datastore we'd have
	// KEY: hash("alice" + "A")            VAL: [0, salt, SymEnc(key_a, mac + chunk, mac + chunk...])
	// KEY: hash("bob" + "B")              VAL: [1, mac + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key_a)
	// KEY: hash("cathy" + "C")            VAL: [1, mac + accessToken_c]
	// KEY: hash("doug" + "D")              VAL: [1, mac + accessToken_d]
	// KEY: hash("doug" + "alice" + "A")    VAL: SymEnc(key_d, key_a)

	// - say alice revokes bob's access
	// - she would first create a new salt' and as a result a new key_a'
	// - then in our datastore we'd have
	// KEY: hash("alice" + "A")            VAL: [0, salt', SymEnc(key_a', mac + chunk, mac + chunk...])
	// KEY: hash("bob" + "B")              VAL: [1, mac + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key_a)
	// KEY: hash("cathy" + "C")            VAL: [1, mac + accessToken_c]
	// KEY: hash("doug" + "D")              VAL: [1, mac + accessToken_d]
	// KEY: hash("doug" + "alice" + "A")    VAL: SymEnc(key_d, key_a')

	// - doug (and his future descendants) can still access the original file with key_a', but bob and cathy can no longer,
	//   since they don't have access to key_a'
	return
}

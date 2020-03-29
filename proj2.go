package proj2

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib

	"fmt"
	"strings"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/hex"
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

// User - stores confidential user information
type User struct {
	Username string
	Password string
	DecKey   userlib.PKEDecKey
	SignKey  userlib.DSSignKey
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

	_, ok := userlib.DatastoreGet(UUID)
	if ok {
		return nil, errors.New("User already exists")
	}

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

	encKey, decKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.DecKey = decKey
	userdata.SignKey = signKey

	userlib.KeystoreSet(username+"p", encKey)
	userlib.KeystoreSet(username+"d", verifyKey)

	// this is to verify that the user exists later with getuser
	// we need to make it so that if this is valid, then the private key is revealed
	encryptedDec, err := encryptPrivateKey("dec key", decKey, masterKey)
	if err != nil {
		return nil, err
	}

	encryptedSign, err := encryptPrivateKey("sign key", signKey, masterKey)
	if err != nil {
		return nil, err
	}

	entry, err := json.Marshal([][]byte{mac, value, encryptedDec, encryptedSign})
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(UUID, entry)
	return &userdata, nil
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
	saltyPassword := contents[1]
	encryptedDec := contents[2]
	encryptedSign := contents[3]

	salt := make([]byte, 16, 16+len(password))
	copy(salt, saltyPassword[:16])
	masterKey := userlib.Argon2Key([]byte(password), salt, 16)
	macKey, err := userlib.HashKDF(masterKey, []byte("mac"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	decKey, err := decryptPrivateKey("dec key", encryptedDec, masterKey)
	if err != nil {
		return nil, err
	}

	signKey, err := decryptPrivateKey("sign key", encryptedSign, masterKey)
	if err != nil {
		return nil, err
	}

	validation, _ := userlib.HMACEval(macKey, saltyPassword)
	if !userlib.HMACEqual(mac, validation) {
		return nil, errors.New("data has been corrupted")
	}

	hashedPassword := saltyPassword[16:]
	// checking if password is correct
	if userlib.HMACEqual(hashedPassword, hash(append(salt, password...))) {
		var userdata User
		userdataptr = &userdata
		userdata.Username = username
		userdata.Password = password
		userdata.DecKey = decKey
		userdata.SignKey = signKey
		return userdataptr, nil
	}

	return nil, errors.New("invalid password")
}

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.

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
	password := []byte(userdata.Password)

	file, k, fileIndex, err := userdata.getFile(filename)
	if err == nil {

		iv := userlib.RandomBytes(16)
		encryptedData := userlib.SymEnc(k, iv, data)

		newKey, err := userlib.HashKDF(k, []byte("mac"))
		if err != nil {
			panic(err)
		}
		macKey := newKey[:16]
		mac, err := userlib.HMACEval(macKey, data)
		if err != nil {
			panic(err)
		}

		fileToBytes := marshal(file[0], file[1], file[2], append(mac, encryptedData...))

		UUID := bytesToUUID(hash(fileIndex))
		userlib.DatastoreSet(UUID, fileToBytes)

	} else {

		userFileIndex := marshal(username, []byte(filename))
		UUID := bytesToUUID(hash(userFileIndex))
		salt := userlib.RandomBytes(16)

		zero := make([]byte, 16)
		childrenKey := userlib.Argon2Key(password, zero, 16)
		iv := userlib.RandomBytes(16)
		marshalledChildren := marshal()
		encryptedChildren := userlib.SymEnc(childrenKey, iv, marshalledChildren)

		fileToBytes := marshal([]byte{OWNED}, encryptedChildren, salt)
		userlib.DatastoreSet(UUID, fileToBytes)

		userdata.AppendFile(filename, data)
	}
}

// AppendFile - This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	file, k, fileIndex, err := userdata.getFile(filename)
	if err != nil {
		return err
	}

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

	UUID := bytesToUUID(hash(fileIndex))
	userlib.DatastoreSet(UUID, fileToBytes)

	return nil
}

// LoadFile - This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	file, k, _, err := userdata.getFile(filename)
	if err != nil {
		return nil, err
	}

	for _, current := range file[3:] {
		mac := current[:64]
		encryptedData := current[64:]

		currentData := userlib.SymDec(k, encryptedData)

		macKey, err := userlib.HashKDF(k, []byte("mac"))
		if err != nil {
			return nil, err
		}
		macKey = macKey[:16]
		validation, err := userlib.HMACEval(macKey, currentData)
		if err != nil {
			return nil, err
		}

		if userlib.HMACEqual(mac, validation) {
			data = append(data, currentData...)
		}
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

	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	// TODO: gotta change this too
	userFileIndex := marshal(username, []byte(filename))
	UUID := bytesToUUID(hash(userFileIndex))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return "", errors.New("file does not exist")
	}

	file := unmarshal(entry)
	var message []byte

	if file[0][0] == OWNED {

		// TODO: need to change naming convention here, cause problems with recipient "bo" with filename "balice_file"--think of malicious group of users for this one
		recipientKey := hash(append([]byte(recipient+filename), password...))[:16]
		// TODO: also need to change the naming convention here, cause problems with recipient "alicebo" with filename "balice_file"
		index := marshal(username, []byte(recipient), []byte(filename))

		// Update children
		encryptedChildren := file[1]
		zero := make([]byte, 16)
		childrenKey := userlib.Argon2Key(password, zero, 16)
		marshalledChildren := userlib.SymDec(childrenKey, encryptedChildren)
		children := unmarshal(marshalledChildren)
		children = append(children, []byte(recipient))
		marshalledChildren = marshal(children...)

		iv := userlib.RandomBytes(16)
		file[1] = userlib.SymEnc(childrenKey, iv, marshalledChildren)

		// Send the access token
		salt := file[2]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		if err != nil {
			return "", err
		}

		iv = userlib.RandomBytes(16)
		encryptedKey := userlib.SymEnc(recipientKey, iv, k)

		macKey, err := userlib.HashKDF(recipientKey, []byte("mac"))
		if err != nil {
			return "", err
		}
		macKey = macKey[:16]
		mac, err := userlib.HMACEval(macKey, k)
		if err != nil {
			return "", err
		}

		userlib.DatastoreSet(UUID, marshal(file...))
		userlib.DatastoreSet(bytesToUUID(hash(index)), append(mac, encryptedKey...))

		message = append(recipientKey, index...)

	} else if file[0][0] == SHARED {

		var ok bool
		message, ok, err = userdata.asymDecrypt(userdata.Username, file[1])
		if !ok {
			return "", errors.New("access token corrupted")
		}
		if err != nil {
			return "", err
		}
	} else {
		return "", errors.New("file is neither shared nor owned")
	}

	encryptedMessage, err := userdata.asymEncrypt(recipient, message)
	if err != nil {
		return "", err
	}

	accessToken = string(encryptedMessage)
	return accessToken, nil
}

// ReceiveFile - Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken string) error {

	accessTokenBytes := []byte(accessToken)
	message, ok, err := userdata.asymDecrypt(sender, accessTokenBytes)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("access token has been corrupted")
	}

	accessTokenBytes, err = userdata.asymEncrypt(userdata.Username, message)
	if err != nil {
		return err
	}

	fileToBytes := marshal([]byte{1}, accessTokenBytes)
	userFileIndex := marshal([]byte(userdata.Username), []byte(filename))
	UUID := bytesToUUID(hash(userFileIndex))
	userlib.DatastoreSet(UUID, fileToBytes)

	return nil
}

// RevokeFile - Removes target user's access.
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	data, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	file, _, fileIndex, err := userdata.getFile(filename)
	if err != nil {
		return err
	}

	salt := userlib.RandomBytes(16)
	k, err := userlib.HMACEval(salt, append(salt, password...))
	k = k[:16]
	iv := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(k, iv, data)

	macKey, err := userlib.HashKDF(k, []byte("mac"))
	if err != nil {
		return err
	}
	macKey = macKey[:16]
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return err
	}

	encryptedChildren := file[1]
	zero := make([]byte, 16)
	childrenKey := userlib.Argon2Key(password, zero, 16)
	marshalledChildren := userlib.SymDec(childrenKey, encryptedChildren)
	children := unmarshal(marshalledChildren)

	newChildren := [][]byte{}

	for _, item := range children {
		child := string(item)
		if child != targetUsername {
			newChildren = append(newChildren, item)
			err = userdata.storeEncryptedKey(filename, child, k)
			if err != nil {
				return err
			}
		} else {
			index := marshal(username, []byte(targetUsername), []byte(filename))
			userlib.DatastoreDelete(bytesToUUID(hash(index)))
		}
	}

	marshalledChildren = marshal(newChildren...)
	iv = userlib.RandomBytes(16)
	encryptedChildren = userlib.SymEnc(childrenKey, iv, marshalledChildren)

	fileToBytes := marshal(file[0], encryptedChildren, salt, append(mac, encryptedData...))
	UUID := bytesToUUID(hash(fileIndex))
	userlib.DatastoreSet(UUID, fileToBytes)

	return nil
}

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

func (userdata *User) storeEncryptedKey(filename string, target string, key []byte) (err error) {
	// TODO: change this index
	index := marshal([]byte(userdata.Username), []byte(target), []byte(filename))

	// TODO: also change the recipientKey
	recipientKey := hash(append([]byte(target+filename), userdata.Password...))[:16]
	UUID := bytesToUUID(hash(index))

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

	userlib.DatastoreSet(UUID, append(mac, encryptedKey...))
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
		return nil, false, errors.New(username + "'s verification key not found")
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

func (userdata *User) getFile(filename string) (file [][]byte, key []byte, fileIndex []byte, err error) {

	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	userFileIndex := marshal(username, []byte(filename))
	UUID := bytesToUUID(hash(userFileIndex))
	entry, exists := userlib.DatastoreGet(UUID)
	if !exists {
		return nil, nil, nil, errors.New("file does not exist")
	}
	file = unmarshal(entry)

	if len(file[0]) == 0 {
		return nil, nil, nil, errors.New("file corrupted")
	}

	if file[0][0] == OWNED {

		salt := file[2]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		k = k[:16]
		if err != nil {
			return nil, nil, nil, err
		}
		return file, k[:16], userFileIndex, nil

	} else if file[0][0] == SHARED {

		message, ok, err := userdata.asymDecrypt(userdata.Username, file[1])
		if !ok {
			return nil, nil, nil, errors.New("data has been corrupted 1")
		}
		if err != nil {
			return nil, nil, nil, err
		}

		recipientKey := message[:16]
		marshalledFileInfo := message[16:]

		keyUUID := bytesToUUID(hash(marshalledFileInfo))

		encodedKeyEntry, exists := userlib.DatastoreGet(keyUUID)
		if !exists {
			return nil, nil, nil, errors.New("file does not exist or permission denied")
		}

		mac := encodedKeyEntry[:64]
		encodedKey := encodedKeyEntry[64:]

		k := userlib.SymDec(recipientKey, encodedKey)

		macKey, err := userlib.HashKDF(recipientKey, []byte("mac"))
		if err != nil {
			return nil, nil, nil, err
		}
		macKey = macKey[:16]
		validation, err := userlib.HMACEval(macKey, k)
		if err != nil {
			return nil, nil, nil, err
		}

		if !userlib.HMACEqual(mac, validation) {
			return nil, nil, nil, errors.New("data has been corrupted 2")
		}

		fileInfo := unmarshal(marshalledFileInfo)
		userFileIndex := marshal(fileInfo[0], fileInfo[2])
		sharedFileUUID := bytesToUUID(hash(userFileIndex))
		sharedFileEntry, exists := userlib.DatastoreGet(sharedFileUUID)
		if !exists {
			return nil, nil, nil, errors.New("file does not exist")
		}
		sharedFile := unmarshal(sharedFileEntry)

		return sharedFile, k[:16], marshal(fileInfo[0], fileInfo[2]), nil

	} else {
		return nil, nil, nil, errors.New("could not calculate k")
	}
}

func marshal(data ...[]byte) (marshalledData []byte) {

	var dataArray [][]byte

	for _, slice := range data {
		dataArray = append(dataArray, slice)
	}

	marshalledData, err := json.Marshal(dataArray)
	if err != nil {
		panic(err)
	}

	return marshalledData
}

func unmarshal(marshalledData []byte) (data [][]byte) {

	err := json.Unmarshal(marshalledData, &data)
	if err != nil {
		panic(err)
	}

	return data
}

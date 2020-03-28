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

	UUID := bytesToUUID(hash(append(username, filename...)))
	salt := userlib.RandomBytes(16)

	var file [][]byte
	// owned vs shared
	file = append(file, []byte{OWNED})
	// who it's shared with
	file = append(file, []byte{})
	// the salt to calculate k with, for the owner
	file = append(file, salt)

	fileToBytes, err := json.Marshal(file)
	if err != nil {
		panic(err)
	}
	userlib.DatastoreSet(UUID, fileToBytes)

	userdata.AppendFile(filename, data)
}

func (userdata *User) getFile(filename string) (file [][]byte, key []byte, err error) {

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
		return nil, nil, err
	}

	if file[0][0] == OWNED {

		salt := file[2]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		k = k[:16]
		if err != nil {
			return nil, nil, err
		}
		return file, k, nil

	} else if file[0][0] == SHARED {

		// this is the digital signature part which i randomly said was length 16, needs to be verified as well
		ds = file[1][:64]
		accessToken = file[1][64:]

		marshalledMessage, err := userlib.PKEDec(userdata.PrivateKey, accessToken)
		if err != nil {
			return nil, nil, err
		}
		var message [][]byte
		err = json.Unmarshal(marshalledMessage, &message)
		if err != nil {
			return nil, nil, err
		}

		recipientKey := message[0]
		fileInfo := message[1]

		keyUUID := bytesToUUID(hash(fileInfo))

		encodedKeyEntry, exists := userlib.DatastoreGet(keyUUID)
		if !exists {
			return errors.New("file does not exist")
		}
		// we still need to make sure the mac is correct
		keyMAC := encodedKey[:64]
		encodedKey := encodedKey[64:]

		k := userlib.SymDec(recipientKey, encodedKey)

		return file, k, nil
	}

	return file, k, errors.New("could not calculate k")
}

// AppendFile - This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	file, k, err := userdata.getFile(filename)
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

	username := []byte(userdata.Username)
	uuid := bytesToUUID(hash(append(username, filename...)))
	userlib.DatastoreSet(uuid, fileToBytes)

	return nil
}

// LoadFile - This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	file, k, err := userdata.getFile(filename)
	if err != nil {
		return nil, err
	}

	for _, current := range file[3:] {
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
	privateKey := userdata.PrivateKey
	signKey := userdata.SignKey

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
	if file[0][0] == OWNED {
		// Update children
		encryptedChildren := file[1]
		children := SymDec(password, encryptedChildren)
		children = append(children, recipient)
		iv := userlib.RandomBytes(16)
		file[1] = SymEnc(password, iv, children)

		// Send the access token

		salt := file[2]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		if err != nil {
			return "", err
		}

		recipientKey := hash(append([]byte(recipient+filename), password...))[:16]

		// must include these three fields so that it is unique
		index, err := json.Marshal([][]byte{username, []byte(recipient), []byte(filename)})
		if err != nil {
			return "", err
		}

		iv := userlib.RandomBytes(16)
		encryptedKey := userlib.SymEnc(recipientKey, iv, k)
		userlib.DatastoreSet(bytesToUUID(hash(index)), encryptedKey)
		publicKey, ok := userlib.KeystoreGet(recipient + "p")
		if !ok {
			return "", errors.New("recipient's PK not found")
		}

		message := append(recipientKey, index...)

	} else {
		// Send the access token
		ds := file[1][:64]
		myAccessToken := file[1][64:]
		verifyKey, ok := userlib.KeySToreGet(username + "d")
		if !ok {
			return "", errors.New("sharer's verification key not found")
		}

		message, err := PKEDec(privateKey, myAccessToken)
		if err != nil {
			return "", err
		}

		err = DSVerify(verifyKey, ds, message)
		if err != nil {
			return "", err
		}
	}

	encryptedMessage, err := userlib.PKEEnc(publicKey, append(recipientKey, index...))
	if err != nil {
		return "", err
	}
	// TODO: digital signature
	signature, err := userlib.DSSign(signKey, message)
	if err != nil {
		return "", err
	}

	accessToken = string(signature[:64] + encryptedMessage)

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
	// KEY: hash("alice" + "A")            VAL: [0, SymEnc(a, ["bob"]), salt, SymEnc(key, mac + chunk), SymEnc(key, mac + chunk), ...]
	// KEY: hash("bob" + "B")              VAL: [1, ds + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key)
	// KEY: hash("cathy" + "C")            VAL: [1, ds + accessToken_c]

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

	// We have accessToken_i := PKEnc(PK_i, [key_i, [og_user, i, filename]]) for all direct children i of owner
	//                                                ^ aka index2
	//     and accessToken_j := PKEnc(PK_j, [key_i, [og_user, i, filename]]) for all descendants j of direct children i
	//                                                ^ aka index2

	// - in our datastore we'd have
	// KEY: hash("alice" + "A")            VAL: [0, SymEnc(a, ["bob", "doug"]), salt, SymEnc(key_a, mac + chunk, mac + chunk...])
	// KEY: hash("bob" + "B")              VAL: [1, ds + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key_a)
	// KEY: hash("cathy" + "C")            VAL: [1, ds + accessToken_c]
	// KEY: hash("doug" + "D")              VAL: [1, ds + accessToken_d]
	// KEY: hash("doug" + "alice" + "A")    VAL: SymEnc(key_d, key_a)

	// - say alice revokes bob's access
	// - she would first create a new salt' and as a result a new key_a'
	// - then in our datastore we'd have
	// KEY: hash("alice" + "A")            VAL: [0, salt', SymEnc(key_a', mac + chunk, mac + chunk...])
	// KEY: hash("bob" + "B")              VAL: [1, ds + accessToken_b]
	// KEY: hash("bob" + "alice" + "A")    VAL: SymEnc(key_b, key_a)
	// KEY: hash("cathy" + "C")            VAL: [1, ds + accessToken_c]
	// KEY: hash("doug" + "D")              VAL: [1, ds + accessToken_d]
	// KEY: hash("doug" + "alice" + "A")    VAL: SymEnc(key_d, key_a')

	// - doug (and his future descendants) can still access the original file with key_a', but bob and cathy can no longer,
	//   since they don't have access to key_a'
	return
}

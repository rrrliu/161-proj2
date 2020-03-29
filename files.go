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
	password := []byte(userdata.Password)

	// TODO: when the filename already exists, make sure it's shared with the same people and maintains the same salt
	//		 but only if the user owns that file, otherwise do the regular scheme
	//		 okay, what if alice, "alice_file" > bob, "bob_file" > cathy, "cathy_file"
	// 		 and then, alice.StoreFile("alice_file", "dfaniefjawf") should change whatever is in alice_file and keep it shared
	ogFile, k, err := userdata.getFile(filename)
	if err == nil {
		newFile := make([][]byte, 3, 4)
		copy(newFile, ogFile[:3])
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

		newFile = append(newFile, append(mac, encryptedData...))

		fileToBytes, err := json.Marshal(newFile)
		if err != nil {
			panic(err)
		}

		username := []byte(userdata.Username)
		uuid := bytesToUUID(hash(append(username, filename...)))
		userlib.DatastoreSet(uuid, fileToBytes)

	} else {

		UUID := bytesToUUID(hash(append(username, filename...)))
		salt := userlib.RandomBytes(16)

		var file [][]byte
		// owned vs shared
		file = append(file, []byte{OWNED})
		// who it's shared with
		zero := make([]byte, 16)
		childrenKey := userlib.Argon2Key(password, zero, 16)
		iv := userlib.RandomBytes(16)
		encryptedChildren := userlib.SymEnc(childrenKey, iv, []byte{})
		file = append(file, encryptedChildren)
		// the salt to calculate k with, for the owner
		file = append(file, salt)

		fileToBytes, err := json.Marshal(file)
		if err != nil {
			panic(err)
		}
		userlib.DatastoreSet(UUID, fileToBytes)

		userdata.AppendFile(filename, data)
	}
}

func (userdata *User) getFile(filename string) (file [][]byte, key []byte, err error) {

	username := []byte(userdata.Username)
	password := []byte(userdata.Password)

	uuid := bytesToUUID(hash(append(username, filename...)))
	entry, exists := userlib.DatastoreGet(uuid)
	if !exists {
		return nil, nil, errors.New("file does not exist")
	}
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
		marshalledMessage, ok, err := userdata.asymDecrypt(userdata.Username, file[1])
		if !ok {
			return nil, nil, errors.New("data has been corrupted 1")
		}
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
			return nil, nil, errors.New("file does not exist")
		}

		mac := encodedKeyEntry[:64]
		encodedKey := encodedKeyEntry[64:]

		k := userlib.SymDec(recipientKey, encodedKey)

		macKey, err := userlib.HashKDF(recipientKey, []byte("mac"))
		if err != nil {
			return nil, nil, err
		}
		macKey = macKey[:16]
		validation, err := userlib.HMACEval(macKey, k)
		if err != nil {
			return nil, nil, err
		}

		if !userlib.HMACEqual(mac, validation) {
			return nil, nil, errors.New("data has been corrupted 2")
		}

		return file, k, nil
	}

	return file, nil, errors.New("could not calculate k")
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

		if !userlib.HMACEqual(mac, validation) {
			return nil, errors.New("data has been corrupted 3")
		}

		data = append(data, currentData...)
	}

	return data, nil
}

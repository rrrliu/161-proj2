package proj2

import (
	"errors"

	"github.com/cs161-staff/userlib"
)

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

package proj2

import (
	"encoding/json"
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

	var message []byte

	publicKey, ok := userlib.KeystoreGet(recipient + "p")
	recipientKey := hash(append([]byte(recipient+filename), password...))[:16]
	index, err := json.Marshal([][]byte{username, []byte(recipient), []byte(filename)})

	if file[0][0] == OWNED {
		// Update children
		encryptedChildren := file[1]
		children := userlib.SymDec(password, encryptedChildren)
		children = append(children, []byte(recipient)...)
		iv := userlib.RandomBytes(16)
		file[1] = userlib.SymEnc(password, iv, children)

		// Send the access token

		salt := file[2]
		k, err := userlib.HMACEval(salt, append(salt, password...))
		if err != nil {
			return "", err
		}

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

		userlib.DatastoreSet(bytesToUUID(hash(index)), append(mac, encryptedKey...))
		if !ok {
			return "", errors.New("recipient's PK not found")
		}

		message = append(recipientKey, index...)

	} else {
		// Send the access token
		ds := file[1][:64]
		myAccessToken := file[1][64:]
		verifyKey, ok := userlib.KeystoreGet(string(append(username, []byte("d")...)))
		if !ok {
			return "", errors.New("sharer's verification key not found")
		}

		message, err = userlib.PKEDec(privateKey, myAccessToken)
		if err != nil {
			return "", err
		}

		err = userlib.DSVerify(verifyKey, ds, message)
		if err != nil {
			return "", err
		}
	}

	encryptedMessage, err := userlib.PKEEnc(publicKey, append(recipientKey, index...))
	if err != nil {
		return "", err
	}

	signature, err := userlib.DSSign(signKey, message)
	if err != nil {
		return "", err
	}

	accessToken = string(append(signature[:64], encryptedMessage...))

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

	accessTokenBytes := []byte(accessToken)
	ok, err := userdata.verifyAccessToken(accessTokenBytes)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("access token has been corrupted")
	}

	uuid := bytesToUUID(hash([]byte(userdata.Username + filename)))
	userlib.DatastoreSet(uuid, accessTokenBytes)

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

	fileBytes, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	userdata.StoreFile(filename, fileBytes)

	file, newKey, err := userdata.getFile(filename)
	if err != nil {
		return err
	}

	encryptedChildren := file[1]
	passKey := []byte(userdata.Password)
	children := userlib.SymDec(passKey, encryptedChildren)

	for _, item := range children {
		child := string(item)
		if child != targetUsername {
			err = userdata.storeEncryptedKey(filename, child, newKey)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (userdata *User) storeEncryptedKey(filename, target string, key []byte) (err error) {
	index, err := json.Marshal([][]byte{
		[]byte(userdata.Username),
		[]byte(target),
		[]byte(filename),
	})
	if err != nil {
		return err
	}
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

// Helper function to verify access token
func (userdata *User) verifyAccessToken(accessTokenBytes []byte) (ok bool, err error) {
	signature := accessTokenBytes[:64]
	myAccessToken := accessTokenBytes[64:]

	username := userdata.Username
	privateKey := userdata.PrivateKey

	verifyKey, ok := userlib.KeystoreGet(string(username + "d"))
	if !ok {
		return false, errors.New("sharer's verification key not found")
	}

	message, err := userlib.PKEDec(privateKey, myAccessToken)
	if err != nil {
		return false, err
	}

	err = userlib.DSVerify(verifyKey, signature, message)
	if err != nil {
		return false, err
	}

	return true, nil
}

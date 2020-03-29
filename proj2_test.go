package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGet(t *testing.T) {
	clear()
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error("Failed to get user", err2)
		return
	}

	_, err3 := GetUser("alice", "bar")
	if err3 == nil {
		t.Error("Failed to account for wrong password", err3)
		return
	}

	_, err4 := GetUser("bob", "fubar")
	if err4 == nil {
		t.Error("Failed to account for wrong username", err4)
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("abe", "lincoln")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	input := []byte("Four score and seven years")

	a := []byte("Four score ")
	u.StoreFile("gettysburg", a)

	b := []byte("and seven years")
	u.AppendFile("gettysburg", b)

	output, err := u.LoadFile("gettysburg")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}
	if !reflect.DeepEqual(input, output) {
		t.Error("Downloaded file is not the same", input, output)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magicString string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magicString, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magicString)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

// in this test, alice shares to bob, then bob shares to cathy
// we also make sure that the new guy, david, cannot use bob or cathy's access tokens
func TestShareLayered(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "alice")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob, err := InitUser("bob", "bob")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}
	cathy, err := InitUser("cathy", "cathy")
	if err != nil {
		t.Error("Failed to initialize cathy", err)
		return
	}

	aliceFile := []byte("This is Alice's file")
	alice.StoreFile("alice_file", aliceFile)

	// alice sharing "alice_file" with bob
	bobAccessToken, err := alice.ShareFile("alice_file", "bob")
	if err != nil {
		t.Error("Failed to share alice's file with bob", err)
		return
	}
	err = bob.ReceiveFile("bob_alice_file", "alice", bobAccessToken)
	if err != nil {
		t.Error("Bob could not receive alice's file", err)
		return
	}

	// bob sharing his version of "alice_file" with cathy
	cathyAccessToken, err := bob.ShareFile("bob_alice_file", "cathy")
	if err != nil {
		t.Error("Bob failed to share alice's file with cathy", err)
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "bob", cathyAccessToken)
	if err != nil {
		t.Error("Cathy could not receive alice's file through bob", err)
		return
	}

	// the new guy david comes in to try to use bob and cathy's access token
	david, err := InitUser("david", "david")
	if err != nil {
		t.Error("Failed to initialize david", err)
		return
	}
	err = david.ReceiveFile("david_alice_file", "alice", bobAccessToken)
	if err == nil {
		t.Error("The new guy, david, could use bob's access token, saying it was from alice")
		return
	}
	err = david.ReceiveFile("david_alice_file", "bob", bobAccessToken)
	if err == nil {
		t.Error("The new guy, david, could use bob's access token, saying it was from bob")
		return
	}
	err = david.ReceiveFile("david_alice_file", "alice", cathyAccessToken)
	if err == nil {
		t.Error("The new guy, david, could use cathy's access token, saying it was from alice")
		return
	}
	err = david.ReceiveFile("david_alice_file", "cathy", cathyAccessToken)
	if err == nil {
		t.Error("The new guy, david, could use cathy's access token, saying it was from cathy")
		return
	}

	// we make sure that cathy is loading the proper file
	cathyAliceFile, err := cathy.LoadFile("cathy_alice_file")
	if err != nil {
		t.Error("Cathy failed to download the alice file after sharing", err)
		return
	}
	if !reflect.DeepEqual(aliceFile, cathyAliceFile) {
		t.Error("Shared file from alice is not the same", aliceFile, cathyAliceFile)
		return
	}

}

// alice shares to bob and david, then bob shares to cathy
// we also make sure that bob and cathy can't use david's access token
func TestRevoke(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "alice")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob, err := InitUser("bob", "bob")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}
	cathy, err := InitUser("cathy", "cathy")
	if err != nil {
		t.Error("Failed to initialize cathy", err)
		return
	}
	david, err := InitUser("david", "david")
	if err != nil {
		t.Error("Failed to initialize david", err)
		return
	}

	aliceFile := []byte("This is Alice's file")
	alice.StoreFile("alice_file", aliceFile)

	// sending to bob and david
	bobAccessToken, err := alice.ShareFile("alice_file", "bob")
	if err != nil {
		t.Error("Failed to share alice's file with bob", err)
		return
	}
	err = bob.ReceiveFile("bob_alice_file", "alice", bobAccessToken)
	if err != nil {
		t.Error("Bob could not receive alice's file", err)
		return
	}
	davidAccessToken, err := alice.ShareFile("alice_file", "david")
	if err != nil {
		t.Error("Failed to share alice's file with david", err)
		return
	}
	err = david.ReceiveFile("david_alice_file", "alice", davidAccessToken)
	if err != nil {
		t.Error("David could not receive alice's file", err)
		return
	}
	// bob sending to cathy
	cathyAccessToken, err := bob.ShareFile("bob_alice_file", "cathy")
	if err != nil {
		t.Error("Failed to share alice's file with cathy", err)
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "bob", cathyAccessToken)
	if err != nil {
		t.Error("Cathy could not receive alice's file", err)
		return
	}

	// at this point, alice will revoke access to bob
	err = alice.RevokeFile("alice_file", "bob")
	if err != nil {
		t.Error("Alice could not revoke from bob", err)
		return
	}

	// now we check to see whether each of bob and cathy can load the file or append to it
	// by our method, they should not be able to load the file at all
	bobFailedLoad, err := bob.LoadFile("bob_alice_file")
	if err == nil && reflect.DeepEqual(bobFailedLoad, aliceFile) {
		t.Error("Bob could read alice's file after being revoked access", err)
		return
	}
	cathyFailedLoad, err := cathy.LoadFile("cathy_alice_file")
	if err == nil && reflect.DeepEqual(cathyFailedLoad, aliceFile) {
		t.Error("Cathy could read alice's file after her boss was revoked", err)
		return
	}

	err = bob.AppendFile("bob_alice_file", []byte("hehe im bob"))
	if err == nil {
		t.Error("Bob was able to append to the file after his access was revoked")
		return
	}
	err = cathy.AppendFile("cathy_alice_file", []byte("hehe im cathy"))
	if err == nil {
		t.Error("Cathy was able to append to the file after her boss was revoked")
		return
	}

	// we check that bob and cathy can't use david's access token
	err = bob.ReceiveFile("bob_alice_file", "alice", davidAccessToken)
	if err == nil {
		t.Error("Bob could use david's access token, saying it was from alice")
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "alice", davidAccessToken)
	if err == nil {
		t.Error("Cathy could use david's access token, saying it was from alice")
		return
	}
	err = bob.ReceiveFile("bob_alice_file", "david", davidAccessToken)
	if err == nil {
		t.Error("Bob could use david's access token, saying it was from david")
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "david", davidAccessToken)
	if err == nil {
		t.Error("Cathy could use david's access token, saying it was from david")
		return
	}

	// lastly, we check whether alice and david can still load and append
	_, err = alice.LoadFile("alice_file")
	if err != nil {
		t.Error("Alice could not access the file after revoking", err)
		return
	}
	_, err = david.LoadFile("david_alice_file")
	if err != nil {
		t.Error("David could not access the file even though his access was not revoked", err)
		return
	}

	err = alice.AppendFile("alice_file", []byte{})
	if err != nil {
		t.Error("Alice could not append to the file after revoking", err)
		return
	}
	err = david.AppendFile("david_alice_file", []byte{})
	if err != nil {
		t.Error("David could not append to the file even though his access was not revoked", err)
		return
	}
}

func TestInvalidUsername(t *testing.T) {
	clear()
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	_, err2 := InitUser("alice", "foobar")
	if err2 == nil {
		t.Error("Created a user with the same username as another user")
		return
	}
}

// alice shares a file with bob, then bob shares a file with alice, but alice overwrites her file she shared with bob's file
func TestShareOverwrite(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "alice")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	bob, err := InitUser("bob", "bob")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}
	cathy, err := InitUser("cathy", "cathy")
	if err != nil {
		t.Error("Failed to initialize cathy", err)
		return
	}

	aliceFile := []byte("This is Alice's file")
	alice.StoreFile("alice_file", aliceFile)

	// alice sharing "alice_file" with bob
	bobAccessToken, err := alice.ShareFile("alice_file", "bob")
	if err != nil {
		t.Error("Failed to share alice's file with bob", err)
		return
	}
	err = bob.ReceiveFile("bob_alice_file", "alice", bobAccessToken)
	if err != nil {
		t.Error("Bob could not receive alice's file", err)
		return
	}

	// bob sharing his version of "alice_file" with cathy
	cathyAccessToken, err := bob.ShareFile("bob_alice_file", "cathy")
	if err != nil {
		t.Error("Bob failed to share alice's file with cathy", err)
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "bob", cathyAccessToken)
	if err != nil {
		t.Error("Cathy could not receive alice's file through bob", err)
		return
	}

	// make sure that bob and cathy can still access after alice stores different text under the same name
	aliceNewFile := []byte("This is Alice's new file")
	alice.StoreFile("alice_file", aliceNewFile)

	bobAliceFile, err := bob.LoadFile("bob_alice_file")
	if err != nil {
		t.Error("Bob failed to download the alice file after alice stored it again", err)
		return
	}
	if !reflect.DeepEqual(aliceNewFile, bobAliceFile) {
		t.Error("Shared file from alice is not the same for bob after alice stored it again", aliceNewFile, bobAliceFile)
		return
	}
	cathyAliceFile, err := cathy.LoadFile("cathy_alice_file")
	if err != nil {
		t.Error("Cathy failed to download the alice file after alice stored it again", err)
		return
	}
	if !reflect.DeepEqual(aliceNewFile, cathyAliceFile) {
		t.Error("Shared file from alice is not the same for cathy after alice stored it again", aliceNewFile, cathyAliceFile)
		return
	}

	// make sure that alice and cathy can still access after bob stores different text in alice_file
	bobNewFile := []byte("This is Bob's file now muhahaha")
	bob.StoreFile("bob_alice_file", bobNewFile)

	aliceFile, err = alice.LoadFile("alice_file")
	if err != nil {
		t.Error("Alice failed to download the alice file after bob stored it again", err)
		return
	}
	if !reflect.DeepEqual(bobNewFile, aliceFile) {
		t.Error("Shared file from alice is not the same for alice after bob stored it again", bobNewFile, aliceFile)
		return
	}
	cathyAliceFile, err = cathy.LoadFile("cathy_alice_file")
	if err != nil {
		t.Error("Cathy failed to download the alice file after bob stored it again", err)
		return
	}
	if !reflect.DeepEqual(bobNewFile, cathyAliceFile) {
		t.Error("Shared file from alice is not the same for cathy after bob stored it again", bobNewFile, cathyAliceFile)
		return
	}
}

// miscellaneous sharing stuff
func TestSharingMisc(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "alice")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	_, err = alice.ShareFile("alice_file", "bob")
	if err == nil {
		t.Error("Shared with a nonexistent user")
		return
	}
	err = alice.RevokeFile("alice_file", "bob")
	if err == nil {
		t.Error("Revoked from a nonexistent user")
		return
	}

	// make sure than a user "alicebob" can't just get direct access to the file by having that username
}

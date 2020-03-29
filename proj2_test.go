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

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
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
func TestShare_1(t *testing.T) {
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
	bobFile := []byte("This is Bob's file")
	// we choose to call bob's other file this name to see if receiving a file overwrites existing file, which it should
	bob.StoreFile("bob_alice_file", bobFile)

	// bob sharing fictitious "bob_alice_file" to cathy with message, "This is Bob's file"
	cathyAccessToken1, err := bob.ShareFile("bob_alice_file", "cathy")
	if err != nil {
		t.Error("Bob failed to share file with cathy", err)
		return
	}
	err = cathy.ReceiveFile("cathy_bob_file", "bob", cathyAccessToken1)
	if err != nil {
		t.Error("Cathy could not receive bob's file", err)
		return
	}

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
	cathyAccessToken2, err := bob.ShareFile("bob_alice_file", "cathy")
	if err != nil {
		t.Error("Bob failed to share alice's file with cathy", err)
		return
	}
	err = cathy.ReceiveFile("cathy_alice_file", "bob", cathyAccessToken2)
	if err != nil {
		t.Error("Cathy could not receive alice's file through bob", err)
		return
	}

	cathyAliceFile, err := cathy.LoadFile("cathy_alice_file")
	if err != nil {
		t.Error("Cathy ailed to download the alice file after sharing", err)
		return
	}
	if !reflect.DeepEqual(aliceFile, cathyAliceFile) {
		t.Error("Shared file from alice is not the same", aliceFile, cathyAliceFile)
		return
	}
	cathyBobFile, err := cathy.LoadFile("cathy_bob_file")
	if err != nil {
		t.Error("Cathy failed to download the bob file after sharing", err)
		return
	}
	if !reflect.DeepEqual(aliceFile, cathyBobFile) {
		t.Error("Shared file from bob is not the same", aliceFile, cathyAliceFile)
		return
	}
}

// alice shares to bob and david, then bob shares to cathy
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
	_, err = bob.LoadFile("bob_alice_file")
	if err == nil {
		t.Error("Bob was able to view the file after his access was revoked")
		return
	}
	_, err = cathy.LoadFile("cathy_alice_file")
	if err == nil {
		t.Error("Cathy was able to view the file after her boss was revoked")
		return
	}

	err = bob.AppendFile("bob_alice_file", []byte{})
	if err == nil {
		t.Error("Bob was able to append to the file after his access was revoked ")
		return
	}
	err = cathy.AppendFile("cathy_alice_file", []byte{})
	if err == nil {
		t.Error("Cathy was able to append to the file after her boss was revoked")
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

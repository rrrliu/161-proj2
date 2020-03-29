package proj2

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

// main idea: generate a new salt, recreate a new master key, and update
//            the encrypted master key entry for every direct child except
//            the encrypted master key entry of targetUsername

// say we have          alice
//                      /   \
//                    bob  doug
//                     |
//                    cathy

// COMMENTS FOR REVOKEFILE
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

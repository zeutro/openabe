from __future__ import print_function
import pyopenabe

print("Testing Python bindings for PyOpenABE...")

openabe = pyopenabe.PyOpenABE()

cpabe = openabe.CreateABEContext("CP-ABE")

cpabe.generateParams()

cpabe.keygen("|two|three|", "alice")

pt1 = b"hello world!"
ct = cpabe.encrypt("((one or two) and three)", pt1)
print("ABE CT: ", len(ct))

pt2 = cpabe.decrypt("alice", ct)
print("PT: ", pt2)
assert pt1 == pt2, "Didn't recover the message!"

print("Testing key import")

msk = cpabe.exportSecretParams()
mpk = cpabe.exportPublicParams()
uk = cpabe.exportUserKey("alice")

cpabe2 = openabe.CreateABEContext("CP-ABE")

cpabe2.importSecretParams(msk)
cpabe2.importPublicParams(mpk)
cpabe2.importUserKey("alice", uk)

ct = cpabe2.encrypt("((one or two) and three)", pt1)
print("ABE CT: ", len(ct))

pt2 = cpabe2.decrypt("alice", ct)
print("PT: ", pt2)
assert pt1 == pt2, "Didn't recover the message!"

print("CP-ABE Success!")


pke = openabe.CreatePKEContext()

pke.keygen("user1")

ct1 = pke.encrypt("user1", pt1)
print("PKE CT: ", len(ct1))

pt2 = pke.decrypt("user1", ct1)
assert pt1 == pt2, "Didn't recover the message!"
print("PKE Success!")


pksig = openabe.CreatePKSIGContext()

pksig.keygen("user2")

sig = pksig.sign("user2", pt1)
print("PKSIG: ", len(sig))

if pksig.verify("user2", pt1, sig):
    print("PKSIG Success!")
else:
    print("ERROR during verify!")


kpabe = openabe.CreateABEContext("KP-ABE")

kpabe.generateParams()

kpabe.keygen("((one or three) and date < April 18, 2018)", "bob")

ct = kpabe.encrypt("|one|date=February 1, 2018|two", pt1)
print("KP-ABE CT size: ", len(ct))

pt2 = kpabe.decrypt("bob", ct)
print("PT: ", pt2)
assert pt1 == pt2, "Didn't recover the message!"

print("Testing key imports")
msk = kpabe.exportSecretParams()
mpk = kpabe.exportPublicParams()
uk = kpabe.exportUserKey("bob")

kpabe2 = openabe.CreateABEContext("KP-ABE")

kpabe2.importSecretParams(msk)
kpabe2.importPublicParams(mpk)
kpabe2.importUserKey("bob", uk)

ct = kpabe.encrypt("|one|date=February 1, 2018|two", pt1)
print("KP-ABE CT size: ", len(ct))
pt2 = kpabe.decrypt("bob", ct)
assert pt1 == pt2, "Didn't recover the message!"

print("KP-ABE Success!")
print("All tests passed!")

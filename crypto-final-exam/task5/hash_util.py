import hashlib, json, os, sys
def h(f):
    with open(f,"rb") as f: d = f.read()
    return {"md5":hashlib.md5(d).hexdigest(),
            "sha1":hashlib.sha1(d).hexdigest(),
            "sha256":hashlib.sha256(d).hexdigest()}
file = sys.argv[1] if len(sys.argv)>1 else "original.txt"
cur = h(file)
j = "task5/hashes.json"
if os.path.exists(j):
    old = json.load(open(j))
    print("INTEGRITY CHECK:", "PASS" if old==cur else "FAIL – TAMPERED!")
else:
    json.dump(cur, open(j,"w"), indent=2)
    print("Original hashes saved")
print("MD5:   ", cur["md5"])
print("SHA1:  ", cur["sha1"])
print("SHA256:", cur["sha256"])

import sys, os, json, hashlib
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
import mode_a_build as M, ubifs_inventory as INV
T, _ = M.load_verifier(M.DEFAULT_VERIFIER)
img, out = sys.argv[1], sys.argv[2]
d = open(img, "rb").read()
man = {}
for cid, vol in ((4, "rootfs"), (5, "usrdata")):
    E = INV.inventory(M.volume_of(T, d, cid)[0], with_content=True)["entries"]
    root = os.path.join(out, vol)
    for p, r in sorted(E.items(), key=lambda kv: kv[0].count("/")):
        dst = root + p
        k = r["mode"] & INV.S_IFMT
        if k == INV.S_IFDIR: os.makedirs(dst, exist_ok=True)
        elif k == INV.S_IFREG:
            os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "wb").write(r["content"])
            man[f"{vol}{p}"] = {"sha256": r["sha256"], "size": r["size"], "mode": oct(r["mode"])}
        elif k == INV.S_IFLNK:
            man[f"{vol}{p}"] = {"link": r["target"], "mode": oct(r["mode"])}
json.dump(man, open(os.path.join(out, "manifest.json"), "w"), indent=0)
print(img, len(man))

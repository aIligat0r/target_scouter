from os import listdir
import hashlib

import mmh3


def sha256hash(icon_path: str) -> str:
    with open(icon_path, "rb") as f:
        icon_bytes = f.read()
        sha256_hash = hashlib.sha256(icon_bytes).hexdigest()
    return sha256_hash


def murmurhash(icon_path: str) -> int:
    with open(icon_path, "rb") as f:
        icon_bytes = f.read()
        murmur_hash = mmh3.hash(icon_bytes)
    return murmur_hash


def favicons_hasher():
    icons_files = ["./favicons/" + f for f in listdir("./favicons/")]
    icons_files.remove("./favicons/.empty")

    for icon in icons_files:
        sha256_hash = sha256hash(icon)
        murmur_hash = murmurhash(icon)
        print(f"file: {icon}\nsha256: {sha256_hash}\nmmh3: {murmur_hash}\n")


if __name__ == "__main__":
    favicons_hasher()

import hashlib
import webbrowser
from context_menu import menus

def sha256sum(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan(filenames, params):
    names = "".join(filenames)
    url = "https://www.virustotal.com/gui/file/" + str(sha256sum(str(names)))
    webbrowser.open(url, new=0, autoraise=True)

if __name__ == '__main__':
    fc = menus.FastCommand('Scan with VirusTotal...', type='FILES', python=scan)
    fc.compile()

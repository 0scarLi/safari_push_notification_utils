try:
    import json
except ImportError:
    import simplejson as json

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import hashlib
import zipfile
from M2Crypto import SMIME
from apnsclient import Session, Message, APNs

ICONS = [
    "icon.iconset/icon_16x16.png",
    "icon.iconset/icon_16x16@2x.png",
    "icon.iconset/icon_32x32.png",
    "icon.iconset/icon_32x32@2x.png",
    "icon.iconset/icon_128x128.png",
    "icon.iconset/icon_128x128@2x.png",
]

ICON_PATH = 'PATH_TO_YOUR_PACKAGES'

WEBSITE_JSON = {
    "allowedDomains": ["https://foo.bar.com"],
    "urlFormatString": "https://foo.bar.com/%@/?%@",
    "webServiceURL": "https://foo.bar.com/",
    "websiteName": "WEBSITE NAME",
    "websitePushID": "your.website.push.id",
}


def create_website_json(token):
    content = WEBSITE_JSON
    content["authenticationToken"] = token

    return json.dumps(content)


def create_manifest(website_json):
    manifest = {
        'website.json': hashlib.sha1(website_json).hexdigest(),
    }
    for m in ICONS:
        with open(ICON_PATH + m) as f:
            manifest[m] = hashlib.sha1(f.read()).hexdigest()
    return json.dumps(manifest)


def create_signature(manifest, certificate, key, password):
    def passwordCallback(*args, **kwds):
        return password

    smime = SMIME.SMIME()
    # need to cast to string since load_key doesnt work with unicode paths
    smime.load_key(str(key), certificate, callback=passwordCallback)
    pk7 = smime.sign(
        SMIME.BIO.MemoryBuffer(manifest),
        flags=SMIME.PKCS7_DETACHED | SMIME.PKCS7_BINARY
    )

    pem = SMIME.BIO.MemoryBuffer()
    pk7.write(pem)
    # convert pem to der
    der = ''.join(
        l.strip() for l in pem.read().split('-----')[2].splitlines()
    ).decode('base64')

    return der


def create_push_package(token, push_cert, push_key):
    website_json = create_website_json(token)
    manifest = create_manifest(website_json)
    signature = create_signature(
        manifest, push_cert, push_key, "")
    zip_file = StringIO()
    zf = zipfile.ZipFile(zip_file, 'w')
    zf.writestr('signature', signature)
    zf.writestr('manifest.json', manifest)
    zf.writestr('website.json', website_json)
    for m in ICONS:
        file_path = ICON_PATH + m
        with open(file_path) as f:
            zf.writestr(m, f.read())
    zf.close()
    return zip_file


def send_push_notifications(tokens, title, message, cert_file, url_args=None):
    url_args = url_args or ["", ""]
    session = Session()
    conn = session.get_connection("push_production", cert_file=cert_file)
    apns = APNs(conn)
    payload = {}
    payload["aps"] = {}
    payload["aps"]["alert"] = {
        "title": title,
        "body": message,
    }
    payload["aps"]["url-args"] = url_args
    message = Message(tokens, payload=payload)
    apns.send(message)

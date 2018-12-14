#
#   Code By M4rK0v
#

from Crypto.Hash import MD5, SHA, SHA224, SHA256, SHA384, SHA512
import codecs
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util import number
import base64
import urllib.parse
from argparse import ArgumentParser


VERSION = '1.0'
HASH_ASN1 = {
    'MD5':     b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'SHA-1':   b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'SHA-224': b'\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c',
    'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}


def UrlDecode(msg):
    return urllib.parse.unquote(msg)


def UrlEncode(msg):
    return urllib.parse.quote(msg)


def removePadding(msg):
    if msg[0] == 0:
        msg = msg[1:]
    if msg[0] == 1:
        msg = msg[1:]
    while True:
        if msg[0] == 255:
            msg = msg[1:]
        else:
            break
    if msg[0] == 0:
        msg = msg[1:]
        for (hashname, asn1code) in HASH_ASN1.items():
            if asn1code in msg:
                msg = msg[(len(asn1code)):]
                return hashname, msg
        return -1, msg
    else:
        return -1, -1

def loadKey(filePath):
    keyFile = open(filePath, 'rb')
    key = RSA.importKey(keyFile.read())
    keyFile.close()
    return key

def main():
    cliParser = ArgumentParser(description="RSA encryption Tool")
    subparsers = cliParser.add_subparsers(help='sub-command help', dest='command')

    # Add subparser
    parserEncrypt = subparsers.add_parser('encrypt', help='RSA encrypt')
    parserDecrypt = subparsers.add_parser('decrypt', help='RSA Decrypt')
    parserSign = subparsers.add_parser('sign', help='RSA Sign')
    parserVerify = subparsers.add_parser('verify', help='RSA Verify')


    # add arg to Encrypt
    parserEncrypt.add_argument('-pub', '--public', help='Public Key', required=True)
    parserEncrypt.add_argument('-i', '--input', help="Input Clear text", required=True)

    # add arg to Decrypt
    parserDecrypt.add_argument('-pri', '--private', help='Private Key', required=True)
    parserDecrypt.add_argument('-i', '--input', help="Input Cipher text", required=True)

    # add arg to Sign
    parserSign.add_argument('-pri', '--private',  help='Private Key', required=True)
    parserSign.add_argument('-b', '--base64', help="Base64 Decode", action='store_true')
    parserSign.add_argument('-u', '--url', help="URL Decode", action='store_true')
    parserSign.add_argument('-hh', '--hash', help="hash function {md5, sha-1, sha-224, sha-256, sha-384, sha-512}", required=True)
    parserSign.add_argument('-i', '--input', help="Input Clear text", required=True)

    # add arg to Verify
    parserVerify.add_argument('-pub', '--public', help='Public Key', required=True)
    parserVerify.add_argument('-b', '--base64', help="Base64 Decode", action='store_true')
    parserVerify.add_argument('-u', '--url', help="URL Decode", action='store_true')
    parserVerify.add_argument('-i', '--input', help="Input Signature text", required=True)

    cliParser.add_argument('-v', '--version', action='version', version='RSA Tool {} - M4rK0v'.format(VERSION), help='Version of this tool')
    args = cliParser.parse_args()

    # Load input
    try:
        inputFile = open(args.input, 'rb')
    except (FileExistsError, FileNotFoundError) as e:
        print(e)
        return -1
    input = inputFile.read()
    input = input.strip()

    # check to do encrypt
    if args.command == 'encrypt':
        try:
            key = loadKey(args.public)
        except (FileNotFoundError, FileExistsError) as e:
            print("[!] Key file not found.")
            return 0
        except (ValueError, TypeError, IndexError) as e:
            print("[!] Key has improper format.")
            return 0
        pubKey = PKCS1_v1_5.new(key)
        cipher = key.encrypt(input, 32)[0]
        print("[+] Cipher Text:")
        print(base64.b64encode(cipher))
    # check to
    elif args.command == 'decrypt':
        try:
            key = loadKey(args.private)
        except (FileNotFoundError, FileExistsError) as e:
            print("[!] Key file not found.")
            return 0
        except (ValueError, TypeError, IndexError) as e:
            print("[!] Key has improper format.")
            return 0
        cipher = base64.b64decode(input)
        clearText = key.decrypt(cipher)
        print("[+] Clear Text:")
        print(clearText)

    elif args.command == 'sign':
        try:
            key = loadKey(args.private)
        except (FileNotFoundError, FileExistsError) as e:
            print("[!] Key file not found.")
            return 0
        except (ValueError, TypeError, IndexError) as e:
            print("[!] Key has improper format.")
            return 0

        keySign = PKCS1_v1_5.new(key)
        if args.hash:
            if args.hash.lower() == 'md5':
                digest = MD5.new()

            elif args.hash.lower() == 'sha-1':
                digest = SHA.new()

            elif args.hash.lower() == 'sha-224':
                digest = SHA224.new()

            elif args.hash.lower() == 'sha-256':
                digest = SHA256.new()

            elif args.hash.lower() == 'sha-384':
                digest = SHA384.new()

            elif args.hash.lower() == 'SHA-512':
                digest = SHA512.new()

            else:
                print("[!] Hash algorithm not found.")
                return 0

            digest.update(input)
            sign = keySign.sign(digest)
            print("[+] Hex Formart:")
            print(codecs.getencoder('hex')(sign))
            # check if encode base64
            if args.base64:
                signBase64 = base64.b64encode(sign)
                print("[+] Base64 format:")
                print(signBase64)

                # check if encode url
                if args.url:
                    signURL = UrlEncode(signBase64)
                    print("[+] URL encoded:")
                    print(signURL)

        else:
            return -1
    elif args.command == 'verify':
        try:
            key = loadKey(args.public)
        except (FileNotFoundError, FileExistsError) as e:
            print("[!] Key file not found.")
            return 0
        except (ValueError, TypeError, IndexError) as e:
            print("[!] Key has improper format.")
            return 0
        # Check to decode URL
        if args.url:
            input = UrlDecode(input.decode())

        # Check to decode Base64
        if args.base64:
            input = base64.b64decode(input)

        # Convert Input Bytes to Long
        sigLong = number.bytes_to_long(input)

        clearSigLong = pow(sigLong, key.e, key.n)

        # Convert clear Sign Long to Bytes
        clearSigByte = number.long_to_bytes(clearSigLong)

        print(codecs.getencoder('hex')(clearSigByte))
        hashArg, clearSig = removePadding(clearSigByte)
        if hashArg==-1 or clearSig ==-1:
            print("[!] Error! in remove padding.")
        else:
            print("[+] Hash algorithm: {}".format(hashArg))
            print("[+] Clear Signature: ")
            print(codecs.getencoder('hex')(clearSig))


if __name__ == '__main__':
    main()









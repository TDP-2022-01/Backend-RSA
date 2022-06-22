from flask import Flask
from flask_restx import Resource, Api, cors
import sympy as smp

api = Api()
app = Flask(__name__)
api.init_app(app)

def rsaEncrypt(publicKey: str, msg: str):
    n, e = extractKey(publicKey)
    encrypt = ''

    for ch in msg:
        ch = ord(ch)
        numbers = str((ch ** e) % n)
        for num in numbers:
            encrypt += chr(int(num) + 64)
        encrypt += '&'

    return encrypt

def rsaDecrypt(privateKey: str, cypherText: str):
    n, d = extractKey(privateKey)
    decrypt = ''
    digit = ''

    for ch in cypherText:
        if ch != '&':
            digit += str(ord(ch) - 64)
        else:
            number = int(digit)
            decrypt += chr(((number ** d) % n))
            digit = ''

    return decrypt

def find_e(z: int):
    e = 2
    while e < z:
        if gcd(e, z)==1:
            return e
        e += 1

def find_d(e: int, z: int):
    d = 2
    while d < z:
        if ((d*e) % z)==1:
            return d
        d += 1

def gcd(x: int, y: int):
    small,large = (x,y) if x<y else (y,x)

    while small != 0:
        temp = large % small
        large = small
        small = temp

    return large


def generateKeys():
    p = smp.randprime(900, 1000)

    while(True):
        q = smp.randprime(900, 1000)
        if q != p:
            break

    n = int(p) * int(q)
    z = (int(p)-1)*(int(q)-1)

    e = find_e(z)
    d = find_d(e, z)

    sharedPart = str(n)
    publicKey = sharedPart + '$' + str(e)
    privateKey = sharedPart + '$' + str(d)

    return publicKey, privateKey


def extractKey(key: str):
    parts = key.split('$')
    n = int(parts[0])
    N = int(parts[1])

    return n, N

@api.route('/generate-keys')
class GenerateKeys(Resource):
    @cors.crossdomain(origin="*")
    def get(self):
        pub, priv = generateKeys()
        response = {
                'publicKey': pub,
                'privateKey': priv
                }

        return response

@api.route('/encrypt-keys/<string:public_key>/<string:message>')
class Encrypt_message(Resource):
    @cors.crossdomain(origin="*")
    def get(self, public_key, message):
        response = {
            'cryptMessage': rsaEncrypt(public_key, message)
        }
        return response

@api.route('/decrypt-message/<string:private_key>/<string:message>')
class Decrypt_message(Resource):
    @cors.crossdomain(origin="*")
    def get(self, private_key, message):
        response = {
            'decryptMessage': rsaDecrypt(private_key, message)
        }
        return response

if __name__ == '__main__':
    app.run()

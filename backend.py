from flask import Flask
from flask_cors import CORS, cross_origin
from flask_restx import Resource, Api, fields
import sympy as smp
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='RSA Project')

ns = api.namespace('RSA', description='RSA Project')
CORS(app)

encrypt_model = api.model('Encrypt', {
    'public_key': fields.String(required=True),
    'message': fields.String(required=True)
    })

decrypt_model = api.model('Decrypt', {
    'private_key': fields.String(required=True),
    'message': fields.String(required=True)
    })

def rsaEncrypt(publicKey: str, msg: str):
    n, e = extractKey(publicKey)
    encrypt = ''

    for ch in msg:
        ch = ord(ch)
        numbers = str(pow(ch, e, n))
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
            decrypt += chr(pow(number, d, n))
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

@api.route('/generate-keys', methods=['GET'])
class GenerateKeys(Resource):
    def get(self):
        pub, priv = generateKeys()
        response = {
                'public_key': pub,
                'private_key': priv
                }

        return response

@ns.route('/encrypt')
class Encrypt_message(Resource):
    @ns.expect(encrypt_model)
    @cross_origin(headers=['Content-Type'])
    def post(self):
        args = api.payload
        response = {
            'cryptMessage': rsaEncrypt(args['public_key'], args['message'])
        }
        return response

@ns.route('/decrypt')
class Decrypt_message(Resource):
    @ns.expect(decrypt_model)
    @cross_origin(headers=['Content-Type'])
    def post(self):
        args = api.payload
        response = {
            'decryptMessage': rsaDecrypt(args['private_key'], args['message'])
        }
        return response

if __name__ == '__main__':
    app.run()

from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import os
import json
import base64
from os.path import exists
import datetime

# TODO: import additional modules as required

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

def pad(s):
    bs = 16
    s = s+ (bs -len(s) % bs) * chr(bs-len(s)%bs)
    return s

def unpad(s):
    bs = 16
    s = s[:-ord(s[len(s)-1:])]
    return s

def checkAccessTable():
    with open('./access_table.json', 'r+') as f:
        access_table = json.loads(f.read())
        for did in access_table.keys():
            new_list = []
            for ele in access_table[did]:
                if datetime.datetime.now() < datetime.datetime(ele['time'][0], ele['time'][1], ele['time'][2], ele['time'][3], ele['time'][4], ele['time'][5]):
                    new_list.append(ele)
            access_table[did] = new_list
        f.seek(0)
        f.truncate()
        f.write(json.dumps(access_table))

class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"

class login(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        if 'msg' in data.keys() and 'signature' in data.keys():
            user = data['msg'].split()[2]
            if exists('./userpublickeys/{}.pub'.format(user)):
                key = RSA.importKey(open('./userpublickeys/{}.pub'.format(user)).read())
                h = SHA256.new(data['msg'].encode())
                try:
                    pkcs1_15.new(key).verify(h, base64.b64decode(data['signature'].encode()))
                    success = True
                    print(data['msg'])
                    if data['msg'] != 'Client1 as {} logs into the Server'.format(user) and data['msg'] != 'Client2 as {} logs into the Server'.format(user):
                        success = False
                except:
                    success = False
            else:
                success = False
        else:
            success = False
        # TODO: Implement login functionality
        '''
            # TODO: Verify the signed statement.
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
        '''
        if success:
            session_token = base64.b64encode(os.urandom(16)).decode() # TODO: Generate session token
            f = open("session_key.json", 'r+')
            session_keys=json.loads(f.read())
            session_keys[user] = session_token
            f.seek(0)
            f.truncate()
            f.write(json.dumps(session_keys))
            f.close()
            
            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        else:
            response = {
	        'status': 700,
                'message': 'Login Failed'
        }
        return jsonify(response)

class checkout(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        session_token = data['session_token']
        did = data['did']

        with open("session_key.json", 'r') as f:
            session_keys = json.loads(f.read())
            for key, value in session_keys.items():
                if session_token == value:
                    user = key
                    break
            else:
                response = {
                    'status':700,
                    'message': 'Not a valid token!',
                }
                return jsonify(response)
        with open("meta-data.json", 'r') as f1:
            meta_data = json.loads(f1.read())
            if did not in meta_data.keys():
                response = {
                    'status':704,
                    'message': 'Check out failed since file not found on the server',
                }
                return jsonify(response)
            if user == meta_data[did]['owner']:
                if 'key' in meta_data[did].keys():
                    key = meta_data[did]['key']
                    iv = meta_data[did]['iv']
                    sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
                    sk = PKCS1_OAEP.new(sk)
                    key = sk.decrypt(base64.b64decode((key.encode())))
                    iv = base64.b64decode(iv.encode())
                    with open("./documents/{}".format(did), 'r+') as f2:
                        content = f2.read()
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        plaintext = unpad(cipher.decrypt(base64.b64decode(content.encode())).decode())
                        response = {
                            'status':200,
                            'message': 'Document Successfully checked out',
                            'content': plaintext
                        }
                        return jsonify(response)
                elif 'signature' in meta_data[did].keys():
                    with open("./documents/{}".format(did), 'r+') as f3:
                        content = f3.read()
                        signature = base64.b64decode(meta_data[did]['signature'].encode())
                        h = SHA256.new(content.encode())
                        pk = RSA.importKey(open('../certs/secure-shared-store.pub').read())
                        try:
                            pkcs1_15.new(pk).verify(h, signature)
                            response = {
                                'status':200,
                                'message': 'Document Successfully checked out',
                                'content': content
                            }
                            return jsonify(response)
                        except:
                            response = {
                                'status':703,
                                'message': 'Check out failed due to broken integrity'
                            }
                            return jsonify(response)
            with open("./access_table.json",'r+') as f4:
                access_table = json.loads(f4.read())
                if did not in access_table.keys():
                    response = {
                        'status':702,
                        'message': 'Access denied to check out'
                    }
                    return jsonify(response)
                for ele in access_table[did]:
                    if (ele['tuid'] == user or ele['tuid'] == '0') and (ele['access_right'] == '2' or ele['access_right'] == '3') and datetime.datetime.now() < datetime.datetime(ele['time'][0], ele['time'][1], ele['time'][2], ele['time'][3], ele['time'][4], ele['time'][5]):
                        if ele['tuid'] == '0' and (ele['access_right'] == '2' or ele['access_right'] == '3'):
                            for elee in access_table[did]:
                                if elee['tuid'] == user and elee['access_right'] == '1':
                                    response = {
                                        'status':702,
                                        'message': 'Access denied to check out'
                                    }
                                    return jsonify(response)
                        if 'key' in meta_data[did].keys():
                            key = meta_data[did]['key']
                            iv = meta_data[did]['iv']
                            sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
                            sk = PKCS1_OAEP.new(sk)
                            key = sk.decrypt(base64.b64decode((key.encode())))
                            iv = base64.b64decode(iv.encode())
                            with open("./documents/{}".format(did), 'r+') as f5:
                                content = f5.read()
                                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                                plaintext = unpad(cipher.decrypt(base64.b64decode(content.encode())).decode())
                                response = {
                                    'status':200,
                                    'message': 'Document Successfully checked out',
                                    'content': plaintext
                                }
                                return jsonify(response)
                        elif 'signature' in meta_data[did].keys():
                            with open("./documents/{}".format(did), 'r+') as f6:
                                content = f6.read()
                                signature = base64.b64decode(meta_data[did]['signature'].encode())
                                h = SHA256.new(content.encode())
                                pk = RSA.importKey(open('../certs/secure-shared-store.pub').read())
                                try:
                                    pkcs1_15.new(pk).verify(h, signature)
                                    response = {
                                        'status':200,
                                        'message': 'Document Successfully checked out',
                                        'content': content
                                    }
                                    return jsonify(response)
                                except:
                                    response = {
                                        'status':703,
                                        'message': 'Check out failed due to broken integrity'
                                    }
                            return jsonify(response)
        response = {
            'status':702,
            'message': 'Access denied to check out'
        }
        return jsonify(response)


        
    '''
        Expected response status codes
        1) 200 - Document Successfully checked out
        2) 702 - Access denied to check out
        3) 703 - Check out failed due to broken integrity
        4) 704 - Check out failed since file not found on the server
        5) 700 - Other failures
    '''

class checkin(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        session_token = data['session_token']
        did = data['did']
        content = data['content']
        sf = data['sf']
        with open("session_key.json", 'r') as f:
            session_keys = json.loads(f.read())
            for key, value in session_keys.items():
                if session_token == value:
                    user = key
                    break
            else:
                response = {
                    'status':700,
                    'message': 'Not a valid token!',
                }
                return jsonify(response)
        with open("meta-data.json", 'r+') as f1:
            meta_data = json.loads(f1.read())
            f1.seek(0)
            if did not in meta_data.keys():
                if sf == '1':
                    key = os.urandom(16)
                    iv = os.urandom(16)
                    content = pad(content)
                    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                    ciphertext = base64.b64encode(cipher.encrypt(content.encode())).decode()
                    with open("./documents/{}".format(did), 'w+') as f2:
                        f2.truncate()
                        f2.write(ciphertext)
                        pk = RSA.importKey(open('../certs/secure-shared-store.pub').read())
                        pk = PKCS1_OAEP.new(pk)
                        key = base64.b64encode(pk.encrypt(key)).decode()
                        iv = base64.b64encode(iv).decode()
                        meta_data[did] = {'owner':user, 'flag':sf, 'key':key, 'iv':iv}
                        f1.truncate()
                        f1.write(json.dumps(meta_data))
                    with open("./access_table.json", 'r+') as f2:
                        access_table = json.loads(f2.read())
                        access_table[did] = []
                        f2.seek(0)
                        f2.truncate()
                        f2.write(json.dumps(access_table))
                    success = True
                elif sf == '2':
                    sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
                    h = SHA256.new(content.encode())
                    signature = base64.b64encode(pkcs1_15.new(sk).sign(h)).decode()
                    with open("./documents/{}".format(did), 'w+') as f3:
                        f3.truncate()
                        f3.write(content)
                        meta_data[did] = {'owner':user, 'flag':sf, 'signature':signature}
                        f1.truncate()
                        f1.write(json.dumps(meta_data))
                    with open("./access_table.json", 'r+') as f2:
                        access_table = json.loads(f2.read())
                        access_table[did] = []
                        f2.seek(0)
                        f2.truncate()
                        f2.write(json.dumps(access_table))
                    success = True
            else:
                if meta_data[did]['owner'] == user:
                    if sf == '1':
                        key = os.urandom(16)
                        iv = os.urandom(16)
                        content = pad(content)
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                        ciphertext = base64.b64encode(cipher.encrypt(content.encode())).decode()
                        with open("./documents/{}".format(did), 'w+') as f4:
                            f4.truncate()
                            f4.write(ciphertext)
                            pk = RSA.importKey(open('../certs/secure-shared-store.pub').read())
                            pk = PKCS1_OAEP.new(pk)
                            key = base64.b64encode(pk.encrypt(key)).decode()
                            iv = base64.b64encode(iv).decode()
                            meta_data[did] = {'owner':user, 'flag':sf, 'key':key, 'iv':iv}
                            f1.truncate()
                            f1.write(json.dumps(meta_data))
                        with open("./access_table.json", 'r+') as f2:
                            access_table = json.loads(f2.read())
                            access_table[did] = []
                            f2.seek(0)
                            f2.truncate()
                            f2.write(json.dumps(access_table))
                        success = True
                    elif sf == '2':
                        sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
                        h = SHA256.new(content.encode())
                        signature = base64.b64encode(pkcs1_15.new(sk).sign(h)).decode()
                        with open("./documents/{}".format(did), 'w+') as f3:
                            f3.seek(0)
                            f3.truncate()
                            f3.write(content)
                            meta_data[did] = {'owner':user, 'flag':sf, 'signature':signature}
                            f1.seek(0)
                            f1.truncate()
                            f1.write(json.dumps(meta_data))
                        with open("./access_table.json", 'r+') as f2:
                            access_table = json.loads(f2.read())
                            access_table[did] = []
                            f2.seek(0)
                            f2.truncate()
                            f2.write(json.dumps(access_table))
                        success = True
                else:
                    with open("./access_table.json",'r+') as f5:
                        access_table = json.loads(f5.read())
                        if did not in access_table.keys():
                            success = False
                        else:
                            for ele in access_table[did]:
                                if (ele['tuid'] == user or ele['tuid'] == '0') and (ele['access_right'] == '1' or ele['access_right'] == '3') and (datetime.datetime.now() < datetime.datetime(ele['time'][0], ele['time'][1], ele['time'][2], ele['time'][3], ele['time'][4], ele['time'][5])):
                                    if ele['tuid'] == '0' and (ele['access_right'] == '1' or ele['access_right'] == '3'):
                                        for elee in access_table[did]:
                                            if elee['tuid'] == user and elee['access_right'] == '2':
                                                print('here')
                                                success = False
                                        else:
                                            success = True
                                        if success == False:
                                            break                                
                                    if sf == '1':
                                        key = os.urandom(16)
                                        iv = os.urandom(16)
                                        content = pad(content)
                                        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                                        ciphertext = base64.b64encode(cipher.encrypt(content.encode())).decode()
                                        with open("./documents/{}".format(did), 'w+') as f6:
                                            f6.truncate()
                                            f6.write(ciphertext)
                                            pk = RSA.importKey(open('../certs/secure-shared-store.pub').read())
                                            pk = PKCS1_OAEP.new(pk)
                                            key = base64.b64encode(pk.encrypt(key)).decode()
                                            iv = base64.b64encode(iv).decode()
                                            meta_data[did] = {'owner':meta_data[did]['owner'], 'flag':sf, 'key':key, 'iv':iv}
                                            f1.seek(0)
                                            f1.truncate()
                                            f1.write(json.dumps(meta_data))
                                        success = True
                                        break
                                    elif sf == '2':
                                        sk = RSA.importKey(open('../certs/secure-shared-store.key').read())
                                        h = SHA256.new(content.encode())
                                        signature = base64.b64encode(pkcs1_15.new(sk).sign(h)).decode()
                                        with open("./documents/{}".format(did), 'w+') as f7:
                                            f7.seek(0)
                                            f7.truncate()
                                            f7.write(content)
                                            meta_data[did] = {'owner':meta_data[did]['owner'], 'flag':sf, 'signature':signature}
                                            f1.seek(0)
                                            f1.truncate()
                                            f1.write(json.dumps(meta_data))
                                        success = True
                                        break
                                else:
                                    success = False
                                break
                            else:
                                success = False
                 
        if success:
            response = {
                'status': 200,
                'message': 'Document Successfully checked in',
            }
        else:
            response = {
                'status': 700,
                'message': 'Access denied to check in'
            }
        return jsonify(response)

    # TODO: Implement checkin functionality
    '''
        Expected response status codes:
        1) 200 - Document Successfully checked in
        2) 702 - Access denied to check in
        3) 700 - Other failures
    '''

class grant(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        session_token = data['session_token']
        did = data['did']
        tuid = data['tuid']
        access_right = data['access_right']
        time = data['time']
        if time <= 0 or (access_right not in ['1','2','3']):
            response = {
                'status':700,
                'message': 'Time should be postive and access right should be 1, 2 or 3',
            }
            return jsonify(response)
        with open("session_key.json", 'r') as f:
            session_keys = json.loads(f.read())
            for key, value in session_keys.items():
                if session_token == value:
                    user = key
                    break
            else:
                response = {
                    'status':700,
                    'message': 'Not a valid token!',
                }
                return jsonify(response)
        with open("meta-data.json", 'r+') as f:
            meta_data = json.loads(f.read())
            if did not in meta_data.keys():
                response = {
                    'status':704,
                    'message': 'Grant access failed since file not found on the server',
                }
                return jsonify(response)
            if user == meta_data[did]['owner']:
                with open("access_table.json", 'r+') as f1:
                    access_table = json.loads(f1.read())
                    time = datetime.datetime.now() + datetime.timedelta(seconds=time)
                    time = [time.year, time.month, time.day, time.hour, time.minute, time.second]
                    for ele in range(len(access_table[did])):
                        print(tuid == access_table[did][ele]['tuid'])
                        if tuid == access_table[did][ele]['tuid']:  
                            access_table[did][ele] = {'tuid':tuid, 'access_right':access_right, 'time':time}
                            break
                    else:
                        access_table[did].append({'tuid':tuid, 'access_right':access_right, 'time':time})
                    f1.seek(0)
                    f1.truncate()
                    f1.write(json.dumps(access_table))
                response = {
                    'status':200,
                    'message': 'Successfully granted access',
                }    
            else:
                response = {
                    'status':702,
                    'message': 'Access denied to grant access',
                }
                return jsonify(response)    
        # TODO: Implement grant functionality
        return jsonify(response)
    '''
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    '''

class delete(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        session_token = data['session_token']
        did = data['did']
        with open("session_key.json", 'r') as f:
            session_keys = json.loads(f.read())
            for key, value in session_keys.items():
                if session_token == value:
                    user = key
                    break
            else:
                response = {
                    'status':700,
                    'message': 'Not a valid token!',
                }
                return jsonify(response)
        with open("meta-data.json", 'r+') as f:
            meta_data = json.loads(f.read())
            if did not in meta_data.keys():
                response = {
                    'status':704,
                    'message': 'Delete failed since file not found on the server',
                }
                return jsonify(response)
            if user == meta_data[did]['owner']:
                del meta_data[did]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(meta_data))
            else:
                response = {
                    'status':702,
                    'message': 'Access denied to delete file',
                }
                return jsonify(response)

        with open('./access_table.json', 'r+') as f:
            access_table = json.loads(f.read())
            if did not in access_table.keys():
                response = {
                    'status':704,
                    'message': 'Check out failed since file not found on the server',
                }
                return jsonify(response)
            del access_table[did]
            f.seek(0)
            f.truncate()
            f.write(json.dumps(access_table))
        os.remove("./documents/{}".format(did))
        response = {
            'status':200,
            'message': 'Successfully deleted the file',
        }
        return jsonify(response)
        # TODO: Implement delete functionality
        '''
             Expected response status codes:
             1) 200 - Successfully deleted the file
             2) 702 - Access denied to delete file
             3) 704 - Delete failed since file not found on the server
             4) 700 - Other failures
	'''

class logout(Resource):
    def post(self):
        checkAccessTable()
        data = request.get_json()
        session_token = data['session_token']
        with open("session_key.json", 'r+') as f:
            session_keys = json.loads(f.read())
            for key, value in session_keys.items():
                if session_token == value:
                    user = key
                    del session_keys[user]
                    f.seek(0)
                    f.truncate()
                    f.write(json.dumps(session_keys))
                    break
            else:
                response = {
                    'status':700,
                    'message': 'Failed to log out',
                }
                return jsonify(response)
        # TODO: Implement logout functionality
        response = {
            'status':200,
            'message': 'Successfully logged out',
        }
        return jsonify(response)
        '''
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
	'''

api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def main():
    secure_shared_service.run(debug=True)

if __name__ == '__main__':
	main()

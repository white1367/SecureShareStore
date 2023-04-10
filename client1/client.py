import requests
import certifi
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json
import base64
import os
from os.path import exists
import shutil
# TODO: import additional modules as required

gt_username = 'hkang331'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'

node_certificate = './certs/{}.crt'.format(os.getcwd().split('/')[-1])
node_key = './certs//{}.key'.format(os.getcwd().split('/')[-1])
''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
    '''
    node_certificate is the name of the certificate file of the client node (present inside certs).
    node_key is the name of the private key of the client node (present inside certs).
    body parameter should in the json format.
    '''
    request_url= 'https://{}/{}'.format(server_name,action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url= request_url,
        data=json.dumps(body),
        headers = request_headers,
        cert = (node_certificate, node_key),
     )
    with open(gt_username, 'wb') as f:
        f.write(response.content)
    return response

''' You can begin modification from here'''
def login(uid, usk):

    msg = 'Client1 as {} logs into the Server'.format(uid)
    try:
        key = RSA.importKey(open("./userkeys/{}".format(usk)).read())
    except:
        print("User key not found\n")
        exit(0)
    h = SHA256.new(msg.encode())
    

    signature = pkcs1_15.new(key).sign(h)
    signature = base64.b64encode(signature).decode()
    
    form = {'msg':msg, 'signature':signature}

    response = post_request(server_name, 'login', form, node_certificate, node_key)
    '''
    # TODO: Accept the
        - user-id
        - name of private key file(should be
        present in the userkeys folder) of the user.
         Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (action = 'login') using
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    '''
    return response

def checkin(session_token):
    did = input("Enter DID: ")
    sf = input("Enter security flag: ")
    if exists("./documents/checkout/{}".format(did)):
        shutil.move("./documents/checkout/{}".format(did),"./documents/checkin/{}".format(did))
        
    try:
        with open("./documents/checkin/{}".format(did), 'r') as f:
            content = f.read()
    except:    
        print("File not exist in checkin folder!")
        return
    
    form = {'did': did, 'session_token':session_token,'content':content, 'sf':sf}
    response = post_request(server_name, 'checkin', form, node_certificate, node_key)
    response = json.loads(response.text)
    if response['message'] == 'Not a valid token!':
        print(response['message'])
        print('Please login again')
        exit(0)
    print(response['message'])
    '''
        # TODO: Accept the
        - DID
        - security flag (1 for confidentiality  and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin') using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    '''
    return

def checkout(session_token):
    did = input("Enter DID: ")

    form = {'did': did, 'session_token':session_token}
    response = post_request(server_name, 'checkout', form, node_certificate, node_key)
    response = json.loads(response.text)
    if response['status'] == 200:
        print(response['message'])
        with open("./documents/checkout/{}".format(did), 'w+') as f:
            f.seek(0)
            f.truncate()
            f.write(response['content'])
    elif response['message'] == 'Not a valid token!':
        print(response['message'])
        print('Please login again')
        exit(0)
    else:
        print(response['message'])
    '''
        # TODO: Accept the DID.
        Send request to server with required parameters (action = 'checkout') using post_request()
    '''
    return

def grant(session_token):
    did = input("Enter DID: ")
    tuid = input("Enter target User ID: ")
    access_right = input("Enter access right (1)checkin (2)checkout (3)both: ")
    if access_right not in ['1','2','3']:
        print("Access_right should be 1, 2 or 3")
        return
    time = int(input("Enter time (in seconds): "))
    if time <= 0:
        print("Time should be positve")
        return
    form = {'did': did, 'session_token':session_token, 'tuid':tuid, 'access_right': access_right, 'time': time}
    response = post_request(server_name, 'grant', form, node_certificate, node_key)
    response = json.loads(response.text)
    if response['message'] == 'Not a valid token!':
        print(response['message'])
        print('Please login again')
        exit(0)
    print(response['message'])
    '''
        # TODO: Accept the
        - DID
        - target user to whom access should be granted (0 for all user)
        - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
        - time duration (in seconds) for which acess is granted
        Send request to server with required parameters (action = 'grant') using post_request()
    '''
    return

def delete(session_token):
    did = input("Enter DID: ")

    form = {'did': did, 'session_token':session_token}
    response = post_request(server_name, 'delete', form, node_certificate, node_key)
    response = json.loads(response.text)
    if response['message'] == 'Not a valid token!':
        print(response['message'])
        print('Please login again')
        exit(0)
    print(response['message'])
    '''
        # TODO: Accept the DID to be deleted.
	Send request to server with required parameters (action = 'delete')
	using post_request().
    '''
    return

def logout(session_token):
    files = os.listdir('./documents/checkout')
    for did in files:
        try:
            with open("./documents/checkout/{}".format(did), 'r') as f:
                content = f.read()
        except:    
            print("File not exist in checkin folder!")
            return
        form = {'did': did, 'session_token':session_token,'content':content, 'sf':'2'}
        post_request(server_name, 'checkin', form, node_certificate, node_key)
    
    form = {'session_token':session_token}
    response = post_request(server_name, 'logout', form ,node_certificate, node_key)
    print(json.loads(response.text)['message'])
    '''
        # TODO: Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    '''
    print('Bye')
    exit() #exit the program

def main():
    '''
    request_url= 'https://{}'.format(server_name)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.get(
        url= request_url,
        headers = request_headers,
        cert = (node_certificate, node_key),
     )
    print(response)
    '''
    with open('../CA/CA.crt','rb') as f1:
        with open(certifi.where(),'ab') as f2:
            f2.write(f1.read())
    uid = input('Input User ID: ')
    usk = input('Input User key: ')
    response = login(uid, usk)
    response = json.loads(response.text)
    if response['status'] != 200:
        print("User ID or User key is wrong\n")
        exit(0)
    else:
        print("Successful login!")
        session_token =response['session_token']
        f = open("session_key.json", 'r+')
        session_key=json.loads(f.read())
        session_key[uid] = session_token
        f.seek(0)
        f.truncate()
        f.write(json.dumps(session_key))
        f.close()
    
    
    while True:
        print("1. Checkin\n2. Checkout\n3. Grant\n4. Delete\n5. Logout")
        option = input("Choise: ")    
    
        if option == '1':
            checkin(session_token)
        elif option == '2':
            checkout(session_token)
        elif option == '3':
            grant(session_token)
        elif option == '4':
            delete(session_token)
        elif option == '5':
            logout(session_token)
        else:
            print("Wrong option!\n")
    '''
	# TODO: Authenticate the user by calling login.
	If the login is successful, provide the following options to the user
	1. Checkin
	2. Checkout
	3. Grant
	4. Delete
	5. Logout
	The options will be the indices as shown above. For example, if user
	enters 1, it must invoke the Checkin function. Appropriate functions
	should be invoked depending on the user input. Users should be able to
	perform these actions in a loop until they logout. This mapping should 
	be maintained in your implementation for the options.
     '''

if __name__ == '__main__':
	main()

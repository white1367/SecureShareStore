# SecureShareStore
This is a secure shared store project for users to upload files storing at the server.

The project folder contains:
1. CA - Represents the Certificate Authority and contains the CA certificates
2. server - Represents the server. It contains server certificates and the 3S application code. The 3S server is implemented using Python Flask.
3. client1 - Represents one of the client nodes. client.py has the implementation of the client. 
4. client2 - Represents another client node and the environment should be similar to client1.


## 3S Implementation Details
After a 3S server starts, a client node can make requests to the server. Let's assume that client nodes have a
discovery service that allows them to find the hostname where 3S runs. The hostname, in this case, is secureshared-store. The certificate for the server contains secure-shared-store as the common name of the server. Whenever the client node makes a request, mutual authentication is performed, and a secure communication channel is established between the client node and the server. Here we make use of nginx to perform mutual
authentication (MTLS). Every request from the client node should include the certificate of the client node for
authentication.
As mentioned before, the 3S service should enable functions such as login, checkin, checkout, grant, delete,
and logout. You will have to complete the skeleton code provided for the server and client to achieve these
functionalities. Details are as follows:
1. login(User UID, UserPrivateKey): This call allows a client node to generate necessary statements to convince the 3S server that requests made by the client are for the user having UID as its user-id. The client node will take UID and UserPrivate key as two separate inputs from the user. The filename of the key is to provided as input as opposed to the key value itself. A user's private key should only be used to generate the necessary statements and then erased. The statement should be of the form "ClientX as UserY logs into the Server" where X represents the client-id and Y represents the user-id. On successful login, the server should return a unique session-token for the user. The session token will have to be included in all the subsequent requests and would play the role of the statement in those requests. Also, you must ensure that each user has a unique UID. You can assume that a given client node only handles requests of a single user in one session (if a user logs in successfully from another client, the previous session will be invalidated).
2. checkin(Document DID, SecurityFlag): A document with its id (DID) is sent to the server over the secure channel that was established when the session was initiated. If the document already exists on the server, it may be overwritten along with its meta-data. If a new document is checked in, the user at the client node becomes the owner of the document. The owner does not change if the document is updated (using checkin) by an authorized user who is not the owner. You can make use of any scheme to ensure that the documents created by different users have unique DIDs. The SecurityFlag specifies how document data should be stored on the server. The documents that are to be checked into the server must be present in the documents/checkin folder within the client directory [It is already created within client1]. On the server, the documents that are checked in must be stored in the documents folder within the server directory. 
When the Security Flag is set as Confidentiality (to be represented by "1"), the server generates a random AES key for the document, uses it for encryption and stores data in the encrypted form. To decrypt the data at a later time, this key is also encrypted using the server's public key and stored with document meta-data. When the Security Flag is set as Integrity (to be represented by "2"), the server stores a document along with a signed copy.
3. checkout(Document DID): After a session is established, a user can use this function to request a specific document based on the document identifier (DID) over the secure channel to the server. The request is granted only if the checkout request is made either by the owner of the document or if performed by a user who is authorized to perform this action. If successful, a copy of the document is sent to the client node. The server would have maintained information about documents (e.g., meta-data) during checkin that allows it to locate the requested document, decrypt it and send the document back to the requestor. Once the document is checked out, it must be stored in the documents/checkout folder within the Client directory.
When a request is made for a document stored with Confidentiality as the SecurityFlag, the server locates the encrypted document and its key, decrypts the data and sends it back over the secure channel. Similarly, when a request is made for a document stored with Integrity as the SecurityFlag, the signature of the document must be verified before sending a copy to the client.
Additionally, when a request is made to checkin a document that is checked out in the current active session, the client must move (not copy) the document from the "/document/checkout" folder into the "/document/checkin" folder. The client implementation handles the transfer of these files between the folders automatically.
4. grant(Document DID, TargetUser TUID, AccessRight R, time T): Grant can only be issued by the owner of the document. This will change the defined access control policy to allow the target user (TUID) to have authorization for the specified action (R) for the specified document (DID). AccessRight can either be checkin (which must be represented by input 1), checkout (2) or both (3) for time duration T (in seconds). If the TargetUser is ALL (TUID=0), the authorization is granted to all the users in the system for this specific document.
If there are multiple grants that have been authorized for a particular document and user, the latest grant would be the effective rule. Basically, the latest grant for the tuple (DID, TUID) should persist.
Here are a few clarification scenarios:
- If an initial grant for (file1, user1, 2, 100) is successful and then a successful grant request (file1, 0, 1, 50) is made, then file1 should be accessible for checkin only to all users for 50 seconds. User1 loses the checkout access given earlier.
- Grant (file1, 0, 3, 100) exists and then a successful grant request (file1, user2, 2, 50), then file1 is accessible to user2 for checkout for 50 seconds and to all other users for both checkin-checkout. The access rights for other users should not be modified.
5. delete(Document DID): If the user currently logged in at the requesting client is the document owner, the file is safely deleted. No one in the future should be able to access data contained in it even if the server gets compromised. The deletion of a confidential document should result in permanent removal of the key used to encrypt it.
6. logout(): Terminates the current session. If any documents received from the server were modified, their new copies must be sent to the server before session termination completes. While checking back in the modified documents, you must set Integrity as the SecurityFlag.
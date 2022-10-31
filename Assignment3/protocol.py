import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    delimiter = b"|"

    def __init__(self):
        self._key = None
        self._nonce = None
        pass

    def generate_key(self):
        return secrets.token_urlsafe(32)

    def generate_iv(self):
        return secrets.token_urlsafe(16)

    def generate_nonce(self):
        return secrets.token_urlsafe(12)

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, isServer):
        challenge = self.generate_nonce()
        self.SetNonce(challenge.encode())
        if isServer:
            return "PROTOCOL_INIT_SERVER|" + challenge
        return "PROTOCOL_INIT_CLIENT|" + challenge


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return message.startswith(b"PROTOCOL")

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, key):
        msg = message.split(self.delimiter)
        stage = msg[0]
        padder = padding.PKCS7(128).padder()
        unpadder = padding.PKCS7(128).unpadder()

        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=None)
        key = ckdf.derive(key.encode())
        cipher = Cipher(algorithms.AES(key), modes.ECB())

        result = b""
        if stage == b"PROTOCOL_INIT_CLIENT":
            print("PROTOCOL_INIT_CLIENT")

            response = self.get_nonce(msg)
            session_key = self.generate_key().encode()
            self.SetSessionKey(session_key)
            data = b"SERVER" + self.delimiter + response + self.delimiter + session_key
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            challenge = self.generate_nonce().encode()
            self.SetNonce(challenge)
            result = b"PROTOCOL_AUTH_SERVER_CHALLENGE" + self.delimiter + ct + self.delimiter + challenge
        elif stage == b"PROTOCOL_INIT_SERVER":
            print("PROTOCOL_INIT_SERVER")

            response = self.get_nonce(msg)
            session_key = self.generate_key().encode()
            self.SetSessionKey(session_key)
            data = b"CLIENT" + self.delimiter + response + self.delimiter + session_key
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            challenge = self.generate_nonce().encode()
            self.SetNonce(challenge)
            result = b"PROTOCOL_AUTH_CLIENT_CHALLENGE" + self.delimiter + ct + self.delimiter + challenge
        elif stage == b"PROTOCOL_AUTH_SERVER_CHALLENGE":
            print("PROTOCOL_AUTH_SERVER_CHALLENGE")

            ct = msg[1]
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter)
                if data[0] == b"SERVER" and data[1] == self._nonce:
                    session_key = data[2]
                    self.SetSessionKey(session_key)
            except:
                raise Exception("Authentication fails")
                
            response = self.get_nonce(msg)
            data = b"CLIENT" + self.delimiter + response + self.delimiter + session_key 
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            result = b"PROTOCOL_AUTH_CLIENT" + self.delimiter + ct
        elif stage == b"PROTOCOL_AUTH_CLIENT_CHALLENGE":
            print("PROTOCOL_AUTH_CLIENT_CHALLENGE")

            ct = msg[1]
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter)
                if data[0] == b"CLIENT" and data[1] == self._nonce:
                    session_key = data[2]
                    self.SetSessionKey(session_key)
            except:
                raise Exception("Authentication fails")

            response = self.get_nonce(msg)
            data = b"SERVER" + self.delimiter + response + self.delimiter + session_key 
            padded_data = padder.update(data) + padder.finalize()
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            result = b"PROTOCOL_AUTH_SERVER" + self.delimiter + ct
        elif stage == b"PROTOCOL_AUTH_SERVER":
            print("PROTOCOL_AUTH_SERVER")

            ct = msg[1]
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            data = unpadder.update(padded_data) + unpadder.finalize()
            data = data.split(self.delimiter)
            if data[0] == b"SERVER" and data[1] == self._nonce:
                session_key = data[2]
                assert(self._key == session_key)
            else:
                raise Exception("Authentication fails")
            result = b"PROTOCOL_END"
        elif stage == b"PROTOCOL_AUTH_CLIENT":
            print("PROTOCOL_AUTH_CLIENT")

            ct = msg[1]
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            data = unpadder.update(padded_data) + unpadder.finalize()
            data = data.split(self.delimiter)
            if data[0] == b"CLIENT" and data[1] == self._nonce:
                session_key = data[2]
                assert(self._key == session_key)
            else:
                raise Exception("Authentication fails")
            result = b"PROTOCOL_END"

        print("The result is", result)
        return result

    # We append the nonce to the end of the message
    def get_nonce(self, message):
        return message[-1]

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Setting the nonce for mutual authentication
    def SetNonce(self, nonce):
        self._nonce = nonce
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        print("My key is ", self._key)
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text

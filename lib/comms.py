import struct
import hashlib
import hmac
from Crypto.Cipher import AES
from lib.Padding import pad, unpad
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad
from dh import create_dh_key, calculate_dh_secret
import time


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False, verbose2=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.verbose2 = verbose2
        self.initiate_session()
        self.hmac = None
        self.shared_hash = ''.encode("ascii")
        self.check = None

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            self.shared_hash = shared_hash.encode("ascii")
            print("Shared hash: {}".format(shared_hash))
        self.cipher = AES.new(shared_hash[:32])

    def send(self, data, crypto=True, nonce=None):
        if crypto and (nonce is not None):
            if self.cipher:
                padded_m = pad(data, AES.block_size)
                encrypted_data = self.cipher.encrypt(padded_m)
                t = str(time.time()).encode('ascii')
                sending = bytes(bytearray(encrypted_data) + bytearray(t))
                md5 = hmac.new(self.shared_hash, sending, hashlib.md5).hexdigest().encode("ascii")
                pkt_len = struct.pack('HHHH', len(encrypted_data), len(md5), len(t), len(nonce))
                self.conn.sendall(pkt_len)
                self.conn.sendall(t)
                self.conn.sendall(md5)
                self.conn.sendall(encrypted_data)
                self.conn.sendall(nonce)
                if self.verbose:
                    print("Original data: {}".format(data))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Sending packet of length {}".format(len(encrypted_data)))
                    print("The HMAC using md5 is {}".format(md5))
                    print("timestamp is {}".format(t))
            else:
                encrypted_data = data
                pkt_len = struct.pack('H', len(encrypted_data))
                self.conn.sendall(pkt_len)
                self.conn.sendall(encrypted_data)
        else:
            encrypted_data = data
            pkt_len = struct.pack('H', len(encrypted_data))
            self.conn.sendall(pkt_len)
            self.conn.sendall(encrypted_data)

    def recv(self, crypto=True, nonce=None):
        # Decode the data's length from an unsigned two byte int ('H')
        if crypto and (nonce is not None):
            if self.cipher:
                flag = True
                pkt_len_packed = self.conn.recv(struct.calcsize('HHHH'))
                unpacked_contents = struct.unpack('HHHH', pkt_len_packed)
                data_len = unpacked_contents[0]
                md5_len = unpacked_contents[1]
                time_len = unpacked_contents[2]
                nonce_len = unpacked_contents[3]
                all_data = bytearray(self.conn.recv(data_len + md5_len + time_len + nonce_len))
                time_received = bytes(all_data[:time_len])
                md5_received = bytes(all_data[time_len:md5_len + time_len])
                encrypted_data = bytes(all_data[time_len + md5_len:time_len + md5_len + data_len])
                nonce_received = bytes(all_data[data_len + md5_len + time_len:])
                receiving = bytes(bytearray(encrypted_data) + bytearray(time_received))
                md5_recalculate = hmac.new(self.shared_hash, receiving, hashlib.md5).hexdigest().encode("ascii")
                padded_c = self.cipher.decrypt(encrypted_data)
                data = unpad(padded_c, AES.block_size)
                time_now = time.time()
                if self.verbose2 and flag:
                    print("Receiving packet of length {}".format(data_len + md5_len + time_len))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("MD5 received: {}".format(md5_received))
                    print("MD5 calculated with received encrypted data: {}".format(md5_recalculate))
                    if md5_recalculate == md5_received:
                        print("The data received correctly!")
                    else:
                        print("The data was corrupted!")
                    print("Original data: {}".format(data))
                    print("Sending time: {}".format(time_received))
                    print("Received time: {}".format(time_now))
                    print("Difference of time: {}".format(time_now - float(time_received)))
                    print("Nonce received: {}".format(nonce_received))
                    print("Nonce should be: {}".format(nonce))

            else:
                pkt_len_packed = self.conn.recv(struct.calcsize('H'))
                unpacked_contents = struct.unpack('H', pkt_len_packed)
                pkt_len = unpacked_contents[0]
                encrypted_data = self.conn.recv(pkt_len)
                data = encrypted_data
        else:
            pkt_len_packed = self.conn.recv(struct.calcsize('H'))
            unpacked_contents = struct.unpack('H', pkt_len_packed)
            pkt_len = unpacked_contents[0]
            encrypted_data = self.conn.recv(pkt_len)
            data = encrypted_data
        return data

    def close(self):
        self.conn.close()

import struct
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Hash import HMAC
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad
from dh import create_dh_key, calculate_dh_secret
from lib.Padding import pad, unpad

from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
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
        self.shared_hash = b''
        self.nonce = b''

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

    def send(self, data):
        # nonce_send = random.randint(0, int(2**8))
        # self.nonce = nonce_send
        if self.cipher:
            if self.client:
                padded_m = pad(data, AES.block_size)
                encrypted_data = self.cipher.encrypt(padded_m)
                t = time.time()
                mac = HMAC.new(self.shared_hash, digestmod=MD5)
                mac.update(padded_m)
                md5 = mac.hexdigest().encode("ascii")
                sending = bytes(bytearray(md5) + bytearray(encrypted_data) + bytearray(self.nonce))


                pkt_len = struct.pack('HHHd', len(encrypted_data), len(md5), len(self.nonce),t)
                self.conn.sendall(pkt_len)
                self.conn.sendall(sending)
                if self.verbose:
                    print("Original data: {}".format(data))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Sending packet of length {}".format(len(encrypted_data)))
                    print("The HMAC using md5 is {}".format(md5))
                    print("The length of HMAC is {}".format(len(md5)))
                    if self.nonce != b'':
                        print("The nonce sending in package is {}".format(self.nonce))
                    print("timestamp is {}".format(t))
            else:
                encrypted_data = data
                pkt_len = struct.pack('H', len(encrypted_data))
                self.conn.sendall(pkt_len)
                self.conn.sendall(encrypted_data)
                self.nonce = data
                # print("The nonce sending to client is {}".format(self.nonce))

        else:
            encrypted_data = data
            pkt_len = struct.pack('H', len(encrypted_data))
            self.conn.sendall(pkt_len)
            self.conn.sendall(encrypted_data)


    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        if self.cipher:
            if self.server:
                pkt_len_packed = self.conn.recv(struct.calcsize('HHHd'))
                unpacked_contents = struct.unpack('HHHd', pkt_len_packed)
                data_len = unpacked_contents[0]
                mac_len = unpacked_contents[1]
                nonce_len = unpacked_contents[2]
                time_received = unpacked_contents[3]
                # nonce_recieved = unpacked_contents[2]
                # sig_len = unpacked_contents[2]
                all_data = bytearray(self.conn.recv(data_len+mac_len+nonce_len))
                md5_received = bytes(all_data[:mac_len])
                encrypted_data = bytes(all_data[mac_len:data_len+mac_len])
                nonce_received = bytes(all_data[data_len+mac_len:])
                time_now = time.time()
                if(((nonce_received!=self.nonce and nonce_received!=b'') or (time_now-time_received)>0.002)and self.verbose2 == True):
                    print("Replay Attack!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    print("The current nonce is {}".format(self.nonce))
                    print("The nonce recieved is from package{}".format(nonce_received))
                    print("Sending time: {}".format(time_received))
                    print("Received time: {}".format(time_now))
                    print("Difference of time: {}".format(time_now - time_received))
                    data = b'replayattack'
                    # self.close()
                else:
                    padded_c = self.cipher.decrypt(encrypted_data)
                    mac = HMAC.new(self.shared_hash, digestmod=MD5)
                    mac.update(padded_c)
                    md5_recalculate = mac.hexdigest().encode("ascii")
                    data = unpad(padded_c, AES.block_size)
                    if self.verbose2:
                        print("Receiving packet of length {}".format(data_len+mac_len))
                        print("Encrypted data: {}".format(repr(encrypted_data)))
                        print("MD5 received: {}".format(md5_received))
                        print("MD5 calculated with received: {}".format(md5_recalculate))
                        print("The current nonce is {}".format(self.nonce))
                        print("The nonce recieved from server is {}".format(nonce_received))
                        print("Sending time: {}".format(time_received))
                        print("Received time: {}".format(time_now))
                        print("Difference of time: {}".format(time_now - time_received))
                        # print("Nonce recieved is {}".format(nonce_recieved))
                        if md5_recalculate == md5_received:
                            print("The data received correctly!")
                        else:
                            print("The data was corrupted!")
            else:
                pkt_len_packed = self.conn.recv(struct.calcsize('H'))
                unpacked_contents = struct.unpack('H', pkt_len_packed)
                pkt_len = unpacked_contents[0]
                encrypted_data = self.conn.recv(pkt_len)
                data = encrypted_data
                self.nonce = data
                # print("The nonce sending from server is {}".format(self.nonce))


        else:
            pkt_len_packed = self.conn.recv(struct.calcsize('H'))
            unpacked_contents = struct.unpack('H', pkt_len_packed)
            pkt_len = unpacked_contents[0]
            encrypted_data = self.conn.recv(pkt_len)
            data = encrypted_data
        # if self.nonce == nonce_recieved:
        return data

    def close(self):
        self.conn.close()

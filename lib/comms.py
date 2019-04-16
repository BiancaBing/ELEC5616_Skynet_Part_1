import struct
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Hash import HMAC
from dh import create_dh_key, calculate_dh_secret, calculate_iv
from lib.Padding import pad, unpad
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
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            my_public_iv, my_private_iv = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key, flag = self.recv()
            their_public_key = int(their_public_key)
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            self.shared_hash = shared_hash.encode("ascii")
            # Send them our public iv seed
            self.send(bytes(str(my_public_iv), "ascii"))
            # Receive their public iv seed
            their_public_iv, flag = self.recv()
            their_public_iv = int(their_public_iv)
            # Obtain our shared iv
            shared_iv = str(calculate_iv(their_public_iv, my_private_iv)).encode("ascii")
            print("Shared hash: \"{}\"".format(shared_hash))
            print("--------------------------------------")
            # initialize the cipher
            self.cipher = AES.new(shared_hash[:32], AES.MODE_CBC, shared_iv[:16])

    def send(self, data):
        if self.cipher:
            # Client encrypt original data with key
            # Pack encrypted data with HMAC, timestamp and nonce
            # The packed messages are sent from client to server
            if self.client:
                # Encrypt original data using AES with key(shared hash)
                padded_m = pad(data, AES.block_size)
                encrypted_data = self.cipher.encrypt(padded_m)
                # Get the current timestamp
                t = str(time.time()).encode('ascii')
                # Mac of timestamp, encrypted data and nonce
                md5_object = bytes(bytearray(t) + bytearray(encrypted_data) + bytearray(self.nonce))
                mac = HMAC.new(self.shared_hash, digestmod=MD5)
                mac.update(md5_object)
                md5 = mac.hexdigest().encode("ascii")
                # Send timestamp, mac, encrypted data and nonce
                sending = bytes(bytearray(t) + bytearray(md5) + bytearray(encrypted_data) + bytearray(self.nonce))
                # Send the pack of data lengths
                pkt_len = struct.pack('HHHH', len(encrypted_data), len(md5), len(t), len(self.nonce))
                self.conn.sendall(pkt_len)
                self.conn.sendall(sending)
                if self.verbose:
                    print("Original data: \"{}\"".format(data.decode("ascii")))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("Sending packet of length {}".format(len(encrypted_data)))
                    print("The HMAC using md5 is \"{}\"".format(md5.decode("ascii")))
                    print("The length of HMAC is {}".format(len(md5)))
                    if self.nonce != b'':
                        print("The nonce sending in package is \"{}\"".format(self.nonce.decode("ascii")))
                    print("timestamp is \"{}\"".format(t.decode("ascii")))
                    print("--------------------------------------")
            # Server send nonce to client and save it
            else:
                encrypted_data = data
                pkt_len = struct.pack('H', len(encrypted_data))
                self.conn.sendall(pkt_len)
                self.conn.sendall(encrypted_data)
                self.nonce = data

        else:
            encrypted_data = data
            pkt_len = struct.pack('H', len(encrypted_data))
            self.conn.sendall(pkt_len)
            self.conn.sendall(encrypted_data)

    def recv(self):
        recv_flag = True  # flag here will decide if the packet should be received or discarded
        if self.cipher:
            # Server receive data sent from client
            # Unpack encrypted data, HMAC, timestamp and nonce
            # Compare the sent nonce, mac and timestamp with calculated mac and current nonce, timestamp
            if self.server:
                # Receive the length packed
                pkt_len_packed = self.conn.recv(struct.calcsize('HHHH'))
                unpacked_contents = struct.unpack('HHHH', pkt_len_packed)
                data_len = unpacked_contents[0]
                md5_len = unpacked_contents[1]
                time_len = unpacked_contents[2]
                nonce_len = unpacked_contents[3]
                # Receive data sent with unpacked lengths
                all_data = bytearray(self.conn.recv(data_len + md5_len + time_len + nonce_len))
                time_received = bytes(all_data[:time_len])
                md5_received = bytes(all_data[time_len:md5_len + time_len])
                encrypted_data = bytes(all_data[time_len + md5_len:time_len + md5_len + data_len])
                nonce_received = bytes(all_data[data_len + md5_len + time_len:])
                receiving = bytes((bytearray(time_received) + bytearray(encrypted_data) + bytearray(nonce_received)))
                # Get current timestamp
                time_now = time.time()
                # Compare the nonce received with current nonce in server
                # Calculate the time difference
                # Decide whether a replay attack happened
                # if this is a replay attack, the packet will be discarded
                if (((nonce_received != self.nonce and nonce_received != b'') or (time_now - float(time_received)) > 1)
                        and self.verbose2 is True):
                    print("Replay Attack!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    print("The current nonce is \"{}\"".format(self.nonce))
                    print("The nonce received is from package \"{}\"".format(nonce_received.decode("ascii")))
                    print("Sending time: \"{}\"".format(time_received.decode("ascii")))
                    print("Received time: \"{}\"".format(time_now))
                    print("Difference of time: \"{}\"".format(time_now - float(time_received)))
                    recv_flag = False
                    data = b''
                # If it is not a replay attack, keeps decrypting data and calculate the mac
                else:
                    padded_c = self.cipher.decrypt(encrypted_data)
                    # Calculate the mac with received encrypted data
                    mac = HMAC.new(self.shared_hash, digestmod=MD5)
                    mac.update(receiving)
                    md5_recalculate = mac.hexdigest().encode("ascii")
                    # decrypt the encrypted data
                    data = unpad(padded_c, AES.block_size)
                    if self.verbose2:
                        print("Receiving packet of length {}".format(data_len + md5_len))
                        print("Encrypted data: {}".format(repr(encrypted_data)))
                        print("MD5 received: \"{}\"".format(md5_received.decode("ascii")))
                        print("MD5 calculated with received: \"{}\"".format(md5_recalculate.decode("ascii")))
                        print("The current nonce is \"{}\"".format(self.nonce.decode("ascii")))
                        print("The nonce received from client is \"{}\"".format(nonce_received.decode("ascii")))
                        print("Sending time: \"{}\"".format(time_received.decode("ascii")))
                        print("Received time: \"{}\"".format(time_now))
                        print("Difference of time: \"{}\"".format(time_now - float(time_received)))
                        # Decide whether the data was corrupted depending on hmac
                        if md5_recalculate == md5_received:
                            print("The data received correctly!")
                        # If MD5 is not matched, the packet will be discarded as well
                        else:
                            print("The data was corrupted!")
                            recv_flag = False
            # Client receive nonce from server
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
        return data, recv_flag

    def close(self):
        self.conn.close()

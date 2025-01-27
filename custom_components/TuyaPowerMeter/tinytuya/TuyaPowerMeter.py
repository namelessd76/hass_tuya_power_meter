# TinyTuya Module
# -*- coding: utf-8 -*-

import binascii
import hmac
import json
from hashlib import md5, sha256
import logging
import socket
import struct
import time
import sys

from .const import DEVICEFILE, TCPPORT
from .crypto_helper import AESCipher
from .error_helper import ERR_CONNECT, ERR_DEVTYPE, ERR_JSON, ERR_KEY_OR_VER, ERR_OFFLINE, ERR_PAYLOAD, error_json
from .exceptions import DecodeError
from .message_helper import MessagePayload, TuyaMessage, pack_message, unpack_message, parse_header
from . import command_types as CT, header as H

log = logging.getLogger(__name__)

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

# Tuya Device Dictionary - Command and Payload Overrides
#
# 'default' devices require the 0a command for the DP_QUERY request
# 'device22' devices require the 0d command for the DP_QUERY request and a list of
#            dps used set to Null in the request payload
#
# Any command not defined in payload_dict will be sent as-is with a
#  payload of {"gwId": "", "devId": "", "uid": "", "t": ""}

payload_dict = {
    CT.AP_CONFIG: {  # [BETA] Set Control Values on Device
        "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
    },
    CT.CONTROL: {
        "command_override": CT.CONTROL_NEW,  # Uses CONTROL_NEW command
        "command": {"protocol":5, "t": "int", "data": {}}
    },
    CT.STATUS: {  # Get Status from Device
        "command": {"gwId": "", "devId": ""},
    },
    CT.HEART_BEAT: {"command": {"gwId": "", "devId": ""}},
    CT.DP_QUERY: {
        "command_override": CT.DP_QUERY_NEW,
        "command": {}
    },
    CT.CONTROL_NEW: {
        "command": {"protocol":5, "t": "int", "data": {}}
    },
    CT.DP_QUERY_NEW: {
        "command": {}
    },
    CT.UPDATEDPS: {"command": {"dpId": [18, 19, 20]}},
    CT.LAN_EXT_STREAM: { "command": { "reqType": "", "data": {} }},
}

class TuyaPowerMeter(object):
    def __init__(
            self, dev_id, address=None, local_key="", connection_timeout=5, version=3.5, persist=False, connection_retry_limit=5, connection_retry_delay=5, port=TCPPORT # pylint: disable=W0621
    ):
        """
        Represents a Tuya device.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            cid (str: Optional sub device id. Default to None.
            node_id (str: alias for cid)
            parent (object: gateway device this device is a child of)

        Attributes:
            port (int): The port to connect to.
        """

        self.id = dev_id
        self.address = address
        self.connection_timeout = connection_timeout
        self.retry = True
        self.disabledetect = False  # if True do not detect device22
        self.port = port  # default - do not expect caller to pass in
        self.socket = None
        self.socketPersistent = False if not persist else True # pylint: disable=R1719
        self.socketNODELAY = True
        self.socketRetryLimit = connection_retry_limit
        self.socketRetryDelay = connection_retry_delay
        self.version = 0
        self.version_str = None
        self.version_bytes = None
        self.version_header = None
        self.dps_to_request = {}
        self.seqno = 1
        self.sendWait = 0.01
        self.dps_cache = {}
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''

        self.local_key = local_key.encode("latin1")
        self.real_local_key = self.local_key
        self.cipher = None

        self.set_version(float(version))

    def __del__(self):
        # In case we have a lingering socket connection, close it
        try:
            if self.socket:
                # self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                self.socket = None
        except:
            pass

    def __repr__(self):
        # FIXME can do better than this
        return ("%s( %r, address=%r, local_key=%r, connection_timeout=%r, persist=%r )" %
                (self.__class__.__name__, self.id, self.address, self.real_local_key.decode(), self.connection_timeout, self.socketPersistent))

    def _get_socket(self, renew):
        if renew and self.socket is not None:
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None
        if self.socket is None:
            # Set up Socket
            retries = 0
            err = ERR_OFFLINE
            while retries < self.socketRetryLimit:
                if not self.address:
                    log.debug("No address for device!")
                    return ERR_OFFLINE

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.socketNODELAY:
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.settimeout(self.connection_timeout)
                try:
                    retries = retries + 1
                    self.socket.connect((self.address, self.port))
                    # restart session key negotiation
                    if self._negotiate_session_key():
                        return True
                    else:
                        if self.socket:
                            self.socket.close()
                            self.socket = None
                        return ERR_KEY_OR_VER
                except socket.timeout as e:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect (timeout) - retry %d/%d",
                        retries, self.socketRetryLimit
                    )
                    err = ERR_OFFLINE
                except Exception as e:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect (exception) - retry %d/%d",
                        retries, self.socketRetryLimit, exc_info=True
                    )
                    err = ERR_CONNECT
                if self.socket:
                    self.socket.close()
                    self.socket = None
                if retries < self.socketRetryLimit:
                    time.sleep(self.socketRetryDelay)
            # unable to get connection
            return err
        # existing socket active
        return True

    def _check_socket_close(self, force=False):
        if (force or not self.socketPersistent) and self.socket:
            self.socket.close()
            self.socket = None

    def _recv_all(self, length):
        tries = 2
        data = b''

        while length > 0:
            newdata = self.socket.recv(length)
            if not newdata or len(newdata) == 0:
                log.debug("_recv_all(): no data? %r", newdata)
                # connection closed?
                tries -= 1
                if tries == 0:
                    raise DecodeError('No data received - connection closed?')
                if self.sendWait is not None:
                    time.sleep(self.sendWait)
                continue
            data += newdata
            length -= len(newdata)
            tries = 2
        return data

    def _receive(self):
        # message consists of header + retcode + [data] + crc (4 or 32) + footer
        min_len_55AA = struct.calcsize(H.MESSAGE_HEADER_FMT_55AA) + 4 + 4 + len(H.SUFFIX_BIN)
        # message consists of header + iv + retcode + [data] + crc (16) + footer
        min_len_6699 = struct.calcsize(H.MESSAGE_HEADER_FMT_6699) + 12 + 4 + 16 + len(H.SUFFIX_BIN)
        min_len = min_len_55AA if min_len_55AA < min_len_6699 else min_len_6699
        prefix_len = len( H.PREFIX_55AA_BIN )

        data = self._recv_all( min_len )

        # search for the prefix.  if not found, delete everything except
        # the last (prefix_len - 1) bytes and recv more to replace it
        prefix_offset_55AA = data.find( H.PREFIX_55AA_BIN )
        prefix_offset_6699 = data.find( H.PREFIX_6699_BIN )

        while prefix_offset_55AA != 0 and prefix_offset_6699 != 0:
            log.debug('Message prefix not at the beginning of the received data!')
            log.debug('Offset 55AA: %d, 6699: %d, Received data: %r', prefix_offset_55AA, prefix_offset_6699, data)
            if prefix_offset_55AA < 0 and prefix_offset_6699 < 0:
                data = data[1-prefix_len:]
            else:
                prefix_offset = prefix_offset_6699 if prefix_offset_55AA < 0 else prefix_offset_55AA
                data = data[prefix_offset:]

            data += self._recv_all( min_len - len(data) )
            prefix_offset_55AA = data.find( H.PREFIX_55AA_BIN )
            prefix_offset_6699 = data.find( H.PREFIX_6699_BIN )

        header = parse_header(data)
        remaining = header.total_length - len(data)
        if remaining > 0:
            data += self._recv_all( remaining )

        log.debug("received data=%r", binascii.hexlify(data))
        hmac_key = self.local_key 
        no_retcode = False
        return unpack_message(data, header=header, hmac_key=hmac_key, no_retcode=no_retcode)

    # similar to _send_receive() but never retries sending and does not decode the response
    def _send_receive_quick(self, payload, recv_retries, from_child=None): # pylint: disable=W0613
        log.debug("sending payload quick")
        if self._get_socket(False) is not True:
            return None
        enc_payload = self._encode_message(payload) if type(payload) == MessagePayload else payload
        try:
            self.socket.sendall(enc_payload)
        except:
            self._check_socket_close(True)
            return None
        if not recv_retries:
            return True
        while recv_retries:
            try:
                msg = self._receive()
            except:
                msg = None
            if msg and len(msg.payload) != 0:
                return msg
            recv_retries -= 1
            if recv_retries == 0:
                log.debug("received null payload (%r) but out of recv retries, giving up", msg)
            else:
                log.debug("received null payload (%r), fetch new one - %s retries remaining", msg, recv_retries)
        return False

    def _send_receive(self, payload, minresponse=28, getresponse=True, decode_response=True, from_child=None):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send. Set to 'None' to receive only.
            minresponse(int): Minimum response size expected (default=28 bytes)
            getresponse(bool): If True, wait for and return response.
        """
        success = False
        partial_success = False
        retries = 0
        recv_retries = 0
        #max_recv_retries = 0 if not self.retry else 2 if self.socketRetryLimit > 2 else self.socketRetryLimit
        max_recv_retries = 0 if not self.retry else self.socketRetryLimit
        do_send = True
        msg = None
        while not success:
            # open up socket if device is available
            sock_result = self._get_socket(False)
            if sock_result is not True:
                # unable to get a socket - device likely offline
                self._check_socket_close(True)
                return error_json( sock_result if sock_result else ERR_OFFLINE )
            # send request to device
            try:
                if payload is not None and do_send:
                    log.debug("sending payload")
                    enc_payload = self._encode_message(payload) if type(payload) == MessagePayload else payload
                    self.socket.sendall(enc_payload)
                    if self.sendWait is not None:
                        time.sleep(self.sendWait)  # give device time to respond
                if getresponse:
                    do_send = False
                    rmsg = self._receive()
                    # device may send null ack (28 byte) response before a full response
                    # consider it an ACK and do not retry the send even if we do not get a full response
                    if rmsg:
                        payload = None
                        partial_success = True
                        msg = rmsg
                    if (not msg or len(msg.payload) == 0) and recv_retries <= max_recv_retries:
                        log.debug("received null payload (%r), fetch new one - retry %s / %s", msg, recv_retries, max_recv_retries)
                        recv_retries += 1
                        if recv_retries > max_recv_retries:
                            success = True
                    else:
                        success = True
                        log.debug("received message=%r", msg)
                else:
                    # legacy/default mode avoids persisting socket across commands
                    self._check_socket_close()
                    return None
            except (KeyboardInterrupt, SystemExit) as err:
                log.debug("Keyboard Interrupt - Exiting")
                raise
            except socket.timeout as err:
                # a socket timeout occurred
                if payload is None:
                    # Receive only mode - return None
                    self._check_socket_close()
                    return None
                do_send = True
                retries += 1
                # toss old socket and get new one
                self._check_socket_close(True)
                log.debug(
                    "Timeout in _send_receive() - retry %s / %s",
                    retries, self.socketRetryLimit
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    # timeout reached - return error
                    return error_json(ERR_KEY_OR_VER)
                # wait a bit before retrying
                time.sleep(0.1)
            except DecodeError as err:
                log.debug("Error decoding received data - read retry %s/%s", recv_retries, max_recv_retries, exc_info=True)
                recv_retries += 1
                if recv_retries > max_recv_retries:
                    # we recieved at least 1 valid message with a null payload, so the send was successful
                    if partial_success:
                        self._check_socket_close()
                        return None
                    # no valid messages received
                    self._check_socket_close(True)
                    return error_json(ERR_PAYLOAD)
            except Exception as err:
                # likely network or connection error
                do_send = True
                retries += 1
                # toss old socket and get new one
                self._check_socket_close(True)
                log.debug(
                    "Network connection error in _send_receive() - retry %s/%s",
                    retries, self.socketRetryLimit, exc_info=True
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    log.debug("Unable to connect to device ")
                    # timeout reached - return error
                    return error_json(ERR_CONNECT)
                # wait a bit before retrying
                time.sleep(0.1)
            # except
        # while

        # could be None or have a null payload
        if not decode_response:
            # legacy/default mode avoids persisting socket across commands
            self._check_socket_close()
            return msg

        return self._process_message( msg, from_child, minresponse, decode_response )

    def _process_message( self, msg, from_child=None, minresponse=28, decode_response=True ):
        # null packet, nothing to decode
        if not msg or len(msg.payload) == 0:
            log.debug("raw unpacked message = %r", msg)
            # legacy/default mode avoids persisting socket across commands
            self._check_socket_close()
            return None

        # option - decode Message with hard coded offsets
        # result = self._decode_payload(data[20:-8])

        # Unpack Message into TuyaMessage format
        # and return payload decrypted
        try:
            # Data available: seqno cmd retcode payload crc
            log.debug("raw unpacked message = %r", msg)
            result = self._decode_payload(msg.payload)

            if result is None:
                log.debug("_decode_payload() failed!")
        except:
            log.debug("error unpacking or decoding tuya JSON payload", exc_info=True)
            result = error_json(ERR_PAYLOAD)

        # legacy/default mode avoids persisting socket across commands
        self._check_socket_close()

        return self._process_response(result)

    def _decode_payload(self, payload):
        log.debug("decode payload=%r", payload)
        cipher = AESCipher(self.local_key)

        if self.version >= 3.2: # 3.2 or 3.3 or 3.4 or 3.5
            # Trim header for non-default device type
            if payload.startswith( self.version_bytes ):
                payload = payload[len(self.version_header) :]
                log.debug("removing 3.x=%r", payload)

            if not isinstance(payload, str):
                try:
                    payload = payload.decode()
                except:
                    log.debug("payload was not string type and decoding failed")
                    return error_json(ERR_JSON, payload)
        elif not payload.startswith(b"{"):
            log.debug("Unexpected payload=%r", payload)
            return error_json(ERR_PAYLOAD, payload)

        if not isinstance(payload, str):
            payload = payload.decode()
        log.debug("decoded results=%r", payload)
        try:
            json_payload = json.loads(payload)
        except:
            json_payload = error_json(ERR_JSON, payload)

        return json_payload

    def _process_response(self, response): # pylint: disable=R0201
        """
        Override this function in a sub-class if you want to do some processing on the received data
        """
        return response

    def _negotiate_session_key(self):
        rkey = self._send_receive_quick( self._negotiate_session_key_generate_step_1(), 2 )
        step3 = self._negotiate_session_key_generate_step_3( rkey )
        if not step3:
            return False
        self._send_receive_quick( step3, None )
        self._negotiate_session_key_generate_finalize()
        return True

    def _negotiate_session_key_generate_step_1( self ):
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''
        self.local_key = self.real_local_key

        return MessagePayload(CT.SESS_KEY_NEG_START, self.local_nonce)

    def _negotiate_session_key_generate_step_3( self, rkey ):
        if not rkey or type(rkey) != TuyaMessage or len(rkey.payload) < 48:
            # error
            log.debug("session key negotiation failed on step 1")
            return False

        if rkey.cmd != CT.SESS_KEY_NEG_RESP:
            log.debug("session key negotiation step 2 returned wrong command: %d", rkey.cmd)
            return False

        payload = rkey.payload

        log.debug("decrypted session key negotiation step 2 payload=%r", payload)
        log.debug("payload type = %s len = %d", type(payload), len(payload))

        if len(payload) < 48:
            log.debug("session key negotiation step 2 failed, too short response")
            return False

        self.remote_nonce = payload[:16]
        hmac_check = hmac.new(self.local_key, self.local_nonce, sha256).digest()

        if hmac_check != payload[16:48]:
            log.debug("session key negotiation step 2 failed HMAC check! wanted=%r but got=%r", binascii.hexlify(hmac_check), binascii.hexlify(payload[16:48]))
            return False

        log.debug("session local nonce: %r remote nonce: %r", self.local_nonce, self.remote_nonce)

        rkey_hmac = hmac.new(self.local_key, self.remote_nonce, sha256).digest()
        return MessagePayload(CT.SESS_KEY_NEG_FINISH, rkey_hmac)

    def _negotiate_session_key_generate_finalize( self ):
        if IS_PY2:
            k = [ chr(ord(a)^ord(b)) for (a,b) in zip(self.local_nonce,self.remote_nonce) ]
            self.local_key = ''.join(k)
        else:
            self.local_key = bytes( [ a^b for (a,b) in zip(self.local_nonce,self.remote_nonce) ] )
        log.debug("Session nonce XOR'd: %r", self.local_key)

        cipher = AESCipher(self.real_local_key)
        iv = self.local_nonce[:12]
        log.debug("Session IV: %r", iv)
        self.local_key = cipher.encrypt( self.local_key, use_base64=False, pad=False, iv=iv )[12:28]

        log.debug("Session key negotiate success! session key: %r", self.local_key)
        return True

    # adds protocol header (if needed) and encrypts
    def _encode_message( self, msg ):
        # make sure to use the parent's self.seqno and session key
        payload = msg.payload
        self.cipher = AESCipher(self.local_key)

        if msg.cmd not in H.NO_PROTOCOL_HEADER_CMDS:
            # add the 3.x header
            payload = self.version_header + payload
        log.debug('final payload: %r', payload)

        # seqno cmd retcode payload crc crc_good, prefix, iv
        msg = TuyaMessage(self.seqno, msg.cmd, None, payload, 0, True, H.PREFIX_6699_VALUE, True)
        self.seqno += 1  # increase message sequence number
        data = pack_message(msg,hmac_key=self.local_key)
        log.debug("payload encrypted=%r",binascii.hexlify(data))
        return data

    def receive(self):
        """
        Poll device to read any payload in the buffer.  Timeout results in None returned.
        """
        return self._send_receive(None)

    def send(self, payload):
        """
        Send single buffer `payload`.

        Args:
            payload(bytes): Data to send.
        """
        return self._send_receive(payload, 0, getresponse=False)

    def heartbeat(self, nowait=True):
        """
        Send a keep-alive HEART_BEAT command to keep the TCP connection open.

        Devices only send an empty-payload response, so no need to wait for it.

        Args:
            nowait(bool): True to send without waiting for response.
        """
        # open device, send request, then close connection
        payload = self.generate_payload(CT.HEART_BEAT)
        data = self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("heartbeat received data=%r", data)
        return data

    def status(self, nowait=False):
        """Return device status."""
        query_type = CT.DP_QUERY
        payload = self.generate_payload(query_type)

        data = self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("status() received data=%r", data)
        # Error handling
        if (not nowait) and data and "Err" in data:
            if data["Err"] == str(ERR_DEVTYPE):
                # Device22 detected and change - resend with new payload
                log.debug("status() rebuilding payload for device22")
                payload = self.generate_payload(query_type)
                data = self._send_receive(payload)
            elif data["Err"] == str(ERR_PAYLOAD):
                log.debug("Status request returned an error, is local key %r correct?", self.local_key)

        return data

    def set_version(self, version): # pylint: disable=W0621
        version = float(version)
        self.version = version
        self.version_str = "v" + str(version)
        self.version_bytes = str(version).encode('latin1')
        self.version_header = self.version_bytes + H.PROTOCOL_3x_HEADER

    def set_socketPersistent(self, persist):
        self.socketPersistent = persist
        if self.socket and not persist:
            self.socket.close()
            self.socket = None

    def set_socketNODELAY(self, nodelay):
        self.socketNODELAY = nodelay
        if self.socket:
            if nodelay:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

    def set_socketRetryLimit(self, limit):
        self.socketRetryLimit = limit

    def set_socketRetryDelay(self, delay):
        self.socketRetryDelay = delay

    def set_socketTimeout(self, s):
        self.connection_timeout = s
        if self.socket:
            self.socket.settimeout(s)

    def set_retry(self, retry):
        self.retry = retry

    def set_sendWait(self, s):
        self.sendWait = s

    def close(self):
        self.__del__()

    def generate_payload(self, command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to send.
                This is what will be passed via the 'dps' entry
            gwId(str, optional): Will be used for gwId
            devId(str, optional): Will be used for devId
            uid(str, optional): Will be used for uid
        """
        json_data = command_override = None

        if command in payload_dict:
            if 'command' in payload_dict[command]:
                json_data = payload_dict[command]['command']
            if 'command_override' in payload_dict[command]:
                command_override = payload_dict[command]['command_override']

        if command_override is None:
            command_override = command
        if json_data is None:
            # I have yet to see a device complain about included but unneeded attribs, but they *will*
            # complain about missing attribs, so just include them all unless otherwise specified
            json_data = {"gwId": "", "devId": "", "uid": "", "t": ""}

        # make sure we don't modify payload_dict
        json_data = json_data.copy()

        if "gwId" in json_data:
            if gwId is not None:
                json_data["gwId"] = gwId
            else:
                json_data["gwId"] = self.id
        if "devId" in json_data:
            if devId is not None:
                json_data["devId"] = devId
            else:
                json_data["devId"] = self.id
        if "uid" in json_data:
            if uid is not None:
                json_data["uid"] = uid
            else:
                json_data["uid"] = self.id
        if "t" in json_data:
            if json_data['t'] == "int":
                json_data["t"] = int(time.time())
            else:
                json_data["t"] = str(int(time.time()))
        if rawData is not None and "data" in json_data:
            json_data["data"] = rawData
        elif data is not None:
            if "dpId" in json_data:
                json_data["dpId"] = data
            elif "data" in json_data:
                json_data["data"]["dps"] = data
            else:
                json_data["dps"] = data
        if reqType and "reqType" in json_data:
            json_data["reqType"] = reqType

        # Create byte buffer from hex data
        if json_data == "":
            payload = ""
        else:
            payload = json.dumps(json_data)
        # if spaces are not removed device does not respond!
        payload = payload.replace(" ", "")
        payload = payload.encode("utf-8")
        log.debug("building command %s payload=%r", command, payload)

        # create Tuya message packet
        return MessagePayload(command_override, payload)

#! /usr/bin/python3
import sys
import os
import select
import socket
import sys
import datetime
import struct 
import time 
import logging
import errno 
import traceback
from queue import Queue
from OpenSSL import SSL, crypto


#variables for configuration
dir =  os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.abspath(os.path.join(dir, os.pardir))
SOCKS_VERSION = 5
AUTH_METHOD = 6
SMGW_ADDRESS = '127.0.0.1'
EMT_IP = '0.0.0.0'
##MQTT_SERVER_PORT = 1883
SMGW_PORT = 1080
MQTT_SERVER_PORT = 44444

#Needed global variables for smgw connection
ctx = None
ssl_handling = None
socks5_client = None

#Logging
logging.basicConfig(filename='mqttHandler.log', level=logging.INFO,format='%(asctime)s %(message)s')


def setContext():
    """
    create a context for tsl connection
    """
    global ctx
    ctx = SSL.Context(SSL.TLSv1_2_METHOD )
    ctx.set_options(SSL.OP_NO_COMPRESSION)
    ctx.set_options(SSL.OP_SINGLE_DH_USE)
    ctx.set_options(SSL.OP_SINGLE_ECDH_USE)
    
    ctx.set_cipher_list('ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES256-SHA384,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-SHA256,DHE-DSS-AES256-GCM-SHA384,DHE-DSS-AES256-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES128-SHA256,DHE-RSA-AES256-GCM-SHA384,DHE-RSA-AES256-SHA256,DHE-RSA-AES128-GCM-SHA256,DHE-RSA-AES128-SHA256,ECDH-ECDSA-AES256-GCM-SHA384,ECDH-ECDSA-AES256-SHA384,ECDH-ECDSA-AES128-GCM-SHA256,ECDH-ECDSA-AES128-SHA256,ECDH-RSA-AES256-GCM-SHA384,ECDH-RSA-AES256-SHA384,ECDH-RSA-AES128-GCM-SHA256,ECDH-RSA-AES128-SHA256')
    
    ctx.set_tmp_ecdh(crypto.get_elliptic_curve('prime256v1'))
    
    cert_file = open(os.path.join(parentdir, 'certificates','path.pem'), 'r')
    cert_data = cert_file.read()
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    ctx.add_client_ca(certificate)
    
   # ctx.set_verify(
   #     SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
   # )  # Demand a certificate
    
    ctx.use_privatekey_file(os.path.join(parentdir,'certificates','pkey.pem'))
    ctx.use_certificate_file(os.path.join(parentdir, 'certificates','certificate.pem'))
    #ctx.load_client_ca(os.path.join(dir, 'certificates','HAN-PPC-TLS.pem'))
    
    store = ctx.get_cert_store()
    #store.set_flags(crypto.X509StoreFlags.PARTIAL_CHAIN)
    store.add_cert(certificate)

    
def encyptionTLSSession(ssl_handling,app_data):
    """
    encyption of a message einer nachricht
    """
    listen = True
    while listen: 
        try:
            ssl_handling.set_app_data(app_data)
            bytes_sent = ssl_handling.send(ssl_handling.get_app_data())
        except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError) as e:
            pass
        else:
            logging.info("Bytes set as app data: " + str(len(app_data)))
            logging.info("Bytes send to internal BIO: " + str(bytes_sent))
            listen = False
    listen = True
    while listen: 
        try:
            enc_data = ssl_handling.bio_read(4096)
        except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError) as e:
            pass
        else:
            logging.info("internally encrypted message: " + str(enc_data))
            if len(enc_data) == 4096:
                logging.info("Warning: Buffer size completly used")
            listen = False
            return enc_data
            
         
def decryptionTLSSession(ssl_handling,enc_message):
    """
    decryption of a message
    """
    listen = True
    while listen: 
        try:
            bytes_sent = ssl_handling.bio_write(enc_message)
        except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError) as e:
            pass
        else:
            logging.info("Bytes send to ssl handler: " + str(bytes_sent))
            logging.info("Bytes of encypted message: " + str(len(enc_message)))
            listen = False
    listen = True
    while listen: 
        try:
            output = ssl_handling.read(4096)
        except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError) as e:
            pass
        except SSL.ZeroReturnError as error:
            dropClient(socks5_client, error)
            return False
        except SSL.Error as error:
            dropClient(socks5_client, error)
            return False
        else:
            logging.info("Decypted message: " + str(output))
            if len(output) == 4096:
                logging.info("Warning: Buffer size completly used")
            listen = False
            return output
                        
def readTCPwithTimeout(sock,buffersize,timeout = 2):
    """
    read funciton on TCP protocol level
    """
    listen = True
    output = b''
    timer = time.time() + timeout
    while listen and time.time() < timer: 
        try:
            output += sock.recv(buffersize)
            if len(output) != buffersize and len(output) != 0:
                return output            
        except socket.error as e:
            if e.errno != errno.EAGAIN:
                raise e
            logging.info('Blocking while reading')
            select.select([sock], [], [sock])  # This blocks until
    return None
    
    
def writeTCPwithTimeout(sock,data,timeout = 2):
    """
    write function on TCP protocol level
    """
    total_sent = 0
    total_data = len(data)
    timer = time.time() + timeout
    while len(data) and time.time() < timer:
        try:
            sent = sock.send(data)
            total_sent += sent
            data = data[sent:]
            logging.info('Sending data')
        except socket.error as e:
            if e.errno != errno.EAGAIN:
                raise e
            logging.info('Blocking with' + str(len(data)) + 'remaining')
        select.select([], [sock], [sock])  # This blocks until
    if total_sent != total_data:
        logging.info("total sent not equal length data")
        return False
    else:
        return True
        
def addSocks5Header(message,state = 3):
    """
    wraps message in socksv5 protocol
    """
    socks5message = struct.pack("!BBH", 1, state,len(message)) + message
    return socks5message
    
def BIOReadwithTimeout(ssl_handling,timeout = 2):
    """
    helper function for internal TLS bio
    """
    timer = time.time() + timeout
    while True and time.time() < timer: 
        try:
            ssl_message = ssl_handling.bio_read(4096)
            return ssl_message
        except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError) as e:
            pass
    return None
    
def establishSocks5Connection():
    """
    establish new socksv5 connection
    """
    global ctx
    global ssl_handling
    global socks5_client
    global SMGW_ADDRESS, SMGW_PORT
    
    #if there is an open connection, close it
    if socks5_client:
        try:
            socks5_client.close()
        except:
            pass
            
    socks5_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks5_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks5_client.bind(('', 1081))
    time.sleep(5)
    socks5_client.connect((SMGW_ADDRESS, SMGW_PORT))
    socks5_client.setblocking(0)
    
    #Create Connection type: Connection (pyopenssl) with arguments: Context(lib: pyopenssl), socket (lib: socket) -> without explicit socket: mit internal BIO
    setContext()
    ssl_handling = SSL.Connection(ctx)
    logging.info("Start new socks5 connection")
    logging.info("socks5: Authentication Method Negotiation Start")
    
    
    message = struct.pack("!BBB", SOCKS_VERSION, 1,AUTH_METHOD)
    #Send Socks Version and #Authentication Method 
    sucess = writeTCPwithTimeout(socks5_client,message)
    if not sucess:
        return False
    ans = readTCPwithTimeout(socks5_client,4096)
    if not ans:
        logging.warning("no Method answer " + str(ans) )  
        return False
    else:
        logging.warning("Auth Method answer " + str(ans) )    
    #socks5 Protokoll --> VERSION | Granted Auth Method
    if int(ans[0]) != 5 or int(ans[1]) != 6:
        logging.warning("Auth Method " + str(AUTH_METHOD) + " not accepted")
        return False
    else:
        logging.warning("Auth Method " + str(AUTH_METHOD) + " accepted")

        
    logging.info("socks5: Authentication Method Negotiation End")
    #Set SSL Connection State to Client Mode
    ssl_handling.set_connect_state()
    logging.info("Start TLS Handshake --> BIO is non-blocking, therefore try catch structure")
    #Start TLS Handshake --> BIO is non-blocking, therefore try catch structure
    try:
        ssl_handling.do_handshake()
    except (SSL.WantReadError,
                SSL.WantWriteError,
                SSL.WantX509LookupError) as e:
        pass
    #Get Client Hello from BIO
    logging.info("Get Client Hello from BIO")
    ans = ssl_handling.bio_read(4096)
    message = addSocks5Header(message = ans,state = 1)
    #Send Client Hello in Socks5 Protocol to SMGW
  
    sucess = writeTCPwithTimeout(socks5_client,message)
    if not sucess:
        logging.warning("send Hello not accepted")
        return False
    else:
        logging.warning("send Hello accepted")

    #Recieve Server Hello, Certificate, Server Key Exchange, Certificate Request, Server Hello Done
    ans = readTCPwithTimeout(socks5_client,4096)
    if not ans:
        return False
    logging.info("socks5:tls: Server Hello, Certificate, Server Key Exchange, Certificate Request, Server Hello Done: " + str(ans.hex()))
    #Write to Bio without Socks5 Layer
    bytes = ssl_handling.bio_write(ans[4:])
    #Get Client Certificate, Client Key Exchange, Certificate Verify, Change Cipher Spec, Encypted Handshake from BIO
    try:
        ssl_handling.read(4096)
    except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError) as e:
        pass
    message = BIOReadwithTimeout(ssl_handling)
    if not ans:
        return False
    logging.info("socks5:tls: Client Certificate, Client Key Exchange: " + str(message.hex()))
    #Add Socks5 Layer
    message = addSocks5Header(message,1)
    #Send Client Key Exchange to SMGW
    sucess = writeTCPwithTimeout(socks5_client,message)
    if not sucess:
        return False
    #Recieve Server Change Cipher Sec
    ans = readTCPwithTimeout(socks5_client,4096)
    if not ans:
        return False
    logging.info("socks5:tls: Cipher Spec and Encrypted Handshake Message: " + str(ans[4:].hex())) 
    #Add Socks5 Layer
    bytes = ssl_handling.bio_write(ans[4:])
    logging.info("socks5:tls: last bio write (Server Change Cipher Spec and Encrpted Handshake Message) bytes sent: " + str(bytes))
    logging.info("socks5:tls: Handshake finished")
    time.sleep(2)
    logging.info("socks5: Subnegotiation Start")
    opt_neg = struct.pack("!B",0)
    logging.info("socks5: Encrypt Subnegotiation")
    opt_neg_enc = encyptionTLSSession(ssl_handling,opt_neg)
    message = addSocks5Header(opt_neg_enc,state = 2)
    
    logging.info("socks5: Subnegotiation " + str(message.hex()))
    sucess = writeTCPwithTimeout(socks5_client,message)
    if not sucess:
        return False
    ans = readTCPwithTimeout(socks5_client,4096,5)
    if ans:
        ans = decryptionTLSSession(ssl_handling,ans[4:])
        logging.info('socks5: conformation sub negotiation method: ' + str(ans))
    else:
        logging.warning("Sub negotiation method not supported")
        return False
    logging.info('socks5: Subnegotiation finished')
    logging.info('socks5: Starting Request')
    #SOCKS Version, CMD,  RSV, Atyp DST.Addr, DST.Port
    time.sleep(2)
    CMD = 1 #connect
    RSV = 0
    ATYP = 1 #IPv4
    dst_addr = socket.inet_pton(socket.AF_INET,EMT_IP)
    dst_port = 1883
    message = struct.pack("!BBBB", SOCKS_VERSION, CMD,RSV,ATYP) + dst_addr + struct.pack("!H",dst_port)
    
    logging.info(' DST.Addr' +  str(dst_addr) +' , DST.Port ' + str(dst_port) )

    message_enc = encyptionTLSSession(ssl_handling,message)
    #Add Socks5 Layer
    message = addSocks5Header(message_enc,state = 3)
    logging.info("socks5: Request for connection:" + str(message.hex()))
    sucesss = writeTCPwithTimeout(socks5_client,message)
    if not sucess:
        return False
    logging.info('socks5: Request finished') 
    
    ans = readTCPwithTimeout(socks5_client,4096,5)
    logging.info('socks5: encrypted answer : ' + str(ans))
    if ans:
        ans = decryptionTLSSession(ssl_handling,ans[4:])
        logging.info('socks5: decrypted answer : ' + str(ans))

        if int(ans[1]) == 0:
            logging.info('socks5: Confirmation of request: ' + str(ans))
        else:
            logging.warning('socks5: Bad request: ' + str(ans))
            return False
    else:
        logging.warning('socks5: No confirmation of request')
    
    ans = readTCPwithTimeout(socks5_client,4096,6)
    if ans:
        logging.info('socks5: 1 Confirmation of endpoint: ' + str(ans))
        ans = decryptionTLSSession(ssl_handling,ans[4:])
        logging.info('socks5: 2 Confirmation of endpoint: ' + str(ans))
        if int(ans[0]) == 1 and len(ans) == 1:
            logging.info('socks5: Confirmation of endpoint: ' + str(ans))
        else:
            logging.warning('socks5: No confirmation of endpoint: ' + str(ans))
            return False
    else:
        logging.warning('socks5: No confirmation of request from endpoint')
        return False
    
    return True 
    
def dropClient(cli, errors=None):
    """
    drop connected client
    """
    global inputs, outputs
    global mqtt_client
    global socks5_client
    if errors:
        try:
            logging.info('Client left unexpectedly:' + str(cli.getpeername()) + " Reason: " + str(errors))
        except Exception:
            try:
                logging.info('Client left unexpectedly, Reason: ' + str(errors))
            except Exception:
                logging.info('Client left unexpectedly')
    else:
        try:
            logging.info('Client left politely' + str(cli.getpeername()))
        except Exception:
            logging.info('Client left politely')
    if cli in inputs:
        inputs.remove(cli)
    if cli in outputs:
        outputs.remove(cli)
    try:
        cli.close()
    except:
        pass
    if cli == mqtt_client or cli == socks5_client:
        
        for s in [mqtt_client,socks5_client]:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except:
                logging.warning(str(traceback.format_exc()))
        messages_to_broker = None
        messages_to_smgw = None
        mqtt_client = None
        socks5_client = None
        global mqtt_server
        inputs = [mqtt_server]
        outputs = []
        
def verify_cb(conn, cert, errnum, depth, ok):
    """
    callback for new TLS connection
    """
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    logging.info('Got certificate: ' + commonname)
    return ok

# Set up server
mqtt_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mqtt_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mqtt_server.bind(('',MQTT_SERVER_PORT))
mqtt_server.listen(1)
mqtt_server.setblocking(0)

logging.info('MQTT Bridge listening')

mqtt_client = None
# Sockets from which we expect to read
inputs = [mqtt_server]
# Sockets to which we expect to write
outputs = []

messages_to_smgw = None
messages_to_broker = None
#connected = False
#run while inputs not empty
while inputs:

    #in case connection disrupted
    for s in inputs:
        if s.fileno() == -1:
            logging.warning(str(s) + " with bad file descriptor: -1")
            inputs.dropClient(s, "bad file descriptor")
    for s in outputs:
        if s.fileno() == -1:
            logging.warning(str(s) + " with bad file descriptor: -1")
            inputs.dropClient(s, "bad file descriptor")    
            
            
    readable, writable, exceptional = select.select(inputs, outputs, inputs)
    
    # Handle inputs
    #to mqtt_server
    if mqtt_server in readable:
        #accept incoming connections
        mqtt_client, addr = mqtt_server.accept()
        logging.info('new connection from ' + str(addr))
        mqtt_client.setblocking(0)
        mqtt_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        #reset previous communications
        outputs = []
        messages_to_broker = Queue()
        messages_to_smgw = Queue()
        
        #establish connection to smgw using socks5
        connected = False
        count = 0
        while not connected and count < 3:
            connected = establishSocks5Connection()
            logging.info("Connected status: " + str(connected))
            if connected:
                break
            time.sleep(10)
            count = count + 1
        if connected:
            inputs = [mqtt_server,mqtt_client,socks5_client]    
            messages_to_smgw = Queue()
        else:
            socks5_client = None
            try:
                mqtt_client.shutdown(socket.SHUT_RDWR)
                mqtt_client.close()
            except Exception as e:
                logging.warning(str(traceback.format_exc()))
            mqtt_client = None
            inputs = [mqtt_server]
            continue
            
    #from mqtt broker to mqtt_server
    if mqtt_client in readable:
            try:
                data = mqtt_client.recv(4096)
            except socket.error as error:
                if error.errno == errno.EAGAIN:
                    time.sleep(0.2)
                else:
                    logging.info("Error occurred: " + str(os.strerror(error.errno)))
                    dropClient(mqtt_client, error)
                    continue
            else:
                if data:
                    logging.info('new message from mqtt broker to mqtt_server  ' + str(mqtt_client.getpeername()) + ', length: ' + str(len(data)))
                    messages_to_smgw.put(data)
                    if not socks5_client in outputs:
                        outputs.append(socks5_client)
    #from smgw
    if socks5_client in readable:
        try:
            data = socks5_client.recv(4096)
        except socket.error as error:
            if error.errno == errno.EAGAIN:
                time.sleep(0.2)
            else:
                logging.info("Error occurred: " + str(os.strerror(error.errno)))
                dropClient(socks5_client, error) 
                continue
        else:
            if data:
                if int(data[1]) == 3:
                    logging.info('new message from smgw ' + str(socks5_client.getpeername()) + ', length: ' + str(len(data)))

                    ssl_length, = struct.unpack('!H',data[2:4])
                    logging.info('ssl_length ' + str(ssl_length) + ', len(data[4:]: ' + str(len(data[4:])))
                    if ssl_length == len(data[4:]):                     
                        msg = decryptionTLSSession(ssl_handling,data[4:])

                        if msg: 
                            messages_to_broker.put(msg)
                            if not mqtt_client in outputs:
                                outputs.append(mqtt_client)
                            # if msg equals false than continue because connection not established anymore
                        else:
                            logging.warning("Error while decrypting")
                            continue
                    else:
                        dropClient(socks5_client, "Stated length in socks Protocol unequal actual length")
                elif int(data[1]) == 4:
                    dropClient(socks5_client, "smgw terminated connection") 
                    continue
    #handle outputs
    for w in writable:
    
        #to mqtt broker
        if w is mqtt_client:
            try:
                msg = messages_to_broker.get(False)
            except queue.Empty as e:
                pass
            else:
                try:
                    mqtt_client.send(msg)
                    logging.info('send message to mqtt broker' + str(mqtt_client.getpeername())+ ', length: ' + str(len(msg)))
                except socket.error as error:
                    if error.errno == errno.EAGAIN:
                        time.sleep(0.2)
                    else:
                        logging.info("Error occurred: " + str(os.strerror(error.errno)))
                        dropClient(mqtt_client, error)
                        continue    
                else:
                    if messages_to_broker.empty():
                        outputs.remove(mqtt_client) 
         
        #to smgw
        if w is socks5_client:
                try:
                    msg = messages_to_smgw.get(False)
                except queue.Empty as e:
                    pass
                else:
                    try:
                        message_enc = encyptionTLSSession(ssl_handling,msg)
                        logging.info('length of message_enc: ' + str(len(message_enc)))
                        message = addSocks5Header(message_enc)
                        logging.info('send message to smgw ' + str(socks5_client.getpeername())+ ', length: ' + str(len(msg)))
                        socks5_client.send(message)                       
                    except socket.error as error:
                        if error.errno == errno.EAGAIN:
                            time.sleep(0.2)
                        else:
                            logging.info("Error occurred: " + str(os.strerror(error.errno)))
                            dropClient(socks5_client, error)
                            continue
                    else:
                        if messages_to_smgw.empty():
                            outputs.remove(socks5_client)
    for ex in exceptional:
        logging.warning('handling exceptional condition for' +  str(ex.getpeername()))
        # Stop listening for input on the connection
        dropClient(ex,"selected in exceptional")
for s in inputs:
    s.close()
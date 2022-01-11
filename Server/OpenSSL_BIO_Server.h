/*
 * OpenSSL_BIO_Server.h
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#ifndef OpenSSL_BIO_Server_H_
#define OpenSSL_BIO_Server_H_

#include <netinet/in.h>
#include <atomic>
#include <mutex>
struct ssl_ctx_st;
struct ssl_st;
struct bio_st;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;

class OpenSSL_BIO_Server
{
public:
    OpenSSL_BIO_Server();
    virtual ~OpenSSL_BIO_Server();

    // Socket functions
    void createSocket(int port);
    void createOutSocket( );
    void connectToServer(struct sockaddr_in serverAddress);
    void writeToSocket(char* buffer, int size);
    void waitForIncomingConnection();
    char* readFromSocket();
    char* readFromServerSocket();
    void closeSocket();

    bool getServerConnected() {return m_serverConnected;}
    bool getClientConnected() {return m_clientConnected;}

    


    // OpenSSL_BIO_Server functions
    void initOpenSSL();
    void cleanupOpenSSL();
    SSL_CTX* createContext();
    void configureContext(SSL_CTX* ctx);
    void doSSLHandshake();

private:
    std::atomic<int> serverSocket;
    std::atomic<int> clientSocket;
    std::atomic<int> outSocket; 
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    struct sockaddr_in outAddress; 

    bool m_serverConnected = false; 
    bool m_clientConnected = false; 
    std::mutex m_mtxServer; 

    SSL* ssl;
    SSL_CTX* context;
    BIO* readBIO;
    BIO* writeBIO;

    const int BUFFER_SIZE = 16384;
    const char* CERT_FILE = "cert.pem";
    const char* KEY_FILE = "key.pem";
};

#endif /* OpenSSL_BIO_Server_H_ */

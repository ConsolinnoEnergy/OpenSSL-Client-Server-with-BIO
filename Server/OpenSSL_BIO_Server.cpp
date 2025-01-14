/*
 * OpenSSL_BIO_Server.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include "OpenSSL_BIO_Server.h"

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <thread>
#include <fcntl.h> /* Added for the nonblocking socket */
#include <future>


OpenSSL_BIO_Server::OpenSSL_BIO_Server() {}

OpenSSL_BIO_Server::~OpenSSL_BIO_Server() {}


void OpenSSL_BIO_Server::createSocket(int port)
{
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    // Allow binding to already used port
    int optval = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));


 

    if (bind(serverSocket, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Unable to bind socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 1) < 0) {
        perror("Listen on socket failed");
        exit(EXIT_FAILURE);
    }
}


void OpenSSL_BIO_Server::createOutSocket() {
    outSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (outSocket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
}

void OpenSSL_BIO_Server::connectToServer(struct sockaddr_in serverAddress)
{
    
    printf("connect to Server...\n");

 

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(outSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if (connect(outSocket, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

   

  
    m_serverConnected = true; 

    printf("Connected to server\n");

 // std::thread t3([this]{ this->readFromServerSocket(); });
    //std :: thread t (readFromServerSocket, void );
 
}
void OpenSSL_BIO_Server::waitForIncomingConnection()
{
    printf("Waiting for incoming connection...\n");
    unsigned int clientAddressLen = sizeof(clientAddress);

    clientSocket = accept(serverSocket, (struct sockaddr*) &clientAddress, &clientAddressLen);


    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if (clientSocket < 0) {
        perror("Accept on socket failed");
        exit(EXIT_FAILURE);
    }
 
   
    printf("Connection accepted!\n");
    

    doSocksV5Handshake(); //Begin socksv5 handshake

    // ====== Begin SSL handling ====== //
    doSSLHandshake();
    // ====== End SSL handling ====== //
}

void OpenSSL_BIO_Server::doSocksV5Handshake(){
    char buffer[BUFFER_SIZE] = { 0 };

    //Wait for socks handshake data

    bool sockv5HandshakeRead = false;

    while(!sockv5HandshakeRead){
        int receivedBytes = read(clientSocket, buffer, BUFFER_SIZE);
        
        if (receivedBytes > 0) {
            printf("Host has received %d bytes data\n", receivedBytes);
            if(buffer[0] == 5 && buffer[1] == 1 && buffer[2] == 6){ //Socks5, stage 1, auth method 6 (ssl)
                buffer[1] = 6; //Accept auth method
            }
            sockv5HandshakeRead = true;
        }
    }



    printf("Host has %d bytes data to send\n", 2);
    write(clientSocket, buffer, 2);

    printf("Host Socks v5 handshake done!\n");
}

void OpenSSL_BIO_Server::doSSLHandshake()
{
    char buffer[BUFFER_SIZE] = { 0 };
    int shift = 4;

    while (!SSL_is_init_finished(ssl)) {
        SSL_do_handshake(ssl);

        int bytesToWrite = BIO_read(writeBIO, buffer, BUFFER_SIZE);

        if (bytesToWrite > 0) {
            printf("Add Header space\n");
            for(int i=bytesToWrite + shift -1; i >= shift; i--){
                buffer[i] = buffer[i - shift]; 
            }
            bytesToWrite = bytesToWrite + shift;

            printf("Host has %d bytes encrypted data to send\n", bytesToWrite);
            write(clientSocket, buffer, bytesToWrite);
        }
        else {
            int receivedBytes = read(clientSocket, buffer, BUFFER_SIZE);
            
            if (receivedBytes > 0) {
                for(int i = 0; i < receivedBytes; i++){
                    buffer[i] = buffer[i + shift]; 
                }
                receivedBytes = receivedBytes - shift;
                printf("Host has received %d bytes data\n", receivedBytes);
                BIO_write(readBIO, buffer, receivedBytes);
            }
        }
    }

    printf("Host SSL handshake done!\n");

    //Wait for socks subnegotiation data

    bool sockv5SubNegotiationRead = false;

    while(!sockv5SubNegotiationRead){
        int receivedBytes = read(clientSocket, buffer, BUFFER_SIZE);
        
        if (receivedBytes > 0) {
            printf("Host has received %d bytes data\n", receivedBytes);

            for(int i = 0; i < receivedBytes; i++){
                buffer[i] = buffer[i + shift]; 
            }
            receivedBytes = receivedBytes - shift;
            BIO_write(readBIO, buffer, receivedBytes);
            int sizeUnencryptBytes = SSL_read(ssl, buffer, receivedBytes);
            if (sizeUnencryptBytes < 0) {
                perror("SSL_read() in subnegotiation failed");
                exit(EXIT_FAILURE);
            }else{
                char* msg = new char[sizeUnencryptBytes];
                memcpy(msg, buffer, sizeUnencryptBytes);
                printf("Subnegotiation Auth method: %d\n", atoi(msg));
            }

            buffer[0] = 0;

            SSL_write(ssl, buffer, 1);

            int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));

            if (bytesToWrite > 0) {
                for(int i=bytesToWrite + shift -1; i >= shift; i--){
                    buffer[i] = buffer[i - shift]; 
                }
                bytesToWrite = bytesToWrite + shift;
                printf("Host has %d bytes encrypted data to send\n", bytesToWrite);
                write(clientSocket, buffer, bytesToWrite);
            }
            sockv5SubNegotiationRead = true;
        }
    }



  /*  printf("Host has %d bytes data to send\n", 2);
    write(clientSocket, buffer, 2);*/

    printf("Host Socks v5 subnegotiation done!\n");


    readFromSocket(); 
}

char* OpenSSL_BIO_Server::readFromSocket()
{
    printf("readFromSocket\n");

    char buffer[BUFFER_SIZE] = { 0 };

    int shift = 4;
    int host_length = 0;
    uint32_t serverAddress = 0; 

    // int optval = 1;
    // if (setsockopt( clientSocket   , SOL_SOCKET, SO_KEEPALIVE, (char *)&optval, sizeof(optval)) == -1)
    // {    
    //     printf("close socket \n");    
    //     close(clientSocket);
    //     return NULL;
    // }

    int receivedBytes = recv(clientSocket, buffer, BUFFER_SIZE,0);    
    printf("readFromSocket receivedBytes %d\n",receivedBytes);

    if (receivedBytes > 0)
    {

        //Shift data, separate header and encrypted data
        for (int i = 0; i < receivedBytes; i++)
        {
            buffer[i] = buffer[i + shift];
        }

        receivedBytes = receivedBytes - shift;

        printf("Host has received %d bytes encrypted data\n", receivedBytes);
        BIO_write(readBIO, buffer, receivedBytes);

        // SSL_read overrides buffer
        int sizeUnencryptBytes = SSL_read(ssl, buffer, receivedBytes);
        if (sizeUnencryptBytes < 0)
        {
            perror("SSL_read() failed");
            exit(EXIT_FAILURE);
        }
 
       printf("sizeUnencryptBytes %d \n", sizeUnencryptBytes);
       char *msg = new char[sizeUnencryptBytes];
       memcpy(msg, buffer, sizeUnencryptBytes);
   
   
        

        //* copy data to array */

        if (msg[0] == 0x05 && msg[1] == 0x01)
        {

             printf(" socks v5 handling "); 

            uint8_t addr_type = msg[3];
            uint16_t port = 0;

            switch (addr_type)
            {
            case 0x01: // IP V4 addres
                //accept connection 
                port = (msg[8] << 8) + msg[9];
                memcpy(&(serverAddress), msg + 4, 4);
                outAddress.sin_family = AF_INET;
                outAddress.sin_port = htons(port);
                outAddress.sin_addr.s_addr = htonl(serverAddress);

                char buf[16];
                inet_ntop(AF_INET, &serverAddress, buf, 16);
                printf(" received IP V4 addres:  %s  \n", buf);

                printf(" received port:  %i  \n", outAddress.sin_port);

                //connect to Server 
                connectToServer(outAddress);

                buffer[0] = 0x05;
                buffer[1] = 0x00;
                buffer[2] = 0x00;
                buffer[3] = 0x01;

                memcpy(&buffer[4], &outAddress.sin_addr, 4);
                memcpy(&buffer[8], &outAddress.sin_port, 2);

                host_length = 10;

                int retval;
                printf("host_length %d \n", host_length);

                printf(" buffer:  %d  \n", buffer[1]);

                int encSize = SSL_write(ssl, buffer, host_length);


                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                int error = SSL_get_error(ssl, retval);

                printf("1 encSize %d , error %d , retval %d\n", encSize, error, retval);
                int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));

 

                shift = 4;
                printf(" SOCKS5 BIO_read bytesToWrite:  %d \n", bytesToWrite);
                if (bytesToWrite > 0)
                {
                    for (int i = bytesToWrite + shift - 1; i >= shift; i--)
                    {
                        buffer[i] = buffer[i - shift];
                    }

                    bytesToWrite = bytesToWrite + shift;
                    //bytesToWrite = bytesToWrite;
                    printf("server connection: Host has %d bytes encrypted data to send\n", bytesToWrite);
                    write(clientSocket, buffer, bytesToWrite);
                }

                
                // endpoint conformation 
                buffer[0] = 1;
                encSize = SSL_write(ssl, buffer, 1);


                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                error = SSL_get_error(ssl, retval);
                printf("2 encSize %d , error %d , retval %d\n", encSize, error, retval);
                bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));

                if(bytesToWrite>0) {
                    for (int i = bytesToWrite + shift - 1; i >= shift; i--)
                    {
                        buffer[i] = buffer[i - shift];
                    }

                    bytesToWrite = bytesToWrite + shift;
                    //bytesToWrite = bytesToWrite;
                    printf("endpoint conformation Host has %d bytes encrypted data to send\n", bytesToWrite);
                    write(clientSocket, buffer, bytesToWrite);
                }

                readFromSocket();


                break;
            }
        }
        else if (msg[0] == 0)
        {
            printf(" Prepare and send test answer \n");
            //Prepare and send test answer
            buffer[0] = 1;
            buffer[1] = 0;
            host_length = 2;
        }
        else
        {       

            printf(" forward to server "); 

            if(m_serverConnected) {

                writeToSocket(msg, sizeUnencryptBytes);  
                readFromServerSocket();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            }
        }
 
       
        return msg;
    } else {
     
        
        return NULL; 
    }

   
    
}

char* OpenSSL_BIO_Server::readFromServerSocket()
{
     
     printf("readFromServerSocket\n");
    char buffer[BUFFER_SIZE] = { 0 };

    int receivedBytes = recv(outSocket, buffer, BUFFER_SIZE,0);

    int shift = 4; 
    if (receivedBytes > 0) 
    {
        char* msg = new char[receivedBytes];
        memcpy(msg, buffer, receivedBytes);
        printf("received Bytes %d from Server \n ",receivedBytes);

        int encSize = SSL_write(ssl, msg, receivedBytes); 
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));
 
       // printf("buffer first 4 bytes %d %d %d %d\n",buffer[0], buffer[1],  buffer[2] ,  buffer[3] );

      

        printf("buffer first 4 bytes %d %d %d %d\n",buffer[0], buffer[1],  buffer[2] ,  buffer[3] );

        for(int i=bytesToWrite + shift -1; i >= shift; i--)
        {          
            buffer[i] = buffer[i - shift];     
        } 
 
        // add socks5 Heder with length 
        buffer[3] = (uint8_t)((bytesToWrite)&0xFF); 
        buffer[2] = (uint8_t)(((bytesToWrite)>>8)&0xFF);

        printf("buffer first 4 bytes %d %d %d %d\n",buffer[0], buffer[1],  buffer[2] ,  buffer[3] );
 
        //byte to write have added 4 because of the shift. 
        printf("Forward  %d bytes encrypted data to send\n", bytesToWrite+shift);
        write(clientSocket, buffer, bytesToWrite+shift);
        readFromSocket(); 
   
        return msg; 
    }

    readFromSocket();
 
    return NULL; 

}




void OpenSSL_BIO_Server::writeToSocket(char* buffer, int size)
{
 
    printf("writeToSocket\n");
   // int msgSize = read(STDIN_FILENO, buffer, size);
    
    printf("writeToSocket %d \n" ,size);

    if (size > 0) {

        printf("Host has %d bytes  data to send to server \n", size);
        write(outSocket, buffer, size);
        
        readFromServerSocket();

        //std::async(std::launch::async, readFromSocket); 

    }
}

void OpenSSL_BIO_Server::initOpenSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    context = createContext();
    configureContext(context);

    ssl = SSL_new(context);
    readBIO = BIO_new(BIO_s_mem());
    writeBIO = BIO_new(BIO_s_mem());

    SSL_set_bio(ssl, readBIO, writeBIO);
    SSL_set_accept_state(ssl); // Server
}

SSL_CTX* OpenSSL_BIO_Server::createContext()
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    // Creates a server that will negotiate the highest version of SSL/TLS supported
    // by the client it is connecting to.
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    const long flags = SSL_EXT_TLS1_3_ONLY;
    SSL_CTX_set_options(ctx, flags);

    return ctx;
}

void OpenSSL_BIO_Server::configureContext(SSL_CTX* ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void OpenSSL_BIO_Server::closeSocket()
{
    close(clientSocket);
 
    close(outSocket); 
}

void OpenSSL_BIO_Server::cleanupOpenSSL()
{
    SSL_CTX_free(context);
    EVP_cleanup();
}


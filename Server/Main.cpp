/*
 * Main.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include <stdio.h>
#include "OpenSSL_BIO_Server.h"

int main(int argc, char **argv)
{
    OpenSSL_BIO_Server server;

    server.createSocket(1080);
    server.createOutSocket();
    server.initOpenSSL();
    server.waitForIncomingConnection();

    while (1) {
        char* msg = server.readFromSocket();
         
        printf("Message: %s\n", msg);
        delete (msg);

        char* servermsg = server.readFromServerSocket(); 
        printf("Server Message: %s\n", servermsg);
        delete (servermsg);
    }

    server.closeSocket();
    server.cleanupOpenSSL();

}


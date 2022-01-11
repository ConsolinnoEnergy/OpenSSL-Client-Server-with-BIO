/*
 * Main.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include <stdio.h>
#include "OpenSSL_BIO_Client.h"

int main(int argc, char **argv)
{
    OpenSSL_BIO_Client client;

    client.createSocket();
    client.initOpenSSL();

    client.connectToServer(1080);

    while (1) {
        // client.writeToSocket();
        // TODO: connect socket to iec server and forward incomming packages
    }

    client.closeSocket();
    client.cleanupOpenSSL();
}

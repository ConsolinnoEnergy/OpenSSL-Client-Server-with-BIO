/*
 * Main.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include <stdio.h>
#include "OpenSSL_BIO_Server.h"
#include <thread>  

OpenSSL_BIO_Server server;

void thread1()
{

    while (1)
    {
 
        if (server.getServerConnected())
        {
            if (NULL == server.readFromServerSocket())
            {
            
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void thread2 () {
    while(1) {
 
     server.readFromSocket()  ; 
     std::this_thread::sleep_for(std::chrono::milliseconds(10));
       
    }
}


int main(int argc, char **argv)
{
  

 

    server.createSocket(1080);
    server.createOutSocket();
    server.initOpenSSL();
    server.waitForIncomingConnection();
 
  // std::thread t1 (thread2); 
    while( 1 ) {
      server.readFromServerSocket() ;
    }
   //t1.join(); 
   
  

    //server.closeSocket();
    //server.cleanupOpenSSL();

}


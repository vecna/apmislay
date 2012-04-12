/*
 * this is client-example.c
 *
 * vecna@s0ftpj.org Tue Aug 31 11:20:09 CEST 2004, this file
 * exist for the the tranon project, anonymous connection
 * without mix-net engine, without encapsulation and encryption
 *
 * http://www.s0ftpj.org/ take a look for "apmislay" 
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "apmislay.h"

int main(int ac, char **av)
{
	struct sockaddr_in sin;
	FILE *src;
	int nbyte, fd, child;

	if(ac != 4)
	{
		printf("%s: file host(ip only!) port\n", *av);
		return -1;
	}

	src =fopen(av[1], "r");

	fd =socket(AF_INET, SOCK_STREAM, 0);

	sin.sin_addr.s_addr =inet_addr(av[2]);
	sin.sin_family =AF_INET;
	sin.sin_port =htons(atoi(av[3]));

	if(anonymous_connect(fd, (struct sockaddr *)&sin, sizeof(sin), &child) ==-1)
	{
		printf("[%s] error in connect\n", __FILE__);
		return -1;
	}

	while(1)
	{
		char buffer[1000];

		nbyte =read(src->_fileno, buffer, 1000);
		write(fd, buffer, nbyte);

		printf("[%s]sent %d bytes\n", __FILE__, nbyte);

		if(nbyte != 1000) /* read as reach EOF */
			break;
	}

	fclose(src);
	anonymous_close(fd);
	close(fd);

	usleep(200);
	kill(child, SIGTERM);
	return 0;
}

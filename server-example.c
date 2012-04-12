/*
 * this is server-example.c
 *
 * vecna@s0ftpj.org Tue Aug 31 12:30:32 CEST 2004, this file
 * exist for the the apmislay project, anonymous connection
 * without mix-net engine, without encapsulation and encryption
 *
 * http://www.s0ftpj.org/ take a look for "apmislay" 
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "apmislay.h"

int main(int ac, char **av)
{
	struct sockaddr_in my;
	int nbyte, fd, client, child;

	if(ac != 3)
	{
		printf("%s: ip_to_bind port_to_bind\n", *av);
		return -1;
	}

	fd =socket(AF_INET, SOCK_STREAM, 0);

	if((my.sin_addr.s_addr =inet_addr(av[1])) ==inet_addr("X"))
	{
		printf("ip in number.number.number.number format :PP\n");
		return 1;
	}

	my.sin_family =AF_INET;
	my.sin_port =htons(atoi(av[2]));

	if((client =anonymous_bind(fd, (struct sockaddr *)&my, sizeof(my), &child)) ==-1)
	{
		fprintf(stderr, "unable to bind: %s\n", strerror(errno));
		return -1;
	}

	while(1)
	{
		char buffer[1000];

		memset(buffer, 0x00, 1000);

		if((nbyte =read(client, buffer, 1000)) <= 0)
			break;

		printf("%s", buffer);
	}

	close(client);
	anonymous_close(fd);
	close(fd);

	usleep(200); 
	kill(child, SIGTERM);
	return 0;
}

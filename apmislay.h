#define SML		1024	/* small string length */

#define IPRANGE		8
#define IPSHIFT		3
#define CAPLEN		1500

#define ORIGINAL_ADDRESS "192.168.1.69"	/* sender only!! */
#define DEFAULT_TTL	64


/* the some prototypes of system call */
int anonymous_connect(int, const struct sockaddr *, socklen_t, int *);
int anonymous_bind(int, struct sockaddr *, socklen_t, int *);
void anonymous_close(int);


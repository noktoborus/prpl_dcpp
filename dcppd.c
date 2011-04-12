/* vim: ft=c ff=unix fenc=utf-8
 * file: dcppd.c
 */
#define _POSIX_SOURCE 1
#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <ev.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

#define TODO() fprintf (stderr, "TODO: %s, %s -> %s:%u (%s)\n",\
		__TIME__, __DATE__, __FILE__, __LINE__, __func__)

#define INBUF_SZ 1024
#define LINE_SZ_BASE 2048
struct dcpp_root_t
{
	int fd;
	struct dcpp_node_t *node;
};

struct dcpp_node_t
{
	int fd;
	size_t line_sz;
	char inbuf [INBUF_SZ + 1];
	char *line;
	struct dcpp_node_t *next;
};

static struct dcpp_node_t*
gen_client_node (char *addr, int fd_or_port)
{
	/* if addr == NULL, user fd_or_port as fd
	 */
	struct dcpp_node_t *node;
	int lv;
	struct sockaddr_in sin;
	node = calloc (1, sizeof (struct dcpp_node_t));
	if (!node)
		return NULL;
	if (addr)
	{
		node->fd = socket (AF_INET, SOCK_STREAM, 0);
		if (node->fd == -1)
			perror ("socket");
		else
		{
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = inet_addr (addr);
			sin.sin_port = htons ((short)fd_or_port);
			lv = connect (node->fd, (struct sockaddr*)&sin,
					sizeof (struct sockaddr_in));
			if (lv == -1)
				perror ("connect");
			else
			{
				write (node->fd, "$MyNick Noktoborus|",
						strlen ("$MyNick Noktoborus|"));
				return node;
			}
		}
	}
	else
	{
		TODO ();
	}
	if (node)
		free (node);
	return NULL;
}

static void
client_cb (EV_P_ ev_io *ev, int revents)
{
	/*** init */
	int fd;
	char buf[1025];
	ssize_t lv = 0;
	/*** assign */
	fd = ev->fd;
	/*** code */
	lv = read (fd, buf, 1024);
	if (lv > 0)
		buf [lv] = '\0';
	else
		buf [0] = '\0';
	fprintf (stderr, "read (fd=%d, buf=%p, 1024) -> (%d, '%s')\n", fd, buf, lv,
			buf);
	if (lv < 1)
		exit (1);
}

static void
server_cb (EV_P_ ev_io *ev, int revents)
{
	/*
	struct dcpp_root_t *root;
	root = arg;
	*/
}

int
main (int argc, char *argv[])
{
	struct dcpp_node_t *node;
	struct ev_loop *loop;
	ev_io *eve;
	eve = calloc (1, sizeof (ev_io));
	loop = EV_DEFAULT;
	node = gen_client_node ("127.0.0.1", 5690);
	if (node)
	{
		ev_io_init (eve, client_cb, node->fd, EV_READ);
		ev_io_start (loop, eve);
		ev_run (loop, 0);
	}
	fprintf (stderr, "END\n");
	return 0;
}


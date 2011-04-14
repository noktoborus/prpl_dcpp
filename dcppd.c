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

#ifndef DEBUG
# define TODO()
#else
# define TODO() fprintf (stderr, "TODO: %s, %s -> %s:%u (%s)\n",\
		__TIME__, __DATE__, __FILE__, __LINE__, __func__)

ssize_t
read_ (int fd, void *buf, size_t count, char const *file, int line,
		char const *func)
{
	ssize_t lv;
	lv = read (fd, buf, count);
	if (lv >= 0)
		((char*)buf)[lv] = '\0';
	else
		((char*)buf)[0] = '\0';
	fprintf (stderr, "%s:%d.%s () -> read (fd=%d, buf=%p, count=%u) -> "\
			"%d '%s'\n", file, line, func, fd, buf, count, lv, (char*)buf);
	return lv;
}

ssize_t
write_ (int fd, void *buf, size_t count, char const* file, int line,
		char const *func)
{
	ssize_t lv;
	lv = write (fd, buf, count);
	if (lv >= 0)
		((char*)buf)[lv] = '\0';
	else
		((char*)buf)[0] = '\0';
	fprintf (stderr, "%s:%d.%s () -> write (fd=%d, buf=%p, count=%u) -> "\
			"%d '%s'\n", file, line, func, fd, buf, count, lv, (char*)buf);
	return lv;
}

#define read(w, x, y) read_(w, x, y, __FILE__, __LINE__, __func__)
#define write(w, x, y) write_(w, x, y, __FILE__, __LINE__, __func__)
#endif

#define DEFAULT_NICK_(X, Y) #X "." #Y
#define DEFAULT_NICK DEFAULT_NICK_(__FILE__, __func__)
#define INBUF_SZ 1023
#define INBUF_SZ_ (INBUF_SZ + 1)
#define LINE_SZ_BASE (INBUF_SZ << 1)
static struct dcpp_root_t
{
	int fd;
	struct dcpp_node_t *node;
} dcpp_root[] =
{
	{ -1, NULL }
};

struct dcpp_node_t
{
	ev_io evio;
	int fd;
	size_t linein_of; /* offset in $line, must be < $line_sz,
					   if > $line_sz, then skip current buffer cmd
					   	(becouse error) */
	size_t linein_sz; /* size of $line */
	char inbuf[INBUF_SZ_];
	char *linein;
	char *lnick;
	char *rnick;
	struct dcpp_node_t *next;
};

#define DCPP_KEY_NULL	0
#define DCPP_KEY_LOCK	1
#define DCPP_KEY_MYNICK	2
static struct dcpp_keys_t
{
	char *id;
	size_t id_len;
	int key;
} dcpp_keys[] =
{
	{ "$Lock ", 0, DCPP_KEY_LOCK },
	{ "$MyNick ", 0, DCPP_KEY_MYNICK },
	{ NULL, 0, DCPP_KEY_NULL }
};

/* DC++ key func */
#define DCPP_KEY_NESC_IF(X) \
	switch (X)\
	{\
		case 0:\
		case 5:\
		case 36:\
		case 96:\
		case 124:\
		case 126:\
			{

#define DCPP_KEY_NESC_ELSE() \
				break;\
			}\
		default:\
			{

#define DCPP_KEY_NESC_ENDIF() \
			}\
	};

inline static char*
dcpp_key_esc (char *key, size_t len, int cc)
{
	char *line;
	size_t c;
	size_t offset;
	/* test len */
	if (cc < 0)
	{
		for (cc = 0, c = 0; c < len; c ++)
		{
			DCPP_KEY_NESC_IF (key[c]);
				cc ++;
			DCPP_KEY_NESC_ENDIF ();
		}
	}
	/* alloc new */
	if (cc > 0)
		line = malloc (len + (10 * cc) + 1);
	else
		return NULL;
	/* replace */
	for (c = 0; c < len; c ++)
	{
		DCPP_KEY_NESC_IF (key[c]);
		{
			snprintf (&(line[offset]), 11, "/%%DCN%03d%%/", key[c]);
			offset += 10;
		}
		DCPP_KEY_NESC_ELSE ();
			line[offset ++] = key[c];
		DCPP_KEY_NESC_ENDIF ();
	}
	line [offset] = '\0';
	return line;
}

inline static char*
dcpp_extract_key (char *lock, int elen) {
	size_t len;
	size_t i;
	char *key;
	char *key_o;
	char v1;
	size_t extra;
	lock[elen] = '\0';
	if (elen == -1)
		len = strlen (lock);
	else
		len = elen;
    if(len < 3)
        return NULL;
	key = malloc (len + 1);
	key[len] = '\0';
    v1 = (char)(lock[0] ^ 5);
    v1 = (char)(((v1 >> 4) | (v1 << 4)) & 0xff);
    key[0] = v1;
    for (i = 1; i< len; i++)
	{
        v1 = (char)(lock[i] ^ lock[i-1]);
        v1 = (char)(((v1 >> 4) | (v1 << 4)) & 0xff);
        key[i] = v1;
		DCPP_KEY_NESC_IF (key[i]);
		{
            extra++;
		}
		DCPP_KEY_NESC_ENDIF ();
	}
    key[0] = (char)(key[0] ^ key[len - 1]);
	DCPP_KEY_NESC_IF (key[0]);
	{
		extra++;
	}
	DCPP_KEY_NESC_ENDIF ();
    key_o = dcpp_key_esc (key, len, extra);
	if (key_o)
	{
		free (key);
		return key_o;
	}
	else
		return key;
}

static struct dcpp_node_t*
gen_client_node (char *addr, int fd_or_port, const char *nick)
{
	/* if addr == NULL, user fd_or_port as fd
	 */
	struct dcpp_node_t *node;
	int lv;
	size_t len;
	char *buf;
	struct sockaddr_in sin;
	/*** init */
	len = 0;
	lv = -1;
	node = NULL;
	if (!nick)
		nick = DEFAULT_NICK;
	/*** alloc structs */
	len = strlen (nick);
	node = calloc (1, sizeof (struct dcpp_node_t) + len + 1);
	if (node)
	{
		node->lnick = (((char*)node) + sizeof (struct dcpp_node_t));
		memcpy (node->lnick, nick, len);
	}
	/*** check alloc */
	if (!node)
		return NULL;
	/*** code */
	if (addr)
	{
		/*** connect */
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
				/* strlen ('$MyNick |') + 1 == 10 */
				len += 10;
				buf = calloc (len, sizeof (char));
				snprintf (buf, len, "$MyNick %s|", nick);
				len = strlen (buf);
				lv = write (node->fd, buf, len);
				free (buf);
				if (lv == len)
					return node;
			}
		}
	}
	else
	{
		/*** accept */
		TODO ();
	}
	if (node)
	{
		if (node->fd != -1)
			close (node->fd);
		free (node);
	}
	return NULL;
}

static inline void
dcpp_parse_cb (struct dcpp_node_t *node)
{
	/*** init */
	char *tmp;
	size_t c;
	int key = DCPP_KEY_NULL;
	size_t key_of = 0;
	/*** code */
	fprintf (stderr, "PARSE: '%s'\n", node->linein);
	/* search key */
	for (c = 0;; c++)
	{
		if (!dcpp_keys[c].id)
			break;
		else
		if (!dcpp_keys[c].id_len)
			dcpp_keys[c].id_len = strlen (dcpp_keys[c].id);
		/* compare input string and key */
		if (!strncmp (node->linein, dcpp_keys[c].id, dcpp_keys[c].id_len))
		{
			key = dcpp_keys[c].key;
			key_of = dcpp_keys[c].id_len;
			break;
		}
	}
	/* use key in parse */
	switch (key)
	{
		case DCPP_KEY_LOCK:
			{
				tmp = strstr (node->linein, " Pk=");
				if (!tmp)
					break;
				c = tmp - node->linein - key_of;
				tmp = dcpp_extract_key (&node->linein[key_of],
						tmp - node->linein - key_of);
				/* TODO */
				free (tmp);
			}
			break;
		case DCPP_KEY_MYNICK:
			if (!node->rnick)
			{
				c = node->linein_of - key_of;
				node->rnick = calloc (c + 1, sizeof (char));
				memcpy (node->rnick, &(node->linein[key_of]), c);
			}
			break;
	};
}

/*
 * callback for input string (after read)
 * set node->inbuf feel in $len
 */
static inline void
dcpp_input_cb (struct dcpp_node_t *node, size_t len)
{
	/*** init */
	size_t off = 0;
	size_t offl = 0;
	size_t lve;
	char *tmp;
	/*** code */
	for (; off < len; off ++)
	{
		if (node->inbuf[off] == '|' || off == len - 1)
		{
			lve = off - offl + 1;
			/* skip current, if lve == 0 */
			if (!lve)
				continue;
			/* realloc */
			if (node->linein_of <= node->linein_sz &&
					node->linein_sz - node->linein_of < lve)
			{
				tmp = realloc (node->linein, node->linein_of + lve);
				if (tmp)
				{
					/* update len info */
					node->linein = tmp;
					node->linein_sz = node->linein_of + lve;
				}
				else
				{
					/* set error state */
					node->linein_of = node->linein_sz + 1;
				}
			}
			/* copy && execute */
			if (node->linein_of <= node->linein_sz)
			{
				memcpy (&(node->linein[node->linein_of]), &(node->inbuf[offl]),
						lve);
				node->linein_of += lve;
				if (node->inbuf[off] == '|')
				{
					/* set string safe for strlen */
					node->linein[node->linein_of - 1] = '\0';
					/* execute */
					dcpp_parse_cb (node);
					/* reset */
					node->linein_of = 0;
				}
			}
			/* next round */
			offl += lve;
		}
	}
	/* free garbage, if buffer not in use */
	if (!node->linein_of && node->linein_sz > LINE_SZ_BASE)
	{
		free (node->linein);
		node->linein = malloc (LINE_SZ_BASE);
		if (node->linein)
			node->linein_sz = LINE_SZ_BASE;
		else
			node->linein_sz = 0;
	}
}

static void
client_cb (EV_P_ ev_io *ev, int revents)
{
	/*** init */
	ssize_t lv = 0;
	struct dcpp_node_t *node;
	/*** code */
	for (node = dcpp_root->node; node; node = node->next)
		if (ev->fd == node->fd)
			break;
	if (node)
	{
		lv = read (ev->fd, node->inbuf, INBUF_SZ);
		if (lv > 0)
			dcpp_input_cb (node, lv);
	}
	if (lv < 1)
	{
		close (ev->fd);
		if (node)
			node->fd = -1;
		/* remove self from loop */
		ev_io_stop (EV_A_ ev);
	}
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
	struct dcpp_node_t *node_p;
	ev_io *eve;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop = EV_DEFAULT;
	if (!loop)
	{
		fprintf (stderr, "can't init libev\n");
		return 1;
	}
#endif
	/*** main loop */
	/* TODO */
	node = gen_client_node ("127.0.0.1", 5690, "Noktoborus");
	if (node)
	{
		node->next = dcpp_root->node;
		dcpp_root->node = node;
		eve = &(node->evio);
		ev_io_init (eve, client_cb, node->fd, EV_READ);
		ev_io_start (EV_A_ eve);
		ev_run (EV_A_ 0);
	}
	for (node = dcpp_root->node; node; node = node_p)
	{
		node_p = node->next;
		if (node->linein)
			free (node->linein);
		if (node->rnick)
			free (node->rnick);
		free (node);
	}
	fprintf (stderr, "END\n");
	return 0;
}


/* vim: ft=c ff=unix fenc=utf-8
 * file: dcppd.c
 */
/*
 * TODO:
 *	+ $Supports HubTopic
 *	+ $Supports BotList
 *	+ $Supports OpPlus
 *	+ $HubTopic
 *	+ $HubIsFull
 *	+ $HubName
 *
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
#include <stdarg.h>

#include <ev.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

#ifdef DEBUG
# include "dcppd_debug.inc.h"
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
	struct ev_loop *evloop;
} dcpp_root[] =
{
	{ -1, NULL }
};

struct dcpp_node_line_t
{
	char *line;
	size_t of; /* offset in $line, must be < $sz,
				  if > $sz, then skip current buffer cmd (becouse error) */
	size_t sz;
};

struct dcpp_node_c2c_t
{
	char *lnick;
	char *rnick;
	short lrand;
	short rrand;
};

struct dcpp_node_t
{
	ev_io evio;
	int fd;
	unsigned int supports;
	struct dcpp_node_line_t in;
	struct dcpp_node_line_t out;
	char inbuf[INBUF_SZ_];
	struct dcpp_node_c2c_t *c2c;
	struct dcpp_node_t *next;
};

struct dcpp_supports_t
{
	char const *id;
	size_t len;
	unsigned int const key;
};

#define DCPP_SUPN_NONE		0
#define DCPP_SUPN_ADCGET	1
#define DCPP_SUPN_TTHL	(1 << 1)
#define DCPP_SUPN_TTHF	(1 << 2)
#define DCPP_SUPN_ZLIG	(1 << 3)

static struct dcpp_supports_t dcpp_supports_c2c[] =\
{
	{ "ADCGet", 0, DCPP_SUPN_ADCGET },
	{ "TTHL", 0, DCPP_SUPN_TTHL },
	{ "TTHF", 0, DCPP_SUPN_TTHF },
	{ "ZLIG", 0, DCPP_SUPN_ZLIG },
	{ NULL, 0, DCPP_SUPN_NONE }
};

static struct dcpp_supports_t dcpp_supports_c2s[] =\
{
	{ NULL, 0, DCPP_SUPN_NONE }
};

#define DCPP_KEY_NULL	0
#define DCPP_KEY_LOCK	1
#define DCPP_KEY_KEY	2
#define DCPP_KEY_MYNICK	3
static struct dcpp_keys_t
{
	char const *id;
	size_t id_len;
	int const key;
} dcpp_keys[] =
{
	{ "$Lock ", 0, DCPP_KEY_LOCK },
	{ "$Key ", 0, DCPP_KEY_KEY },
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

#define DCPP_FS_(X) #X
#define DCPP_FS(X) DCPP_FS_(X)
#define DCPP_F_END		0 /* end of args */
#define DCPP_F_SEP		1 /* use as packet separator */
#define DCPP_F_STR		2 /* char* */
#define DCPP_F_DSTR		3 /* dynamic char* (free() it after copy) */
#define DCPP_F_HUINT	4 /* host uint (size_t) */
#define DCPP_F_BUINT	5 /* big uint (uint64_t) */

#define DCPP_FF_LOCK		11 /* Fast format: $Lock */
#define DCPP_FF_SUPS_C2C	12 /* Fast format: $Supports (to client) */
#define DCPP_FF_SUPS_C2S	13 /* Fast format: $Supports (to server) */

#define DCPP_FF_LOCK_DT "$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC "\
		"Pk=WANNA_TWO_PEACE"
#define DCPP_FF_LOCK_SZ (sizeof (DCPP_FF_LOCK_DT) - 1)
#define DCPP_FF_SUPS_DT "$Supports "
#define DCPP_FF_SUPS_SZ (sizeof (DCPP_FF_SUPS_DT) - 1)

/* convert string $Supports notation to host */
static inline unsigned int
dcpp_gen_Supports_s2i (struct dcpp_supports_t *supsi, char *input, ssize_t len)
{
	unsigned int r = 0;
	size_t c;
	size_t cc;
	char *s;
	if (!input)
		return 0;
	if (len < -1)
		len = strlen (input);
	if (!len)
		return 0;
	for (s = input, c = 0; c < len; c ++)
	{
		/* test for string delimeter (' ') or EOL */
		if (c != (len - 1))
		{
			if (input[c] != ' ')
				continue;
		}
		else
		{
			/* if EOL, then fix string len */
			c ++;
		}
		/* find key of $Support node */
		for (cc = 0; supsi[cc].id; cc ++)
		{
			if (!(supsi[cc].len))
				supsi[cc].len = strlen (supsi[cc].id);
			/* compare len of strings */
			if (supsi[cc].len == input + c - s)
			{
				/* compare strings */
				if (!strncmp (supsi[cc].id, s, supsi[cc].len))
				{
					r |= supsi[cc].key;
					break;
				}
			}
		}
		/* for next cycle */
		s = &(input[c + 1]);
	}
	return r;
}

/* convert host $Supports notation to string,
 * if $output == NULL, return buffer size only
 * $len == len of output
 */
static inline size_t
dcpp_gen_Supports_2s (struct dcpp_supports_t *supsi, char *output, size_t len)
{
	size_t cc = 0;
	size_t offset = 0;
	size_t tmp;
	for (; supsi[cc].id; cc ++)
	{
		if (!supsi[cc].len)
			supsi[cc].len = strlen (supsi[cc].id);
		if (output)
		{
			if (offset + supsi[cc].len < len)
			{
				memcpy (&(output[offset]), supsi[cc].id, supsi[cc].len);
				offset += supsi[cc].len;
				if (offset + 1 < len)
					output[offset ++] = ' ';
			}
			else
			/* if (offset <= len) */
			{
				/* calculate length */
				tmp = len - offset;
				if (tmp)
				{
					/* prevent 0-length string copy */
					memcpy (&(output[offset]), supsi[cc].id, tmp);
					offset += tmp;
				}
			}
		}
		else
		{
			offset += (supsi[cc].len + 1);
		}
	}
	/* fix last ' ' */
	if (offset)
		offset --;
	return offset;
}

static inline void
dcpp_format_packet (struct dcpp_node_t *node, ...)
{
	size_t blen = 1;
	size_t t;
	struct dcpp_supports_t *supst = NULL;
	char *tmp;
	int va_f;
	va_list va;
	struct ev_loop *evloop = dcpp_root->evloop;
	ev_io *eve;
	if (!node)
		return;
	/* calculate buffer len */
	va_start (va, node);
	while ((va_f = va_arg (va, int)) != DCPP_F_END)
	{
		switch (va_f)
		{
			case DCPP_F_SEP:
				blen ++;
				break;
			case DCPP_F_DSTR:
			case DCPP_F_STR:
				tmp = va_arg (va, char*);
				if (tmp)
					blen += strlen (tmp);
				break;
			case DCPP_F_HUINT:
				blen += sizeof (DCPP_FS (UINTPTR_MAX)) - 1;
				break;
			case DCPP_F_BUINT:
				blen += sizeof (DCPP_FS (UINT64_MAX)) - 1;
				break;
			case DCPP_FF_LOCK:
				blen += DCPP_FF_LOCK_SZ;
				break;
			case DCPP_FF_SUPS_C2C:
				supst = dcpp_supports_c2c;
			case DCPP_FF_SUPS_C2S:
				if (!supst)
					supst = dcpp_supports_c2s;
				t = dcpp_gen_Supports_2s (supst, NULL, 0);
				if (t)
					blen += DCPP_FF_SUPS_SZ + t;
				break;
		};
	}
	va_end (va);
	/* resize buffer */
	if (node->out.of + blen > node->out.sz)
	{
		/* blen + 1 for \0 in snprintf */
		if (node->out.sz < LINE_SZ_BASE)
		{
			tmp = realloc (node->out.line, LINE_SZ_BASE + 1);
			if (tmp)
				node->out.sz = LINE_SZ_BASE + 1;
		}
		else
		{
			tmp = realloc (node->out.line, node->out.of + blen + 1);
			if (tmp)
				node->out.sz = node->out.of + blen + 1;
		}
		if (tmp)
			node->out.line = tmp;
		else
		{
			return;
		}
	}
	/* reset same ptrs */
	supst = NULL;
	/* put data */
	va_start (va, node);
	while ((va_f = va_arg (va, int)) != DCPP_F_END)
	{
		switch (va_f)
		{
			case DCPP_F_SEP:
				node->out.line[node->out.of ++] = '|';
				break;
			case DCPP_F_DSTR:
			case DCPP_F_STR:
				tmp = va_arg (va, char*);
				if (!tmp)
					break;
				blen = strlen (tmp);
				memcpy (&(node->out.line[node->out.of]), tmp, blen);
				node->out.of += blen;
				if (va_f == DCPP_F_DSTR)
					free (tmp);
				break;
			case DCPP_F_HUINT:
				snprintf (&(node->out.line[node->out.of]),
						node->out.sz - node->out.of, "%u",
						va_arg (va, size_t));
				node->out.of += strlen (&(node->out.line[node->out.of]));
				break;
			case DCPP_F_BUINT:
				snprintf (&(node->out.line[node->out.of]),
						node->out.sz - node->out.of, "%llu",
						va_arg (va, uint64_t));
				node->out.of += strlen (&(node->out.line[node->out.of]));
				break;
			case DCPP_FF_LOCK:
				memcpy (&(node->out.line[node->out.of]), DCPP_FF_LOCK_DT,
						DCPP_FF_LOCK_SZ);
				node->out.of += DCPP_FF_LOCK_SZ;
				break;
			case DCPP_FF_SUPS_C2C:
				supst = dcpp_supports_c2c;
			case DCPP_FF_SUPS_C2S:
				if (!supst)
					supst = dcpp_supports_c2s;
				/* если список поддерживаемых расширений пустой, то по адресу
				 * *(line + offset + DCPP_FF_SUPS_SZ) ничего не будет записано
				 * иначе предполагается, что длина буфера была расчитана ранее
				 */
				t = dcpp_gen_Supports_2s (supst,
						&(node->out.line[node->out.of + DCPP_FF_SUPS_SZ]),
						node->out.sz);
				if (t)
				{
					/* если был сгенерирован и скопирован список расширений,
					 * то дописываем "заголовок" сообщения
					 */
					memcpy (&(node->out.line[node->out.of]), DCPP_FF_SUPS_DT,
							DCPP_FF_SUPS_SZ);
					/* и обновляем offset */
					node->out.of += (DCPP_FF_SUPS_SZ + t);
				}
				break;
		};
	}
	va_end (va);
	node->out.line[node->out.of ++] = '|';
	/* update event lists */
	eve = &(node->evio);
	ev_io_stop (evloop, eve);
	ev_io_set (eve, node->fd, eve->events | EV_WRITE);
	ev_io_start (evloop, eve);
}

static struct dcpp_node_t*
gen_client_node (char *addr, int fd_or_port, const char *nick)
{
	/* if addr == NULL, user fd_or_port as fd
	 */
	struct dcpp_node_t *node;
	int lv;
	size_t len;
	struct sockaddr_in sin;
	/*** init */
	len = 0;
	lv = -1;
	node = NULL;
	if (!nick)
		nick = DEFAULT_NICK;
	/*** alloc structs */
	len = strlen (nick);
	node = calloc (1, sizeof (struct dcpp_node_t) +
			sizeof (struct dcpp_node_c2c_t) + len + 1);
	if (node)
	{
		node->c2c = (void*)(((char*)node) + sizeof (struct dcpp_node_t));
		node->c2c->lnick = (((char*)node) + sizeof (struct dcpp_node_t) +
				sizeof (struct dcpp_node_c2c_t));
		memcpy (node->c2c->lnick, nick, len);
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
				/*
				len += 10;
				buf = calloc (len, sizeof (char));
				snprintf (buf, len, "$MyNick %s|", nick);
				len = strlen (buf);
				lv = write (node->fd, buf, len);
				free (buf);
				if (lv == len)
					*/
					return node;
			}
		}
	}
	else
	{
		/*** accept */
		/* TODO */
	}
	if (node)
	{
		if (node->fd != -1)
			close (node->fd);
		free (node);
	}
	return NULL;
}

#define DCPP_EXTENDED_LOCK		"EXTENDEDPROTOCOL"
#define DCPP_EXTENDED_LOCK_SZ	(sizeof (DCPP_EXTENDED_LOCK) - 1)
static inline void
dcpp_parse_cb (struct dcpp_node_t *node)
{
	/*** init */
	char *tmp;
	size_t c;
	int key = DCPP_KEY_NULL;
	size_t key_of = 0;
	/*** code */
	fprintf (stderr, "PARSE: '%s'\n", node->in.line);
	/* search key */
	for (c = 0;; c++)
	{
		if (!dcpp_keys[c].id)
			break;
		else
		if (!dcpp_keys[c].id_len)
			dcpp_keys[c].id_len = strlen (dcpp_keys[c].id);
		/* compare input string and key */
		if (!strncmp (node->in.line, dcpp_keys[c].id, dcpp_keys[c].id_len))
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
				tmp = strstr (node->in.line, " Pk=");
				if (!tmp)
					break;
				c = tmp - node->in.line - key_of;
				tmp = dcpp_extract_key (&(node->in.line[key_of]),
						tmp - node->in.line - key_of);
				if (strncmp (&(node->in.line[key_of]), DCPP_EXTENDED_LOCK,
								DCPP_EXTENDED_LOCK_SZ))
				{
					dcpp_format_packet (node,
							DCPP_F_STR, "$Key ",
							DCPP_F_STR, tmp,
							DCPP_F_END);
				}
				else
				{
					dcpp_format_packet (node,
							DCPP_F_STR, "$Key ",
							DCPP_F_STR, tmp,
							DCPP_F_SEP,
							DCPP_FF_SUPS_C2C,
							DCPP_F_END);
				}
				free (tmp);
			}
			break;
		case DCPP_KEY_MYNICK:
			if (!node->c2c->rnick)
			{
				c = node->in.of - key_of;
				node->c2c->rnick = calloc (c + 1, sizeof (char));
				memcpy (node->c2c->rnick, &(node->in.line[key_of]), c);
				dcpp_format_packet (node, DCPP_FF_LOCK, DCPP_F_END);
			}
			break;
		case DCPP_KEY_KEY:
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
			if (node->in.of <= node->in.sz && node->in.sz - node->in.of < lve)
			{
				if (node->in.of + lve <= LINE_SZ_BASE)
				{
					tmp = realloc (node->in.line, LINE_SZ_BASE);
					if (tmp)
						node->in.sz = LINE_SZ_BASE;
				}
				else
				{
					tmp = realloc (node->in.line, node->in.of + lve);
					if (tmp)
						node->in.sz = node->in.of + lve;
				}
				/* update ptrs */
				if (tmp)
					node->in.line = tmp;
				else
				{
					/* set error state */
					node->in.of = node->in.sz + 1;
				}
			}
			/* copy && execute */
			if (node->in.of <= node->in.sz)
			{
				memcpy (&(node->in.line[node->in.of]), &(node->inbuf[offl]),
						lve);
				node->in.of += lve;
				if (node->inbuf[off] == '|')
				{
					/* set string safe for strlen */
					node->in.line[node->in.of - 1] = '\0';
					/* execute */
					dcpp_parse_cb (node);
					/* reset */
					node->in.of = 0;
				}
			}
			/* next round */
			offl += lve;
		}
	}
	/* free garbage, if buffer not in use */
	if (!node->in.of && node->in.sz > LINE_SZ_BASE)
	{
		free (node->in.line);
		node->in.line = malloc (LINE_SZ_BASE);
		if (node->in.line)
			node->in.sz = LINE_SZ_BASE;
		else
			node->in.sz = 0;
	}
}

static inline struct dcpp_node_t*
get_client_node (int fd)
{
	struct dcpp_node_t *node;
	for (node = dcpp_root->node; node; node = node->next)
		if (fd == node->fd)
			return node;
	return NULL;
}

static inline void
client_read_cb (struct ev_loop *evloop, ev_io *ev, int revents)
{
	/*** init */
	ssize_t lv = 0;
	struct dcpp_node_t *node;
	/*** code */
	node = get_client_node (ev->fd);
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
		ev_io_stop (evloop, ev);
	}
}

static inline void
client_write_cb (struct ev_loop *evloop, ev_io *ev, int revents)
{
	struct dcpp_node_t *node = get_client_node (ev->fd);
	ssize_t lv;
	/* try send buffer */
	if (node && node->out.of)
	{
		lv = write (ev->fd, node->out.line, node->out.of);
		if (lv > 0)
		{
			if (lv != node->out.of)
			{
				/* copy message to start of line */
				memmove (node->out.line, &(node->out.line[lv]),
						node->out.of -= lv);
			}
			else
				node->out.of = 0;
		}
		else
		{
			/* exception */
			/* TODO */
			ev_io_stop (evloop, ev);
		}
	}
	/* try remove buffer from event list */
	if (!node || !node->out.of)
	{
		ev_io_stop (evloop, ev);
		ev_io_set (ev, ev->fd, ev->events & ~EV_WRITE);
		ev_io_start (evloop, ev);
	}
}

static void
client_dispatch_cb (struct ev_loop *evloop, ev_io *ev, int revents)
{
	fprintf (stderr, "!! DISP: %d, ", revents);
	if (revents & EV_READ)
		fprintf (stderr, "EV_READ ");
	if (revents & EV_WRITE)
		fprintf (stderr, "EV_WRITE ");
	fprintf (stderr, "\n");

	if (revents & EV_READ)
		client_read_cb (evloop, ev, revents);
	if (revents & EV_WRITE)
		client_write_cb (evloop, ev, revents);
}

static void
server_cb (struct ev_loop *evloop, ev_io *ev, int revents)
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
	char *nick = "Noktoborus";
	ev_io *eve;
#ifdef DEBUG
	ev_set_allocator (_ev_alloc);
#endif
	struct ev_loop *evloop = EV_DEFAULT;
	if (!evloop)
	{
		fprintf (stderr, "can't init libev\n");
		return 1;
	}
	dcpp_root->evloop = evloop;
	/*** main loop */
	/* TODO */
	node = gen_client_node ("127.0.0.1", 5690, nick);
	if (node)
	{
		node->next = dcpp_root->node;
		dcpp_root->node = node;
		eve = &(node->evio);
		ev_io_init (eve, client_dispatch_cb, node->fd, EV_READ | EV_WRITE);
		ev_io_start (evloop, eve);
		dcpp_format_packet (node,
				DCPP_F_STR, "$MyNick ",
				DCPP_F_STR, nick,
				DCPP_F_END);
		fprintf (stderr, "RUN\n");
		ev_run (evloop, 0);
	}
	for (node = dcpp_root->node; node; node = node_p)
	{
		node_p = node->next;
		if (node->in.line)
			free (node->in.line);
		if (node->out.line)
			free (node->out.line);
		if (node->c2c->rnick)
			free (node->c2c->rnick);
		free (node);
	}
	ev_loop_destroy (EV_DEFAULT);
	fprintf (stderr, "END\n");
	return 0;
}


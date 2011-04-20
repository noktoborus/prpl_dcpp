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
#include <time.h>

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
#define DCPP_BUF_SZ		1023
#define DCPP_BUF_SZ_	(DCPP_BUF_SZ + 1)
#define LINE_SZ_BASE	((DCPP_BUF_SZ << 1) + 1)
static struct dcpp_root_t
{
	int fd;
	struct dcpp_node_t *node;
} dcpp_root[] =
{
	{ -1, NULL }
};

struct dcpp_node_c2c_t
{
	char *lnick;
	char *rnick;
	unsigned short lrand;
	unsigned short rrand;
};

#define DCPP_OUT_T_NONE	0
#define DCPP_OUT_T_END	DCPP_OUT_T_NONE
#define DCPP_OUT_T_STR	4
#define DCPP_OUT_T_FILE	5
struct dcpp_node_out_file_t
{
	off_t offset;
	off_t size;
	char fname[1];
};

struct dcpp_node_out_t
{
	char type;		/* for DCPP_OUT_T_* */
	size_t size;	/* reserved bytes for this struct */
	union
	{
		char *string;
		struct dcpp_node_out_file_t *file;
	} store;
};

struct dcpp_node_t
{
	ev_io evio;
	int fd;
	unsigned int supports;
	struct
	{
		char buf[DCPP_BUF_SZ_];
		char *line;
		size_t of; /* offset in $line, must be < $sz,
						else skip current cmd (as error) */
		size_t sz;
	} in;
	struct
	{
		char buf[DCPP_BUF_SZ_];
		char *queue;	/* pointer to start of buffer */
		size_t qlast;	/* offset to last node */
		size_t feel;	/* заполненность буфера (не должен превышать size) */
		size_t size;	/* size of all allocated buffer */
	} out;
	char inbuf[DCPP_BUF_SZ_];
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
#define DCPP_SUPN_TTHL		(1 << 1)
#define DCPP_SUPN_TTHF		(1 << 2)
#define DCPP_SUPN_ZLIG		(1 << 3)
#define DCPP_SUPN_XMLBZLIST	(1 << 4)

static struct dcpp_supports_t dcpp_supports_c2c[] =\
{
	{ "ADCGet", 0, DCPP_SUPN_ADCGET },
	{ "TTHL", 0, DCPP_SUPN_TTHL },
	{ "TTHF", 0, DCPP_SUPN_TTHF },
	/*{ "ZLIG", 0, DCPP_SUPN_ZLIG },*/
	{ "XmlBZList", 0, DCPP_SUPN_XMLBZLIST },
	{ NULL, 0, DCPP_SUPN_NONE }
};

static struct dcpp_supports_t dcpp_supports_c2s[] =\
{
	{ NULL, 0, DCPP_SUPN_NONE }
};

#define DCPP_KEY_NULL		0
#define DCPP_KEY_LOCK		1
#define DCPP_KEY_KEY		2
#define DCPP_KEY_MYNICK		3
#define DCPP_KEY_SUPPORTS	4
#define DCPP_KEY_DIRECTION	5
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
	{ "$Supports ", 0, DCPP_KEY_SUPPORTS },
	{ "$Direction ", 0, DCPP_KEY_DIRECTION },
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
dcpp_format_packet (EV_P_ struct dcpp_node_t *node, ...)
{
	size_t blen	= 1;
	size_t tlen	= 0;
	char *ptr	= NULL;
	int va_f	= DCPP_F_END;
	ev_io *eve;
	struct dcpp_node_out_t *qptr	= NULL;
	struct dcpp_supports_t *supst	= NULL;
	va_list va;
	if (!node)
		return;
	/* если предыдущая задача не строка, то учитываем размер заголовка */
	qptr = (struct dcpp_node_out_t*)(node->out.queue + node->out.qlast);
	if (!node->out.queue || qptr->type != DCPP_OUT_T_STR)
		blen += sizeof (struct dcpp_node_out_t);
	/* count new buffer size */
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
				ptr = va_arg (va, char*);
				if (ptr)
					blen += strlen (ptr);
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
				tlen = dcpp_gen_Supports_2s (supst, NULL, 0);
				if (tlen)
					blen += (DCPP_FF_SUPS_SZ + tlen);
				break;
		}
	}
	va_end (va);
	/* realloc buffer, if need */
	tlen = node->out.feel + blen;
	if (tlen > node->out.size)
	{
		if (node->out.size < LINE_SZ_BASE && tlen < LINE_SZ_BASE)
			tlen = LINE_SZ_BASE;
		ptr = realloc (node->out.queue, tlen);
		if (!ptr)
			return;
		node->out.queue = ptr;
		node->out.size = tlen;
		tlen = node->out.size - node->out.feel;
		/* set zero, if length > 0 */
		if (tlen)
			memset (&(node->out.queue[node->out.feel]), 0, tlen);
	}
	/* reset ptrs */
	supst = NULL;
	blen = 0;
	/* prepare to put data */
	qptr = (struct dcpp_node_out_t*)(node->out.queue + node->out.qlast);
	if (qptr->type != DCPP_OUT_T_STR)
	{
		node->out.qlast = node->out.feel;
		node->out.feel += sizeof (struct dcpp_node_out_t);
		qptr = (void*)(node->out.queue + node->out.qlast);
		qptr->type = DCPP_OUT_T_STR;
	}
	else
		/* set offset in string */
		blen = qptr->size;
	qptr->store.string = ((char*)qptr) + sizeof (struct dcpp_node_out_t);
	/* feel buffer */
	va_start (va, node);
	while ((va_f = va_arg (va, int)) != DCPP_F_END)
	{
		switch (va_f)
		{
			case DCPP_F_SEP:
				qptr->store.string[blen ++] = '|';
				break;
			case DCPP_F_DSTR:
			case DCPP_F_STR:
				ptr = va_arg (va, char*);
				if (!ptr)
					break;
				tlen = strlen (ptr);
				memcpy (&(qptr->store.string[blen]), ptr, tlen);
				blen += tlen;
				if (va_f == DCPP_F_DSTR)
					free (ptr);
				break;
			case DCPP_F_HUINT:
				tlen = node->out.size - node->out.feel - blen;
				snprintf (&(qptr->store.string[blen]), tlen,
						"%u", va_arg (va, size_t));
				blen += strlen (&(qptr->store.string[blen]));
				break;
			case DCPP_F_BUINT:
				tlen = node->out.size - node->out.feel - blen;
				snprintf (&(qptr->store.string[blen]), tlen,
						"%llu", va_arg (va, uint64_t));
				blen += strlen (&(qptr->store.string[blen]));
				break;
			case DCPP_FF_LOCK:
				memcpy (&(qptr->store.string[blen]), DCPP_FF_LOCK_DT,
						DCPP_FF_LOCK_SZ);
				blen += DCPP_FF_LOCK_SZ;
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
				tlen = dcpp_gen_Supports_2s (supst,
						&(qptr->store.string[blen + DCPP_FF_SUPS_SZ]),
						node->out.size - node->out.qlast - DCPP_FF_SUPS_SZ -
							blen - sizeof (struct dcpp_node_out_t));
				if (tlen)
				{
					/* если был сгенерирован и скопирован список расширений,
					 * то дописываем "заголовок" сообщения
					 */
					memcpy (&(qptr->store.string[blen]), DCPP_FF_SUPS_DT,
							DCPP_FF_SUPS_SZ);
					/* и обновляем offset */
					blen += (DCPP_FF_SUPS_SZ + tlen);
				}
				break;
		};
	}
	va_end (va);
	qptr->store.string[blen ++] = '|';
	/* finalize calculate */
	qptr->size = blen;
	node->out.feel = node->out.qlast + qptr->size +
			sizeof (struct dcpp_node_out_t);
	/* update ev */
	eve = &(node->evio);
	ev_io_stop (EV_A_ eve);
	ev_io_set (eve, node->fd, eve->events | EV_WRITE);
	ev_io_start (EV_A_ eve);
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
				return node;
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
dcpp_parse_cb (EV_P_ struct dcpp_node_t *node)
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
				/* TODO: определять направление ($Direction): Download или
				 * Upload */
				srand ((unsigned int)time (NULL));
				node->c2c->lrand = rand () % 32767;
				if (strncmp (&(node->in.line[key_of]), DCPP_EXTENDED_LOCK,
								DCPP_EXTENDED_LOCK_SZ))
				{
					/* old protocol variant */
					dcpp_format_packet (EV_A_ node,
							DCPP_F_STR, "$Direction Upload ",
							DCPP_F_HUINT, node->c2c->lrand,
							DCPP_F_SEP,
							DCPP_F_STR, "$Key ",
							DCPP_F_STR, tmp,
							DCPP_F_END);
				}
				else
				{
					/* EXTENDEDPROTOCOL-variant */
					dcpp_format_packet (EV_A_ node,
							DCPP_FF_SUPS_C2C,
							DCPP_F_SEP,
							DCPP_F_STR, "$Direction Upload ",
							DCPP_F_HUINT, node->c2c->lrand,
							DCPP_F_SEP,
							DCPP_F_STR, "$Key ",
							DCPP_F_STR, tmp,
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
				dcpp_format_packet (EV_A_ node, DCPP_FF_LOCK, DCPP_F_END);
			}
			break;
		case DCPP_KEY_KEY:
			/* TODO? */
			break;
		case DCPP_KEY_SUPPORTS:
			node->supports = dcpp_gen_Supports_s2i (dcpp_supports_c2c,
					&(node->in.line[key_of]), node->in.of - key_of);
			break;
		case DCPP_KEY_DIRECTION:
			tmp = strchr (&(node->in.line[key_of]), ' ');
			if (tmp && (tmp - &(node->in.line[key_of])) == 8)
				/* only Download-direction unpack */
				node->c2c->rrand = (unsigned short)strtoul (tmp + 1, NULL, 10);
			break;
	};
}

/*
 * callback for input string (after read)
 * set node->inbuf feel in $len
 */
static inline void
dcpp_input_cb (EV_P_ struct dcpp_node_t *node, size_t len)
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
					dcpp_parse_cb (EV_A_ node);
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
client_read_cb (EV_P_ ev_io *ev, int revents)
{
	/*** init */
	ssize_t lv = 0;
	struct dcpp_node_t *node;
	/*** code */
	node = get_client_node (ev->fd);
	if (node)
	{
		lv = read (ev->fd, node->inbuf, DCPP_BUF_SZ);
		if (lv > 0)
			dcpp_input_cb (EV_A_ node, lv);
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

static inline size_t
dcpp_output_cb (EV_P_ struct dcpp_node_t *node)
{
	size_t len	= 0u;
	size_t tlen	= 0u;
	struct dcpp_node_out_t *qptr;
	/* prevent exceptions */
	if (!node)
		return 0u;
	/* copy to buffer */
	if (node->out.feel)
	{
		qptr = (struct dcpp_node_out_t*)node->out.queue;
		switch (qptr->type)
		{
			case DCPP_OUT_T_STR:
				if (qptr->size <= DCPP_BUF_SZ)
				{
					/* copy string to outbuf */
					memcpy (node->out.buf, qptr->store.string, qptr->size);
					len = qptr->size;
					/* remove node from queue */
					tlen = node->out.feel -
							sizeof (struct dcpp_node_out_t) - qptr->size;
					if (tlen)
					{
						/* copy next struct to start of buffer */
						memmove (node->out.queue,
								&(node->out.queue[
									sizeof (struct dcpp_node_out_t) +
									qptr->size]), tlen);
					}
					/* or zero current struct */
					else
					{
						memset (node->out.queue, 0,
								sizeof (struct dcpp_node_out_t));
					}
					node->out.feel = tlen;
				}
				else
				{
					memcpy (node->out.buf, qptr->store.string, DCPP_BUF_SZ);
					len = DCPP_BUF_SZ;
					/* move data */
					tlen = node->out.feel - DCPP_BUF_SZ -
						sizeof (struct dcpp_node_out_t);
					memmove (qptr->store.string,
							&(qptr->store.string[DCPP_BUF_SZ]), tlen);
					node->out.feel -= DCPP_BUF_SZ;
					qptr->size -= DCPP_BUF_SZ;
				}
				break;
			case DCPP_OUT_T_FILE:
				/* TODO */
				break;
		}
	}
	return len;
	/* TODO */
}

static inline void
client_write_cb (EV_P_ ev_io *ev, int revents)
{
	ssize_t lv;
	size_t len;
	/* prepare buffer */
	struct dcpp_node_t *node;
	node = get_client_node (ev->fd);
	if (node)
	{
		len = dcpp_output_cb (EV_A_ node);
		if (len)
		{
			/* send buffer */
			lv = write (ev->fd, node->out.buf, len);
			if (lv != len)
			{
				/* exception */
				ev_io_stop (EV_A_ ev);
				return;
			}
		}
	}
	/* try remove buffer from event list (for write) */
	if (!node || !node->out.feel)
	{
		ev_io_stop (EV_A_ ev);
		ev_io_set (ev, ev->fd, ev->events & ~EV_WRITE);
		ev_io_start (EV_A_ ev);
	}
}

static void
client_dispatch_cb (EV_P_ ev_io *ev, int revents)
{
	fprintf (stderr, "!! DISP: %d, ", revents);
	if (revents & EV_READ)
		fprintf (stderr, "EV_READ ");
	if (revents & EV_WRITE)
		fprintf (stderr, "EV_WRITE ");
	fprintf (stderr, "\n");

	if (revents & EV_READ)
		client_read_cb (EV_A_ ev, revents);
	if (revents & EV_WRITE)
		client_write_cb (EV_A_ ev, revents);
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
	char *nick = "Noktoborus";
	ev_io *eve;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop = EV_DEFAULT;
	if (!loop)
	{
		fprintf (stderr, "can't init libev\n");
		return 1;
	}
#endif
#ifdef DEBUG
	ev_set_allocator (_ev_alloc);
#endif
	/*** main loop */
	/* TODO */
	node = gen_client_node ("127.0.0.1", 5690, nick);
	if (node)
	{
		node->next = dcpp_root->node;
		dcpp_root->node = node;
		eve = &(node->evio);
		ev_io_init (eve, client_dispatch_cb, node->fd, EV_READ | EV_WRITE);
		ev_io_start (EV_A_ eve);
		dcpp_format_packet (EV_A_ node,
				DCPP_F_STR, "$MyNick ",
				DCPP_F_STR, nick,
				DCPP_F_END);
		fprintf (stderr, "RUN\n");
		ev_run (EV_A_ 0);
	}
	for (node = dcpp_root->node; node; node = node_p)
	{
		node_p = node->next;
		if (node->in.line)
			free (node->in.line);
		if (node->out.queue)
			free (node->out.queue);
		if (node->c2c->rnick)
			free (node->c2c->rnick);
		free (node);
	}
	ev_loop_destroy (EV_A);
	fprintf (stderr, "END\n");
	return 0;
}


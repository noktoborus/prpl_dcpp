/* vim: ft=c ff=unix fenc=utf-8
 * file: S5dc.h
 */
#ifndef _S5DC_1304994850_H_
#define _S5DC_1304994850_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>
#include <netdb.h>

#define LINE_SZ		1024
#define LINE_SZ_	(LINE_SZ + 1)

struct _s_cout_file_t
{
	int fd;
	off_t offset;
	off_t length;
};

#define _S_T_NULL	0
#define _S_T_STRING	1
#define _S_T_FILE	2
struct _s_cout_t
{
	char type;
	size_t size;
	char buffer[1];
};

struct _s_cony_t
{
	int fd;
	ev_io evio;
	struct
	{
		char *line;
		size_t fill;
		size_t size;
		char buf[LINE_SZ_];
		size_t inbuf;
	} in;
	struct
	{
		char *line;
		size_t fill;
		size_t size;
		size_t last;
		char buf[LINE_SZ_];
		size_t inbuf;
	} out;
};

#define S5_AT_IP	1	/* ip(v4|v6) address */
#define S5_AT_DN	2	/* domain name */

#define S5_ST_NONE	0
#define S5_ST_AUTH	1	/* wait auth */
#define S5_ST_TRANS	2	/* prepare complete */
struct S5_store_t
{
	unsigned char state;
	char atype;	/* address type */
	unsigned char no;
	unsigned char addr_len;
	union
	{
		char dn[257]; /* strlen (name) + 1 */
		unsigned char ip[16]; /* ipv4 or ipv6 */
		uint32_t ipv4;
	} addr;
	union
	{
		uint16_t p16;
		uint8_t p8[2];
	} port;
};

struct dcpp_acc_t
{
	uint32_t crc32;
	/* MyINFO */
	size_t nick;
	size_t description;
	size_t email;
	/* tag */
	size_t tag_client;
	size_t tag_version;
	char store[1];
};

/*** STATES */
#define STATE_FREE	0	/* */
/* SOCKS5-states */
#define STATE_S5	1	/* SOCKS5 */
#define STATE_S5_H0	STATE_S5 /* get version # */
#define STATE_S5_H1	2	/* get size of auth method array */
#define STATE_S5_H2	3	/* choose auth method */
#define STATE_S5_W0	4	/* get version # */
#define STATE_S5_W1	5	/* get type of socket (command) */
#define STATE_S5_WR	6	/* RESERVED BYTE (always == 0x00) */
#define STATE_S5_W2	7	/* get type of address */
#define STATE_S5_W3	8	/* fill address */
#define STATE_S5_W4	9	/* fill port */
/* DC-states */
#define STATE_DC	10	/* DC */
/* */
#define STATE_END	11	/* FINILIZE CONNECTION */
/**** --- */
#define ERRCC_MAX	8	/* max of exception, before destruct structures */
struct S5tun_t
{
	struct _s_cony_t _s[2]; /* { SOCK5, DC }  */
	union
	{
		void *ptr;
		struct dcpp_acc_t *acc;
		struct S5_store_t *sto;
	} u;
	size_t u_sz;
	struct S5tun_t *next;
	/* */
	unsigned char errcc; /* exception counter */
	char state;
};

struct S5srv_t
{
	int fd;
	ev_io evio;
	struct S5tun_t *clist;
};

/**** DC++ symbols */
/* format message (for DC++) */
#define DCPP_FS_(X) #X
#define DCPP_FS(X) DCPP_FS_(X)
/* Format */
#define DCPP_F_END		0 /* end of args */
#define DCPP_F_SEP		1 /* use as packet separator */
#define DCPP_F_STR		2 /* char* */
#define DCPP_F_DSTR		3 /* dynamic char* (free() it after copy) */
#define DCPP_F_HUINT	4 /* host uint (size_t) */
#define DCPP_F_BUINT	5 /* big uint (uint64_t) */

/* Fast Formats */
#define DCPP_FF_LOCK	11 /* Fast format: $Lock */
#define DCPP_FF_SUPS	12 /* Fast foramt: $Supports */

#define DCPP_FF_LOCK_DT "$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC "\
		"Pk=WANNA_TWO_PEACE"
#define DCPP_FF_LOCK_SZ (sizeof (DCPP_FF_LOCK_DT) - 1)
#define DCPP_FF_SUPS_DT "$Supports "
#define DCPP_FF_SUPS_SZ (sizeof (DCPP_FF_SUPS_DT) - 1)

/* supports */
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
#define DCPP_SUPN_S5DCPROXY	(1 << 5)

static struct dcpp_supports_t dcpp_supports_s5[] =
{
	{ "S5DCProxy", 0, DCPP_SUPN_S5DCPROXY },
	{ NULL, 0, DCPP_SUPN_NONE } /* EOL */
};

#endif /* _S5DC_1304994850_H_ */


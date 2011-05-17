/* vim: ft=c ff=unix fenc=utf-8
 * file: dcppd_S5s.c
 */
#include "S5dc.h"

static void clipair_dispatch_cb (EV_P_ ev_io *ev, int revents);

/**** DC protocol utils */
/* convert string $Supports notation to host */
static inline unsigned int
dcpp_sups2i (struct dcpp_supports_t *supsi, char *input, ssize_t len)
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
dcpp_i2sups (struct dcpp_supports_t *supsi, char *output, size_t len)
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
			offset += (supsi[cc].len + 1);
	}
	/* fix last ' ' */
	if (offset)
		offset --;
	return offset;
}

/**** proxy funcs */
static struct S5tun_t*
S5_get_tun (struct S5srv_t *root, int fd)
{
	struct S5tun_t *tun;
	if (!root)
		return NULL;
	if (fd == -1)
	{
		/* search not assigned elemets, or create new */
		for (tun = root->clist; tun; tun = tun->next)
		{
			if (tun->state == STATE_FREE)
				break;
		}
		/* test structs */
		if (!tun)
			tun = malloc (sizeof (struct S5tun_t));
		else
		if (tun->u.ptr)
			free (tun->u.ptr);
		/* put zero in struct */
		if (tun)
			memset (tun, 0, sizeof (struct S5tun_t));
	}
	else
	{
		/* try to match fd */
		for (tun = root->clist; tun; tun = tun->next)
		{
			if (tun->_s[0].fd == fd || tun->_s[0].fd == fd)
				break;
		}
	}
	/* return result */
	return tun;
}

/* messages */
static struct _s_cout_t*
msg_format_buf_ (struct _s_cony_t *cony, size_t length, char type)
{
	bool _ex = false;
	size_t tlen;
	void *tmp;
	struct _s_cout_t *cout;
	if (cony->out.fill)
	{
		cout = (void*)(cony->out.line + cony->out.last);
		if (cout->type != type || type != _S_T_STRING)
			_ex = true;
	}
	else
		_ex = true;
	/* calc size */
	tlen = length + cony->out.fill;
	if (_ex)
		tlen += sizeof (struct _s_cout_t);
	/* check space in buffer */
	if (tlen > cony->out.size)
	{
		if (tlen < LINE_SZ)
			tlen = LINE_SZ;
		/* realloc */
		tmp = realloc (cony->out.line, tlen);
		if (tmp)
		{
			/* update sizes */
			cony->out.line = tmp;
			cony->out.size = tlen;
		}
		else
			return NULL;
	}
	/* update ptr */
	if (_ex)
	{
		cony->out.last = cony->out.fill;
		/* put zero in *cout */
		memset (cony->out.line + cony->out.last, 0, sizeof (struct _s_cout_t));
	}
	cout = (void*)(cony->out.line + cony->out.last);
	/* return */
	return cout;
}

/* format file for output buffer */
static void
msg_format_file (struct _s_cony_t *cony, int fd, off_t off, off_t len)
{
	struct _s_cout_t *cout;
	struct _s_cout_file_t *cfile;
	size_t tlen;
	if (off >= len || fd == -1)
		return;
	/* update size */
	cout = msg_format_buf_ (cony, sizeof (struct _s_cout_file_t), _S_T_FILE);
	if (!cout)
		return;
	/* update ptrs */
	cout->type = _S_T_FILE;
	cout->size = sizeof (struct _s_cout_file_t);
	tlen = sizeof (struct _s_cout_file_t) + sizeof (struct _s_cout_t);
	cfile = (void*)cout->buffer;
	/* set data */
	cfile->fd = fd;
	cfile->offset = off;
	cfile->length = len;
	/* terminate */
	cout->buffer[sizeof (struct _s_cout_file_t)] = '\0';
	/* finialize */
	cony->out.fill += tlen;
}

/* put raw F_STRING (with length) to output buffer
 * msg_format_raw (cony, 7, "buffer0", 1, "e", 7, "buffer2", 0)
 */
static void
msg_format_raw (struct _s_cony_t *cony, ...)
{
	struct _s_cout_t *cout = NULL;
	size_t tlen = 0u;
	size_t length = 0u;
	char *buffer = NULL;
	va_list va;
	va_start (va, cony);
	while ((length = va_arg (va, size_t)))
	{
		va_arg (va, char*);
		tlen += length;
	}
	va_end (va);
	/* check size of buffer */
	cout = msg_format_buf_ (cony, length, _S_T_STRING);
	if (!cout)
		return;
	/* update type */
	if (cout->type != _S_T_STRING)
		cout->type = _S_T_STRING;
	/* */
	/* copy buffers */
	va_start (va, cony);
	while ((length = va_arg (va, size_t)))
	{
		buffer = va_arg (va, char*);
		memcpy ((cout->buffer + cout->size), buffer, length);
		cout->size += length;
	}
	va_end (va);
	cout->buffer[cout->size] = '\0';
	/* update sizes */
	cony->out.fill = cony->out.last + sizeof (struct _s_cout_t) + cout->size;
}

/* format message, before put to output buffer */
static void
msg_format_dcpp (struct _s_cony_t *cony, ...)
{
	int va_f	= DCPP_F_END;
	size_t blen	= 1; /* calc with '|' at end of string */
	size_t tlen	= 0;
	char *val	= NULL;
	struct _s_cout_t *cout	= NULL;
	struct dcpp_supports_t *supst	= NULL;
	va_list va;
	/* count new buffer size */
	va_start (va, cony);
	while ((va_f = va_arg (va, int)) != DCPP_F_END)
	{
		switch (va_f)
		{
			case DCPP_F_SEP:
				blen ++;
				break;
			case DCPP_F_DSTR:
			case DCPP_F_STR:
				val = va_arg (va, char*);
				if (val)
					blen += strlen (val);
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
			case DCPP_FF_SUPS:
				supst = va_arg (va, struct dcpp_supports_t*);
				if (supst)
				{
					tlen = dcpp_i2sups (supst, NULL, 0);
					if (tlen)
						blen += (DCPP_FF_SUPS_SZ + tlen);
				}
				break;
		}
	}
	va_end (va);
	/* realloc buffer, if need */
	cout = msg_format_buf_ (cony, blen, _S_T_STRING);
	if (!cout)
		return;
	/* reset ptrs */
	supst = NULL;
	blen = 0;
	/**** prepare to put data */
	if (cout->type != _S_T_STRING)
	{
		blen = 0;
		cony->out.fill += sizeof (struct _s_cout_t);
		cout->type = _S_T_STRING;
	}
	else
		/* set offset in string */
		blen = cout->size;
	/* fill buffer */
	va_start (va, cony);
	while ((va_f = va_arg (va, int)) != DCPP_F_END)
	{
		switch (va_f)
		{
			case DCPP_F_SEP:
				cout->buffer[blen ++] = '|';
				break;
			case DCPP_F_DSTR:
			case DCPP_F_STR:
				val = va_arg (va, char*);
				if (!val)
					break;
				tlen = strlen (val);
				memcpy (&(cout->buffer[blen]), val, tlen);
				blen += tlen;
				if (va_f == DCPP_F_DSTR)
					free (val);
				break;
			case DCPP_F_HUINT:
				tlen = cony->out.size - cony->out.fill - blen;
				snprintf (&(cout->buffer[blen]), tlen,
						"%u", va_arg (va, size_t));
				blen += strlen (&(cout->buffer[blen]));
				break;
			case DCPP_F_BUINT:
				tlen = cony->out.size - cony->out.fill - blen;
				snprintf (&(cout->buffer[blen]), tlen,
						"%llu", va_arg (va, uint64_t));
				blen += strlen (&(cout->buffer[blen]));
				break;
			case DCPP_FF_LOCK:
				memcpy (&(cout->buffer[blen]), DCPP_FF_LOCK_DT,
						DCPP_FF_LOCK_SZ);
				blen += DCPP_FF_LOCK_SZ;
				break;
			case DCPP_FF_SUPS:
				supst = va_arg (va, struct dcpp_supports_t*);
				if (!supst)
					break;
				/* если список поддерживаемых расширений пустой, то по адресу
				 * *(line + offset + DCPP_FF_SUPS_SZ) ничего не будет записано
				 * иначе предполагается, что длина буфера была расчитана ранее
				 */
				tlen = dcpp_i2sups (supst,
						&(cout->buffer[blen + DCPP_FF_SUPS_SZ]),
						cony->out.size - cony->out.last - DCPP_FF_SUPS_SZ -
							blen - sizeof (struct _s_cout_t));
				if (tlen)
				{
					/* если был сгенерирован и скопирован список расширений,
					 * то дописываем "заголовок" сообщения
					 */
					memcpy (&(cout->buffer[blen]), DCPP_FF_SUPS_DT,
							DCPP_FF_SUPS_SZ);
					/* и обновляем offset */
					blen += (DCPP_FF_SUPS_SZ + tlen);
				}
				break;
		};
	}
	va_end (va);
	cout->buffer[blen ++] = '|';
	cout->buffer[blen] = '\0';
	/* finalize calculate */
	cout->size = blen;
	cony->out.fill = cony->out.last + cout->size + sizeof (struct _s_cout_t);
}

/* add buffer to queue on write */
static void
msg_commit (EV_P_ struct _s_cony_t *cony)
{
	ev_io *eve;
	if (cony->out.fill)
	{
		eve = &(cony->evio);
		ev_io_stop (EV_A_ eve);
		ev_io_set (eve, cony->fd, eve->events | EV_WRITE);
		ev_io_start (EV_A_ eve);
	}
}

static void
output_cb_rem_ (struct _s_cony_t *cony, struct _s_cout_t *cout)
{
	size_t tlen;
	if (cony->out.last)
	{
		tlen = sizeof (struct _s_cout_t) + cout->size;
		memmove (cony->out.line, cony->out.line + tlen,
				cony->out.fill - tlen);
		cony->out.last -= tlen;
		cony->out.fill -= tlen;
	}
	else
	{
		memset (cony->out.line, 0, sizeof (struct _s_cout_t));
		cony->out.fill = 0;
	}
}

static inline size_t
output_cb (EV_P_ ev_io *ev, struct _s_cony_t *cony, char *output,
		size_t len)
{
	struct _s_cout_t *cout = NULL;
	struct _s_cout_file_t *cfile = NULL;
	size_t tlen = 0u;
	ssize_t lv = -1;
	if (!len || !output)
		return 0;
	if (cony->out.fill >= sizeof (struct _s_cout_t))
	{
		cout = (struct _s_cout_t*)cony->out.line;
		switch (cout->type)
		{
			case _S_T_STRING:
				if (cout->size > len)
					tlen = len;
				else
					tlen = cout->size;
				memcpy (output, cout->buffer, tlen);
				if (tlen == cout->size)
					/* complete remove */
					output_cb_rem_ (cony, cout);
				else
				{
					/* part remove */
					cony->out.fill -= tlen;
					memmove (cout->buffer, &(cout->buffer[tlen]),
							cony->out.fill - sizeof (struct _s_cout_t));
				}
				break;
			case _S_T_FILE:
				/* send file */
				cfile = (struct _s_cout_file_t*)cout->buffer;
				if (cfile->fd != -1 && cfile->offset < cfile->length)
				{
					tlen = cfile->length - cfile->offset;
					if (tlen > len)
						tlen = len;
					lv = read (cfile->fd, output, tlen);
					if (lv > 0)
					{
						tlen = lv;
						cfile->offset += tlen;
					}
					else
						tlen = 0;
				}
				if (cfile->fd == -1 || cfile->offset >= cfile->length || !tlen)
				{
					/* remove from queue */
					if (cfile->fd != -1)
					{
						close (cfile->fd);
						cfile->fd = -1;
					}
					/* update queue */
					output_cb_rem_ (cony, cout);
				}
				break;
			default:
				/* remove node from line */
				output_cb_rem_ (cony, cout);
				/* or except? */
				break;
		}
	}
	return tlen;
}

static inline void
clipair_wr_cb (EV_P_ ev_io *ev, struct S5tun_t *self, int dir)
{
	/* send data to pairs */
	ssize_t lv;
	/* check output buffer */
	if (self->_s[dir].out.fill < LINE_SZ)
	{
		self->_s[dir].out.fill += output_cb (EV_A_ ev, &(self->_s[dir]),
				(self->_s[dir].out.buf + self->_s[dir].out.fill),
				LINE_SZ - self->_s[dir].out.fill);
	}
	else
		self->errcc ++;
	if (self->_s[dir].out.fill)
	{
		/* send buffer */
		lv = write (self->_s[dir].fd, self->_s[dir].out.buf, self->_s[dir].out.fill);
		if (lv != self->_s[dir].out.fill)
		{
			/* copy not-writed data */
			if (lv > 0)
				memmove (self->_s[dir].out.buf, (self->_s[dir].out.buf + lv),
						self->_s[dir].out.fill - lv);
		}
	}
	/* free write event, if buffer == zero */
	/* TODO: generate exception, remove from event list */
}

static inline void
clipair_DC_rd_cb (EV_P_ ev_io *ev, struct S5tun_t *self)
{
	/* get s2c-traffic from server */
	/* capture messages $ConnectToMe, $SR, $Search, $RevConnectToMe  */
}

/* connections */
static int
_S5_connect_DC_v4 (struct sockaddr *sa, size_t sasz)
{
	int sock;
	sock = socket (PF_INET, SOCK_STREAM, 0);
	if (sock != -1)
	{
		if (connect (sock, sa, sasz) == -1)
		{
			close (sock);
			sock = -1;
		}
	}
	return sock;
}

static int
_S5_connect_DC_v6 (struct sockaddr *sa, size_t sasz)
{
	int sock;
	sock = socket (PF_INET6, SOCK_STREAM, 0);
	if (sock != -1)
	{
		if (connect (sock, sa, sasz) == -1)
		{
			close (sock);
			sock = -1;
		}
	}
	return -1;
}

static inline int
S5_connect_DC (EV_P_ ev_io *ev, struct S5tun_t *self)
{
	ev_io *eve;
	struct addrinfo hint; /* for matching */
	struct addrinfo *air; /* root address info (for freeaddrinfo ()) */
	struct addrinfo *aic; /* current address info */
	char port[6];
	int sock;
	union
	{
		struct sockaddr *_;
		struct sockaddr_in *in;
		struct sockaddr_in6 *in6;
	} _s;
	if (self->state < STATE_DC)
		return -1;
	if (self->u.sto->atype == S5_AT_DN)
	{
		memset (&hint, 0, sizeof (struct addrinfo));
		hint.ai_socktype = SOCK_STREAM;
		snprintf (port, 6, "%u", self->u.sto->port.p16);
		sock = -1;
		if (!getaddrinfo (self->u.sto->addr.dn, port, &hint, &air))
		{
			for (aic = air; aic; aic = aic->ai_next)
			{
				if (aic->ai_family == AF_INET)
					sock = _S5_connect_DC_v4 (aic->ai_addr,
							sizeof (struct sockaddr_in));
				else
				if (aic->ai_family == AF_INET6)
					sock = _S5_connect_DC_v6 (aic->ai_addr,
							sizeof (struct sockaddr_in6));
				if (sock != -1)
					break;
			}
			freeaddrinfo (air);
			return sock;
		}
	}
	else
	if (self->u.sto->atype == S5_AT_IP)
	{
		_s._ = NULL;
		if (self->u.sto->addr_len == 4)
		{
			/* IPv4 */
			_s._ = calloc (1, sizeof (struct sockaddr_in));
			if (!_s._)
			return -1;
		_s.in->sin_family = PF_INET;
		_s.in->sin_addr.s_addr = self->u.sto->addr.ipv4;
		_s.in->sin_port = self->u.sto->port.p16;
		sock = _S5_connect_DC_v4 (_s._, sizeof (struct sockaddr_in));
		}
		else
		if (self->u.sto->addr_len == 16)
		{
			/* IPv6 */
			_s._ = calloc (1, sizeof (struct sockaddr_in6));
			if (!_s._)
				return -1;
			_s.in6->sin6_family = PF_INET6;
			memcpy (&(_s.in6->sin6_addr), self->u.sto->addr.ip, 16);
			_s.in6->sin6_port = self->u.sto->port.p16;
			sock = _S5_connect_DC_v6 (_s._, sizeof (struct sockaddr_in6));
		}
		if (_s._)
			free (_s._);
		eve = &(self->_s[0].evio);
		ev_io_init (eve, clipair_dispatch_cb, sock, EV_READ);
		ev_io_start (EV_A_ eve);
		/* update event list */
		return sock;
	}
	return -1;
}

static inline size_t
S5_input_cb (EV_P_ ev_io *ev, struct S5tun_t *self, char *input, size_t len)
{
	size_t _c = 0u;
	/* - ' */
	if (self->state == STATE_S5)
	{
		/* check struct size */
		if (!(self->u_sz < sizeof (struct S5_store_t)))
		{
			if (self->u.ptr)
				free (self->u.ptr);
			self->u.ptr = malloc (sizeof (struct S5_store_t));
			if (self->u.ptr)
				self->u_sz = sizeof (struct S5_store_t);
			else
			{
				/* memory fail */
				self->u_sz = 0u;
				self->errcc ++;
				return 0u;
			}
		}
		/* remove garbage from struct */
		memset (self->u.ptr, 0, sizeof (struct S5_store_t));
	}
	/* */
	for (_c = 0u; self->state < STATE_END && _c < len; _c ++)
	{
		switch (self->state)
		{
			case STATE_S5:
			case STATE_S5_W0:
				/* match protocol version */
				if (input[_c] != 0x05)
					self->state = STATE_END;
				else
					self->state ++;
				break;
			case STATE_S5_WR:
				/* check RSV (reserved) octet */
				if (input[_c] != 0x00)
					self->state = STATE_END;
				else
					self->state ++;
				break;
			case STATE_S5_H1:
				/* count of auth methods */
				self->u.sto->no = input[len];
				self->state ++;
				break;
			case STATE_S5_H2:
				/* check auth types */
				if (self->u.sto->no)
					self->u.sto->no --;
				if (input[_c] == 0x00)
				{
					/* send OK: b'\0x05\0x00' */
					msg_format_raw (&(self->_s[0]), 2, "\x05\x00");
					self->u.sto->state = S5_ST_AUTH;
				}
				if (!self->u.sto->no)
				{
					self->state ++;
					if (self->u.sto->state != S5_ST_AUTH)
					{
						/* send error b'\0x05\0xFF' */
						msg_format_raw (&(self->_s[0]), 2, "\x05\xFF");
						self->state = STATE_END;
					}
				}
				break;
				if (input[_c] != 0x05)
					self->state = STATE_END;
				else
					self->state ++;
				break;
			case STATE_S5_W1:
				/* type of socket */
				if (input[_c] != 0x01) /* 0x01 = CONNECT */
					self->state = STATE_END;
				else
					self->state ++;
				break;
			case STATE_S5_W2:
				/* type of address */
				if (self->u.sto->atype == S5_AT_DN)
				{
					self->u.sto->addr_len = input[_c];
					self->state ++;
				}
				else
				{
					switch (input[_c])
					{
						case 0x01:
							self->u.sto->atype = S5_AT_IP;
							self->u.sto->addr_len = 4;
							self->state ++;
							break;
						case 0x04:
							self->u.sto->atype = S5_AT_IP;
							self->u.sto->addr_len = 16;
							self->state ++;
							break;
						case 0x03:
							self->u.sto->atype = S5_AT_DN;
							break;
						default:
							self->state = STATE_END;
					}
				}
				break;
			case STATE_S5_W3:
				/* fill address */
				switch (self->u.sto->atype)
				{
					case S5_AT_IP:
						self->u.sto->addr.ip[self->u.sto->no] = input[_c];
						break;
					case S5_AT_DN:
						self->u.sto->addr.dn[self->u.sto->no] = input[_c];
						break;
				};
				self->u.sto->no ++;
				/* if filling complete, then go to next stage */
				if (self->u.sto->no == self->u.sto->addr_len)
				{
					self->u.sto->addr.dn[self->u.sto->no] = '\0';
					self->state ++;
					/* update len info */
					self->u.sto->no = 0;
				}
				else
				if (self->u.sto->no > self->u.sto->addr_len)
					self->state = STATE_END;
				break;
			case STATE_S5_W4:
				/* fill port */
				self->u.sto->port.p8[self->u.sto->no] = input[_c];
				self->u.sto->no ++;
				/* end parse */
				if (self->u.sto->no == 2)
				{
					/* create connection to next DC-node */
					self->_s[1].fd = S5_connect_DC (EV_A_ ev, self);
					if (self->_s[1].fd != -1)
					{
						/* send OK (00 - Success)*/
						msg_format_raw (&(self->_s[0]), 3, "\x05\x00\x00");
						/* set state to STATE_DC */
						self->state ++;
					}
					else
					{
						/* send error (01 - SOCKS-server error) */
						msg_format_raw (&(self->_s[0]), 3, "\x05\x01\x00");
						self->state = STATE_END;
					}
					/* complite response packet */
					switch (self->u.sto->atype)
					{
						case S5_AT_IP:
							switch (self->u.sto->addr_len)
							{
								case 4:
									/* IPv4 */
									msg_format_raw (&(self->_s[0]),
											1, "\01",
											4, self->u.sto->addr.ip);
									break;
								case 16:
									/* IPv6 */
									msg_format_raw (&(self->_s[0]),
											1, "\04",
											16, self->u.sto->addr.ip);
									break;
							}
							break;
						case S5_AT_DN:
							msg_format_raw (&(self->_s[0]),
									1, "\x03",
									1, self->u.sto->addr_len,
									self->u.sto->addr_len,
									self->u.sto->addr.dn);
							break;
					} /* switch atype */
				}
				break;
		}
	}
	msg_commit (EV_A_ &(self->_s[0]));
	/* возвращает количество пройденных ("поглощённых") символов  */
	return _c;
}

static inline void
clipair_S5_rd_cb (EV_P_ ev_io *ev, struct S5tun_t *self)
{
	ssize_t lv;
	size_t off;
	lv = read (self->_s[0].fd, self->_s[0].in.buf, LINE_SZ);
	if (lv < 1)
	{
		/* TODO: set off state for current struct and close all connections */
		self->_s[0].in.inbuf = 0u;
		self->_s[0].in.buf[0] = '\0';
	}
	else
	{
		self->_s[0].in.inbuf = (size_t)lv;
		self->_s[0].in.buf[lv] = '\0';
	}
	off = 0;
	while (off != self->_s[0].in.inbuf && self->errcc < ERRCC_MAX
			&& self->state != STATE_END)
	{
		/* parse input */
		if (self->state < STATE_DC)
		{
			/* STATE_S5 */
			off = S5_input_cb (EV_A_ ev, self, &(self->_s[0].in.buf[off]),
					self->_s[0].in.inbuf - off);
		}
		else
		{
			/* STATE_DC */
			/* TODO */
		}
	}
	if (self->errcc >= ERRCC_MAX)
	{
		if (self->state != STATE_END)
			self->state = STATE_END;
		/* */
		/* TODO: drop struct */
	}
	/* rewrite messages with keys: $MyINFO */
}

static void
clipair_dispatch_cb (EV_P_ ev_io *ev, int revents)
{
	struct S5srv_t *root;
	struct S5tun_t *self;
	root = ev_userdata (EV_A);
	if (!root)
		return;
	self = S5_get_tun (root, ev->fd);
	if (!self)
	{
		/* TODO? exception try to remove from event list */
		return;
	}
	if (ev->fd == self->_s[0].fd)
	{
		/* execute code */
		if (revents & EV_READ)
			clipair_S5_rd_cb (EV_A_ ev, self);
		if (revents & EV_WRITE)
			clipair_wr_cb (EV_A_ ev, self, 0);
	}
	else
	if (ev->fd == self->_s[1].fd)
	{
		if (revents & EV_READ)
			clipair_DC_rd_cb (EV_A_ ev, self);
		if (revents & EV_WRITE)
			clipair_wr_cb (EV_A_ ev, self, 1);
	}
	else
	{
		/* TODO: remove from event list */
	}
}

static void
S5_server_cb (EV_P_ ev_io *ev, int revents)
{
	struct sockaddr_in sin;
	int lv;
	struct S5srv_t *root;
	struct S5tun_t *tun;
	ev_io *eve;
	socklen_t sin_sz;
	/* get root node from ev_loop */
	root = ev_userdata (EV_A);
	/* accept socket */
	sin_sz = sizeof (struct sockaddr_in);
	lv = accept (root->fd, (struct sockaddr*)&sin, &sin_sz);
	if (lv == -1)
	{
		perror ("accept");
		return;
	}
	/* create new node */
	tun = S5_get_tun (root, -1);
	if (!tun)
	{
		close (lv);
		return;
	}
	/* update state && s5-fd */
	tun->state ++;
	tun->_s[0].fd = lv;
	/* create event's bindings */
	eve = &(tun->_s[0].evio);
	ev_io_init (eve, clipair_dispatch_cb, tun->_s[0].fd, EV_READ);
	ev_io_start (EV_A_ eve);
}

int
main (int argc, char *argv[])
{
	struct sockaddr_in sin;
	struct S5srv_t root;
	int lv;
	ev_io *eve;
#if EV_MULTIPLICITY
	struct ev_loop *loop = EV_DEFAULT;
	if (!loop)
	{
		fprintf (stderr, "can't init libev\n");
		return EXIT_FAILURE;
	}
#endif
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr ("0.0.0.0");
	sin.sin_port = htons ((unsigned short)1080);
	fprintf (stderr, "socket () S5s\n");
	root.fd = socket (AF_INET, SOCK_STREAM, 0);
	fprintf (stderr, "bind () S5s\n");
	lv = bind (root.fd, (struct sockaddr*)&sin, sizeof (struct sockaddr_in));
	if (lv == -1)
	{
		perror ("bind");
		return EXIT_FAILURE;
	}
	fprintf (stderr, "listen () S5s\n");
	lv = listen (root.fd, 1);
	if (lv == -1)
	{
		perror ("listen");
		return EXIT_FAILURE;
	}
	fprintf (stderr, "ev_io_init () S5s\n");
	eve = &(root.evio);
	ev_io_init (eve, S5_server_cb, root.fd, EV_READ);
	ev_io_start (EV_A_ eve);
	/* put *root to current ev_loop */
	ev_set_userdata (EV_A_ &root);
	fprintf (stderr, "RUN libev\n");
	ev_run (EV_A_ 0);
	fprintf (stderr, "DESTROY\n");
	/* TODO */
	return EXIT_SUCCESS;
}


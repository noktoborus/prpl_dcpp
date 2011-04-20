/* vim: ft=c ff=unix fenc=utf-8
 * file: dcppd_debug.c
 */

#ifndef DEBUG
 /* */
#else
static void*
_ev_alloc (void *ptr, long int sz)
{
	static int cc = 0;
	void *p = NULL;
	if (sz == 0)
	{
		if (ptr)
		{
			cc --;
			free (ptr);
			fprintf (stderr, "## ev mem free (ptr=%p) -> count allocs=%d\n",
					ptr, cc);
		}
	}
	else
	if (ptr == NULL)
	{
		cc ++;
		p = malloc (sz);
		fprintf (stderr, "## ev mem alloc (sz=%ld) -> new ptr=%p, "\
					"count allocs=%d\n", sz, p, cc);
	}
	else
	{
		p = realloc (ptr, sz);
		fprintf (stderr, "## ev mem realloc (old ptr=%p, sz=%ld) "\
					"-> new ptr=%p, count allocs=%d\n",
				ptr, sz, p, cc);
	}
	return p;
}

static inline ssize_t
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

static inline ssize_t
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

static void*
malloc_ (size_t size, char const *file, int line, char const *func)
{
	void *r;
	r = malloc (size);
	fprintf (stderr, "%s:%d.%s () -> malloc (size=%u) -> %p\n",
			file, line, func, size, r);
	return r;
}

static void*
calloc_ (size_t nmemb, size_t size,
		char const *file, int line, char const *func)
{
	void *r;
	r = calloc (nmemb, size);
	fprintf (stderr, "%s:%d.%s () -> calloc (nmemb=%u, size=%u) -> %p\n",
			file, line, func, nmemb, size, r);
	return r;
}

static void*
realloc_ (void *ptr, size_t size, char const *file, int line, char const *func)
{
	void *r;
	fprintf (stderr, "%s:%d.%s () -> realloc (ptr=%p, size=%u) -> ",
			file, line, func, ptr, size);
	r = realloc (ptr, size);
	fprintf (stderr, "%p\n", r);
	return r;
}

static void
free_ (void *ptr, char const *file, int line, char const *func)
{
	fprintf (stderr, "%s:%d.%s () -> free (ptr=%p)\n", file, line, func, ptr);
	free (ptr);
}

#define read(w, x, y) read_ (w, x, y, __FILE__, __LINE__, __func__)
#define write(w, x, y) write_ (w, x, y, __FILE__, __LINE__, __func__)

#define malloc(x)		malloc_ (x, __FILE__, __LINE__, __func__)
#define calloc(x, y)	calloc_ (x, y, __FILE__, __LINE__, __func__)
#define realloc(x, y)	realloc_ (x, y, __FILE__, __LINE__, __func__)
#define free(x)			free_ (x, __FILE__, __LINE__, __func__)
#endif


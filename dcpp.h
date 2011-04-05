/* vim: ft=c ff=unix fenc=utf-8
 * file: dcpp.h
 */
#ifndef _DCPP_1301826924_H_
#define _DCPP_1301826924_H_

#define DCPP_INPUT_SZ 1024
#define DCPP_LINE_SZ 16384
struct dcpp_t
{
	char inbuf[DCPP_INPUT_SZ + 1];
	char *line;
	size_t line_sz;
	size_t offset;
	int fd;
};

#endif /* _DCPP_1301826924_H_ */


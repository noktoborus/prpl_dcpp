/* vim: ft=c ff=unix fenc=utf-8
 * file: dcpp.h
 */
#ifndef _DCPP_1301826924_H_
#define _DCPP_1301826924_H_

#define DCPP_INPUT_SZ 1024
#define DCPP_LINE_SZ 16384
struct dcpp_t
{
	char inbuf[DCPP_INPUT_SZ];
	char line[DCPP_LINE_SZ];
	size_t offset;
};

#endif /* _DCPP_1301826924_H_ */


/*
 * Copyright(c) 2017-2018 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

//#include <curl_setup.h>

#include <curl/curl.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fuzzer.h"

// #define VERBOSE
#ifdef VERBOSE
  #define TRACEF(...) fprintf(stderr, __VA_ARGS__)
#else
  #define TRACEF(...)
#endif

#define countof(a) (sizeof(a)/sizeof(*(a)))

static int (*libc_socket)(int domain, int type, int protocol);
static int (*libc_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
static int (*libc_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*libc_recvfrom)(int sockfd, void *buf, size_t count, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t count, int flags);
static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t count, int flags, const struct sockaddr *src_addr, socklen_t addrlen);
static int (*libc_getsockopt)(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

static int fd[2];
static int nconnects;

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	TRACEF("%s: %d\n", __func__, sockfd);

	if (nconnects < countof(fd)) {
		fd[nconnects++] = sockfd;
		errno = EAGAIN;
		return -1;
	}

	return libc_connect(sockfd, addr, addrlen);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int ret = 0;

	TRACEF("%s: %lu %d %d\n", __func__, nfds, fd[0], fd[1]);

	for (int it = 0; it < nfds; it++) {
		TRACEF("  %d\n", fds[it].fd);
		if ((fd[0] && fds[it].fd == fd[0]) || (fd[1] && fds[it].fd == fd[1])) {
			if (fds[it].events | POLLIN)
				fds[it].revents = POLLIN|POLLWRNORM;
			if (fds[it].events | POLLOUT)
				fds[it].revents = POLLOUT|POLLRDNORM;

			errno = 0;
			ret++;
		}
	}

	TRACEF("%s: ret %d\n", __func__, ret);
	return ret;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	if (optname == SO_ERROR) {
		TRACEF("%s: %d\n", __func__, sockfd);

		if ((fd[0] && sockfd == fd[0]) || (fd[1] && sockfd == fd[1])) {
			*((int *)optval)=0;
			TRACEF("%s: ret 0\n", __func__);
			return 0;
		}
	}

	return libc_getsockopt(sockfd, level, optname, optval, optlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	TRACEF("%s: %d %d %d\n", __func__, sockfd, fd[0], fd[1]);

	if ((fd[0] && sockfd == fd[0]) || (fd[1] && sockfd == fd[1])) {
		memset(addr, 0 , sizeof(struct sockaddr_in));

		struct sockaddr_in *in = addr;
		in->sin_family = AF_INET;
		in->sin_port = 21;
		inet_aton("127.0.0.1", &in->sin_addr);
		// in->sin_addr.s_addr = 0x71717171;

		*addrlen = sizeof(struct sockaddr_in);
		return 0;
	}

	return -1;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	TRACEF("%s: %d %d %d\n", __func__, sockfd, fd[0], fd[1]);

	if ((fd[0] && sockfd == fd[0]) || (fd[1] && sockfd == fd[1])) {
		memset(addr, 0 , sizeof(struct sockaddr_in));

		struct sockaddr_in *in = addr;
		in->sin_family = AF_INET;
		in->sin_port = 12345;
		inet_aton("127.0.0.1", &in->sin_addr);
		// in->sin_addr.s_addr = 0x70707070;

		*addrlen = sizeof(struct sockaddr_in);
		return 0;
	}

	return -1;
}

static const char *fuzzData;
static size_t fuzzDataLen;

static const char *response[] = {
	"220 GNU alpha FTP server ready.\r\n",
	"230 Login successful.\r\n",
	"257 \"/\"\r\n",
//	"250 Directory successfully changed.\r\n",
	"229 Entering Extended Passive Mode (|||34347|).\r\n",
	"200 Switching to ASCII mode.\r\n",
	"150 Here comes the directory listing.\r\n",
	"226 Directory send OK.\r\n",
	"221 Goodbye.\r\n",
};
static int n1;

ssize_t recvfrom(int sockfd, void *buf, size_t count, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	TRACEF("%s: %d %d\n", __func__, sockfd, fd[0]);

	if (fd[0] && fd[0] == sockfd) {
		TRACEF("%s: %s\n", __func__, response[n1]);
		return snprintf(buf, count, "%s", response[n1++]);
	}
	else if (fd[1] && fd[1] == sockfd) {
		size_t n = fuzzDataLen < count ? fuzzDataLen : count;
		TRACEF("%s: got %zu bytes\n", __func__, n);
		memcpy(buf, fuzzData, n);
		fuzzDataLen -= n;
		fuzzData += n;
		return fuzzDataLen;
	}

	return libc_recvfrom(sockfd, buf, count, flags, src_addr, addrlen);
}

ssize_t recv(int sockfd, void *buf, size_t count, int flags)
{
	TRACEF("%s(%d, buf, %zu)\n", __func__, sockfd, count);

	if (fd[0] && fd[0] == sockfd) {
		TRACEF("%s: %s\n", __func__, response[n1]);
		return snprintf(buf, count, "%s", response[n1++]);
	}
	else if (fd[1] && fd[1] == sockfd) {
		TRACEF("  fuzzDataLen=%zu\n", fuzzDataLen);
		size_t n = fuzzDataLen < count ? fuzzDataLen : count;
		memcpy(buf, fuzzData, n);
		fuzzDataLen -= n;
		fuzzData += n;
		TRACEF("  ret %zu (fuzzDataLen=%zu)\n", n, fuzzDataLen);
		return n;
	}

	return libc_recv(sockfd, buf, count, flags);
}

ssize_t sendto(int sockfd, const void *buf, size_t count, int flags, const struct sockaddr *src_addr, socklen_t addrlen)
{
	if (fd[0] && fd[0] == sockfd) {
		return count;
	}

	return libc_sendto(sockfd, buf, count, flags, src_addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t count, int flags)
{
	if (fd[0] && fd[0] == sockfd) {
		return count;
	}

	return libc_send(sockfd, buf, count, flags);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 16384) // same as max_len = 10000 in .options file
		return 0;

	fuzzData = (const char *) data;
	fuzzDataLen = size;
	n1 = nconnects = 0;
	fd[0]=fd[1]=0;

	libc_socket = dlsym(RTLD_NEXT, "socket");
	libc_poll = dlsym(RTLD_NEXT, "poll");
	libc_connect = dlsym(RTLD_NEXT, "connect");
	libc_recv = dlsym(RTLD_NEXT, "recv");
	libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	libc_send = dlsym(RTLD_NEXT, "send");
	libc_sendto = dlsym(RTLD_NEXT, "sendto");
	libc_getsockopt = dlsym(RTLD_NEXT, "getsockopt");

	struct Curl_easy *easy = curl_easy_init();

#ifdef VERBOSE
	curl_easy_setopt(easy, CURLOPT_VERBOSE, 1);
#endif
	curl_easy_setopt(easy, CURLOPT_URL, "ftp://127.0.0.1/fe*.txt");
	curl_easy_setopt(easy, CURLOPT_WILDCARDMATCH, 1);

	curl_easy_perform(easy);

	curl_easy_cleanup(easy);
	TRACEF("%s: ####### done ######\n", __func__);

	return 0;
}

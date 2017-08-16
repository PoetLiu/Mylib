#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "mylib.h"

int connect_timeout(int fd, const struct sockaddr * dest, int dlen,
		struct timeval timeout) {
	int flags, ret, error, len = sizeof(int);
	fd_set fds;

	// 设为非阻塞模式
	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		DEBUG("fcntl get file_flags faild\n");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		DEBUG("fcntl set file_flags faild\n");
		return -1;
	}

	if (connect(fd, dest, dlen) < 0) {
		// 设为阻塞模式
		if (fcntl(fd, F_SETFL, flags) < 0) {
			DEBUG("fcntl set file_flags faild\n");
			return -1;
		}

		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		ret = select(fd + 1, NULL, &fds, NULL, &timeout);
		if (ret == -1) {
			DEBUG("select error\n");
			return -1;
		} else if (ret == 0) {
			DEBUG("socket connect timeout\n");
			return -1;
		} else {
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *) &len);
			if (error == 0) {
				if (FD_ISSET(fd, &fds)) {
					DEBUG("socket %d connect ok\n", fd);
					return fd;
				}
			} else {
				DEBUG("socket connect error:(%d:%s)\n", error, strerror(error));
				return -1;
			}

		}
	} else {
		// 设为阻塞模式
		if (fcntl(fd, F_SETFL, flags) < 0) {
			DEBUG("fcntl set file_flags faild\n");
			return -1;
		}
		DEBUG("socket %d connect ok\n", fd);
		return fd;
	}
}

int get_socket(int reuse, int prot) {
	int fd;

	if (prot)
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	else
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (fd < 0) {
		DEBUG("socket faild\n");
		return -1;
	}
	if (reuse
			&& setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse,
					sizeof(reuse)) == -1) {
		DEBUG("set SO_REUSEADDR error\n");
		close(fd);
		return -1;
	}
	return fd;
}

// 复用端口和地址连接到指定的地址
// old_sk 已经被绑定到了old_port上
// 上面的bind必须将socket参数设置为SO_REUSEADDR
int connect_2_address_reuse_old(const struct address_info *dest, int old_sk,
		int *old_port, struct timeval timeout, int prot) {
	int fd, len;
	struct sockaddr_in dest_addr, addr, addr_old;

	len = sizeof(struct sockaddr_in);
	if (getsockname(old_sk, (struct sockaddr *) &addr_old, &len) != 0) {
		DEBUG("getsockname faild\n");
		return -1;
	}
	*old_port = ntohs(addr_old.sin_port);

	if ((fd = get_socket(1, prot)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = addr_old.sin_port;
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DEBUG("bind failed (%d %s)\n", errno, strerror(errno));
		goto err_r;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(dest->port);
	dest_addr.sin_addr.s_addr = inet_addr(dest->ip);

	DEBUG("reuse port:%d sock:%d connecting to %s:%d \n", *old_port, fd,
			dest->ip, dest->port);
	if (prot) {
		if (connect_timeout(fd, (struct sockaddr *) &dest_addr,
				sizeof(dest_addr), timeout) < 0)
			goto err_r;
		else
			return fd;
	} else {
		if (connect(fd, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0)
			DEBUG("udp connect error (%d %s)\n", errno, strerror(errno));
		return fd;
	}

	err_r: close(fd);
	return -1;
}

int connect_2_address(const struct address_info *dest, struct timeval timeout,
		int reuse, int prot) {
	int fd;
	struct sockaddr_in dest_addr;

	if ((fd = get_socket(reuse, prot)) < 0)
		return -1;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(dest->port);
	dest_addr.sin_addr.s_addr = inet_addr(dest->ip);

	DEBUG("connecting to %s:%d \n", dest->ip, dest->port);
	if (prot) {
		if (connect_timeout(fd, (struct sockaddr *) &dest_addr,
				sizeof(dest_addr), timeout) < 0) {
			goto err_r;
		} else {
			DEBUG("tcp socket %d connect ok\n", fd);
			return fd;
		}
	} else {
		if (connect(fd, (struct sockaddr *) &dest_addr, sizeof(dest_addr))
				< 0) {
			DEBUG("udp connect error (%d %s)\n", errno, strerror(errno));
			goto err_r;
		} else {
			return fd;
		}
	}

	err_r: close(fd);
	return -1;
}

// 首先从fd中读取sizeof(int)作为消息长度len
// 再从fd中读取len个字节
// 注意：返回的json指向的空间必须由调用者释放
// timeout为阻塞read的时间长度
cJSON * read_json_from_fd(int fd, struct timeval timeout, int is_tcp) {
	cJSON *json;

	if (fd < 0 || is_tcp < 0) {
		DEBUG("error param\n");
		return NULL;
	}

	if (is_tcp) {
		char *r_data;
		int r_len, len, len_hl;
		if (read_str_from_fd(fd, (char *) &len, sizeof(int), timeout)
				!= sizeof(int)) {
			DEBUG("read json head error\n");
			return NULL;
		}
		len_hl = ntohl(len);
		DEBUG("tcp get json head:%d\n", len_hl);

		r_data = (char *) malloc(len_hl + 1);
		if (r_data == NULL) {
			DEBUG("malloc error\n");
			return NULL;
		}
		memset(r_data, 0, len_hl + 1);

		r_len = read_str_from_fd(fd, r_data, len_hl, timeout);
		if (r_len != len_hl) {
			DEBUG("read json msg error\n");
			free(r_data);
			return NULL;
		}
		r_data[r_len] = '\0';
		DEBUG("get data from fd:%d len:%d data:%s\n", fd, r_len, r_data);

		json = cJSON_Parse(r_data);
		if (!json) {
			DEBUG("cJSON_Parse error\n");
			free(r_data);
			return NULL;
		}
		free(r_data);
		return json;
	} else {
		char r_data[65535];
		int r_len, t_len;
		r_len = read_str_from_fd(fd, r_data, 65535, timeout);
		t_len = ntohl(*(int *) r_data) + sizeof(int);
		if (r_len != t_len) {
			DEBUG("read json msg error\n");
			return NULL;
		}
		r_data[r_len] = '\0';
		DEBUG("get data from fd:%d len:%d data:%s\n", fd, r_len,
				r_data + sizeof(int));
		json = cJSON_Parse(r_data + sizeof(int));
		if (!json) {
			DEBUG("cJSON_Parse error\n");
			return NULL;
		}
		return json;
	}
}

// 向fd中写入json指向的数据
// 这里数据包的前sizeof(int)个字节为后面数据的长度
// 这里将这个长度值和后面的数据打包到一起， 一并写出去
// 如果分开成两次发送，将会出错
// json指向的空间由调用者释放
int write_json_to_fd(int fd, cJSON *json, struct timeval timeout) {
	char *msg_data;
	int len, w_len;

	if (fd < 0 || json == NULL) {
		DEBUG("error param\n");
		return -1;
	}

	// 准备数据
	msg_data = cJSON_Print(json);
	if (msg_data == NULL) {
		DEBUG("cJSON_Print error");
		return -1;
	}
	len = strlen(msg_data);

	// 发送数据
	w_len = write_str_2_fd(fd, (char *) msg_data, len, timeout);
	if (w_len != len) {
		DEBUG("write error (%d %s)\n", errno, strerror(errno));
		free(msg_data);
		return -1;
	}
	DEBUG("writing data to fd:%d ok\n", fd);

	free(msg_data);
	return 0;
}

int write_str_2_fd(int fd, const char *buf, int len, struct timeval timeout) {
	int ret;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (fd < 0 || buf == NULL || len < 0) {
		DEBUG("error param\n");
		return -1;
	}

	if ((ret = select(fd + 1, NULL, &fds, NULL, &timeout)) < 0) {
		return -1;
	}

	if (FD_ISSET(fd, &fds)) {
		if (write(fd, buf, len) > 0) {
			DEBUG("write message to fd:%d %d\n", fd, len);
			return len;
		} else {
			DEBUG("write message to fd:%d error:%d %s\n", fd, errno,
					strerror(errno));
			return -1;
		}
	} else {
		DEBUG("write fd:%d timeout\n", fd);
		return -1;
	}
}

int read_str_from_fd(int fd, char *buf, int len, struct timeval timeout) {
	int ret, rlen = 0, elen = sizeof(int), error;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (fd < 0 || buf == NULL || len < 0) {
		DEBUG("error param\n");
		return -1;
	}

	if ((ret = select(fd + 1, &fds, NULL, NULL, &timeout)) < 0) {
		DEBUG("select error\n");
		return -1;
	}

	if (FD_ISSET(fd, &fds)) {
		if ((rlen = read(fd, buf, len)) > 0) {
			DEBUG("read message from fd:%d len:%d\n", fd, rlen);
			return rlen;
		} else {
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *) &elen);
			DEBUG("read message from fd:%d error:%d %s\n", fd, error,
					strerror(error));
			return -1;
		}
	} else {
		DEBUG("read fd:%d timeout\n", fd);
		return -1;
	}
}

int socket_init(int port, int prot) {
	int sk;
	struct sockaddr_in addr;
	int reuse = 1;

	if ((sk = get_socket(1, prot)) < 0)
		return -1;

	//bind
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DEBUG("bind failed\n");
		close(sk);
		return -1;
	}

	//listen
	if (prot) {
		if (listen(sk, 10) < 0) {
			DEBUG("listen failed\n");
			close(sk);
			return -1;
		}
	}

	DEBUG("socket=%d\n", sk);
	return sk;
}

int wait_client_conn(int port, struct timeval timeout_r, int prot) {
	fd_set fds;
	int len, ret, rlen, new_fd, fd;
	struct sockaddr_in addr;
	char buff[256];

	if (port < 0 || prot < 0) {
		DEBUG("error param\n");
		return -1;
	}

	fd = socket_init(port, prot);
	len = sizeof(struct sockaddr);
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if ((ret = select(fd + 1, &fds, NULL, NULL, &timeout_r)) < 0) {
		DEBUG("select error\n");
		goto err_r;
	}

	if (FD_ISSET(fd, &fds)) {
		if (prot) {
			new_fd = accept(fd, (struct sockaddr *) &addr, &len);
			if (new_fd < 0) {
				DEBUG("accept failed\n");
				goto err_r;
			} else {
				DEBUG("got a call from %s:%d\n", inet_ntoa(addr.sin_addr),
						ntohs(addr.sin_port));
				close(fd);
				return new_fd;
			}
		} else {
			rlen = recvfrom(fd, buff, sizeof(buff), 0,
					(struct sockaddr *) &addr, &len);
			if (rlen >= 0) {
				buff[rlen] = '\0';
				DEBUG("got a msg from %s:%d msg:%s\n", inet_ntoa(addr.sin_addr),
						ntohs(addr.sin_port), buff);
				if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
					DEBUG("udp connect error (%d %s)\n", errno,
							strerror(errno));
				return fd;
			}
		}
	} else {
		DEBUG("select timeout\n");
		goto err_r;
	}

	err_r: close(fd);
	return -1;
}

int tcp_send_data(int sock, void *p_data, int data_len)
{
	int ret = 0, left_len = data_len, sent_len = 0;
	int i = 0;

	if (!p_data || data_len <= 0)
		return -1;

	/* wait most 2s to send data */
	while (i++ <= 100 && left_len > 0) {
		ret = send(sock, (char *)p_data+sent_len, left_len, MSG_DONTWAIT);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				usleep(20000);
				continue;
			}
			ERROR("send data error: %s\n", strerror(errno));
			return -2;
		}
		else if (ret == 0) {
			ERROR("socket error: %s\n", strerror(errno));
			return -3;
		} else {
			left_len	-= ret;
			sent_len	+= ret;
		}
	}

	DEBUG("socket[%d] send data success: len=%d, send_len=%d\n", sock, data_len, sent_len);
	return sent_len;
}

static int tcp_recv_data(int sock, void *p_buff, int size, int data_len)
{
	int left_len = data_len, read_len = 0, i = 0, ret = 0;

	if (!p_buff || size <= 0 || data_len < 0 || data_len > size)
		return -1;

	/* wait most 1s to recv all data */
	while (i++ <= 100 && left_len > 0) {
		ret = recv(sock, (char *)p_buff+read_len, left_len, MSG_DONTWAIT);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				usleep(10000);
				continue;
			}
			ERROR("socket[%d] recv data error: %s\n", sock, strerror(errno));
			return -2;
		}
		else if (ret == 0) {
			ERROR("socket[%d] recv() return 0, client close the socket!!!\n", sock);
			return -3;
		} else {
			read_len	+= ret;
			left_len	-= ret;
		}
	}
	return read_len;
}

int setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);
	if (opts < 0) {
		ERROR("fcntl(sock,GETFL)\n");
		return -1;
	}

	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
		ERROR("fcntl(sock,SETFL,opts)\n");
		return -2;
	}

	return 0;
}

/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <getopt.h>
#include <android/multinetwork.h>

#include "lxc.h"
#include "log.h"

#define DNS_PORT 53
#define BUFFER_SIZE 4096
#define MAX_CONCURRENT_QUERIES 64
#define QUERY_TIMEOUT_SEC 2
#define DEFAULT_BIND_ADDRESS "127.0.0.53"
#define MAX_EVENTS 128

lxc_log_define(lxc_networkd, lxc);

/* DNS query state */
struct dns_query {
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	int query_fd;
	int timer_fd;
	uint8_t request[BUFFER_SIZE];
	ssize_t request_len;
	int slot;
	bool active;
	char client_ip[INET_ADDRSTRLEN];
	char domain[256];
};

/* Main context */
struct lxc_networkd {
	char bind_address[INET_ADDRSTRLEN];
	int bind_port;
	char pid_file[PATH_MAX];
	bool have_pid_file;
	int server_fd;
	int epoll_fd;
	struct dns_query queries[MAX_CONCURRENT_QUERIES];
	int query_count;
	bool foreground;
};

static struct lxc_networkd networkd;
static volatile sig_atomic_t running = 1;

/* Signal handler */
static void signal_handler(int sig)
{
	running = 0;
}

/* Print usage */
static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"       %s --help\n\n"
		"DNS Proxy for LXC containers\n\n"
		"Options:\n"
		"  -f, --foreground        Run in foreground (default is daemon mode)\n"
		"  -a, --address ADDR      Bind to specific IP (default: %s)\n"
		"  -p, --port PORT         Bind to specific port (default: %d)\n"
		"  -P, --pid-file FILE     Write PID to specified file\n"
		"  -h, --help              Show this help message\n\n",
		name, name, DEFAULT_BIND_ADDRESS, DNS_PORT);
}

/* Write PID file */
static int write_pid_file(const char *pid_file)
{
	int fd;
	char pid_str[32];
	ssize_t len;

	fd = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		return -1;
	}

	len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	if (write(fd, pid_str, len) != len) {
		close(fd);
		unlink(pid_file);
		return -1;
	}

	close(fd);
	return 0;
}

/* Remove PID file */
static void remove_pid_file(void)
{
	if (networkd.have_pid_file && networkd.pid_file[0] != '\0') {
		unlink(networkd.pid_file);
		networkd.pid_file[0] = '\0';
		networkd.have_pid_file = false;
	}
}

/* Daemonize process */
static int daemonize(void)
{
	pid_t pid;
	int fd;
	struct rlimit rl;

	/* Fork once */
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Create new session */
	if (setsid() < 0) {
		return -1;
	}

	/* Fork again */
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0)
		_exit(EXIT_SUCCESS);

	/* Change working directory */
	if (chdir("/") < 0) {
		return -1;
	}

	/* Get maximum file descriptor count */
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		rl.rlim_max = 1024;
	}

	/* Close unnecessary file descriptors */
	for (fd = 0; fd < (int)rl.rlim_max; fd++) {
		if (fd != networkd.server_fd && 
			fd != networkd.epoll_fd && 
			fd > 2)
			close(fd);
	}

	/* Redirect stdio to /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		return -1;
	}
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > STDERR_FILENO)
		close(fd);

	umask(027);

	if (networkd.have_pid_file) {
		write_pid_file(networkd.pid_file);
	}

	return 0;
}

/* Validate DNS packet */
static bool is_valid_dns_packet(const uint8_t *packet, size_t length)
{
	uint16_t qdcount;

	if (length < 12)
		return false;

	if ((packet[2] & 0x80) != 0)
		return false;

	qdcount = (packet[4] << 8) | packet[5];
	return qdcount > 0;
}

/* Extract domain name from DNS query */
static char *extract_domain_name(const uint8_t *packet, size_t length, char *buffer, size_t bufsize)
{
	if (length < 12)
		return NULL;

	const uint8_t *ptr = packet + 12;
	const uint8_t *end = packet + length;
	char *buf_ptr = buffer;
	size_t remaining = bufsize;

	while (ptr < end && *ptr != 0) {
		if (*ptr > 63) /* Invalid label length */
			return NULL;

		uint8_t label_len = *ptr++;
		if (ptr + label_len > end)
			return NULL;

		if (buf_ptr != buffer) {
			if (remaining < 2)
				return NULL;
			*buf_ptr++ = '.';
			remaining--;
		}

		if (remaining < label_len + 1)
			return NULL;

		memcpy(buf_ptr, ptr, label_len);
		buf_ptr += label_len;
		remaining -= label_len;
		ptr += label_len;
	}

	*buf_ptr = '\0';
	return buffer;
}

/* Fix DNS response ID */
static bool fix_dns_response_id(const uint8_t *query, uint8_t *response, size_t length)
{
	if (length < 12)
		return false;

	response[0] = query[0];
	response[1] = query[1];
	return true;
}

/* Create error response */
static int create_error_response(const uint8_t *query, uint8_t *response, size_t max_len)
{
	if (max_len < 12)
		return 12;

	memcpy(response, query, 12);
	response[2] = 0x81;
	response[3] = 0x82;
	response[6] = response[7] = 0;
	response[8] = response[9] = 0;
	response[10] = response[11] = 0;

	return 12;
}

/* Find free query slot */
static int find_free_slot(struct lxc_networkd *netd)
{
	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		if (!netd->queries[i].active) {
			netd->queries[i].slot = i;
			return i;
		}
	}
	return -1;
}

/* Remove query from epoll and clean up */
static void cleanup_query(struct lxc_networkd *netd, int slot)
{
	struct dns_query *query = &netd->queries[slot];

	if (!query->active)
		return;

	if (query->query_fd > 2) {
		epoll_ctl(netd->epoll_fd, EPOLL_CTL_DEL, query->query_fd, NULL);
		close(query->query_fd);
	}

	if (query->timer_fd > 2) {
		epoll_ctl(netd->epoll_fd, EPOLL_CTL_DEL, query->timer_fd, NULL);
		close(query->timer_fd);
	}

	query->active = false;
	query->query_fd = -1;
	query->timer_fd = -1;
	netd->query_count--;
}

/* Handle DNS response */
static void handle_dns_response(struct lxc_networkd *netd, int slot)
{
	struct dns_query *query = &netd->queries[slot];
	uint8_t answer[BUFFER_SIZE];
	int rcode = 0;
	ssize_t answer_len;

	answer_len = android_res_nresult(query->query_fd, &rcode, answer, BUFFER_SIZE);

	if (answer_len > 0) {
		if (answer_len < 12) {
			if (netd->foreground) {
				printf("[%s:%d] Query from %s for %s: ERROR - Truncated response\n",
					netd->bind_address, netd->bind_port, query->client_ip, query->domain);
			}
			answer_len = create_error_response(query->request, answer, BUFFER_SIZE);
		} else {
			if (!fix_dns_response_id(query->request, answer, answer_len)) {
				if (netd->foreground) {
					printf("[%s:%d] Query from %s for %s: ERROR - Failed to fix DNS ID\n",
						netd->bind_address, netd->bind_port, query->client_ip, query->domain);
				}
				answer_len = create_error_response(query->request, answer, BUFFER_SIZE);
			} else {
				if (netd->foreground) {
					printf("[%s:%d] Query from %s for %s: SUCCESS\n",
						netd->bind_address, netd->bind_port, query->client_ip, query->domain);
				}
			}
		}

		sendto(netd->server_fd, answer, answer_len, 0,
			   (struct sockaddr *)&query->client_addr,
			   query->client_addr_len);
	} else {
		if (netd->foreground) {
			printf("[%s:%d] Query from %s for %s: ERROR - No response\n",
				netd->bind_address, netd->bind_port, query->client_ip, query->domain);
		}

		uint8_t error_response[BUFFER_SIZE];
		int error_len = create_error_response(query->request, error_response, BUFFER_SIZE);
		if (error_len > 0) {
			sendto(netd->server_fd, error_response, error_len, 0,
				   (struct sockaddr *)&query->client_addr,
				   query->client_addr_len);
		}
	}

	cleanup_query(netd, slot);
}

/* Handle query timeout */
static void handle_query_timeout(struct lxc_networkd *netd, int slot)
{
	struct dns_query *query = &netd->queries[slot];
	uint64_t expirations;

	if (query->timer_fd > 2) {
		read(query->timer_fd, &expirations, sizeof(expirations));
	}

	if (netd->foreground) {
		printf("[%s:%d] Query from %s for %s: ERROR - Timeout\n",
			netd->bind_address, netd->bind_port, query->client_ip, query->domain);
	}

	uint8_t error_response[BUFFER_SIZE];
	int error_len = create_error_response(query->request, error_response, BUFFER_SIZE);
	if (error_len > 0) {
		sendto(netd->server_fd, error_response, error_len, 0,
			   (struct sockaddr *)&query->client_addr,
			   query->client_addr_len);
	}

	cleanup_query(netd, slot);
}

static void handle_new_query(struct lxc_networkd *netd, int fd)
{
	struct dns_query *query = NULL;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	uint8_t buffer[BUFFER_SIZE];
	ssize_t recv_len;
	int slot;
	struct epoll_event ev;

	recv_len = recvfrom(fd, buffer, BUFFER_SIZE, 0,
				(struct sockaddr *)&client_addr, &addr_len);
	if (recv_len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			SYSERROR("Failed to receive query");
		}
		return;
	}

	if (recv_len == 0 || !is_valid_dns_packet(buffer, recv_len)) {
		return;
	}

	slot = find_free_slot(netd);
	if (slot < 0) {
		WARN("Max concurrent queries reached (%d)", MAX_CONCURRENT_QUERIES);
		return;
	}

	query = &netd->queries[slot];
	memset(query, 0, sizeof(*query));
	query->client_addr = client_addr;
	query->client_addr_len = addr_len;
	query->request_len = recv_len;
	memcpy(query->request, buffer, recv_len);
	query->slot = slot;
	query->query_fd = -1;
	query->timer_fd = -1;

	/* Extract client IP */
	inet_ntop(AF_INET, &client_addr.sin_addr, query->client_ip, INET_ADDRSTRLEN);

	/* Extract domain name */
	if (!extract_domain_name(buffer, recv_len, query->domain, sizeof(query->domain))) {
		strcpy(query->domain, "<unknown>");
	}

	query->query_fd = android_res_nsend(NETWORK_UNSPECIFIED,
					query->request,
					query->request_len,
					0);

	if (query->query_fd < 0) {
		SYSERROR("Failed to forward query (errno=%d)", errno);

		if (netd->foreground) {
			printf("[%s:%d] Query from %s for %s: ERROR - Failed to forward\n",
				netd->bind_address, netd->bind_port, query->client_ip, query->domain);
		}

		uint8_t error_response[BUFFER_SIZE];
		int error_len = create_error_response(query->request, error_response, BUFFER_SIZE);
		if (error_len > 0) {
			sendto(netd->server_fd, error_response, error_len, 0,
				   (struct sockaddr *)&client_addr, addr_len);
		}
		return;
	}

	if (query->query_fd <= 2) {
		SYSERROR("android_res_nsend returned invalid fd %d", query->query_fd);
		close(query->query_fd);
		return;
	}

	int flags = fcntl(query->query_fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(query->query_fd, F_SETFL, flags | O_NONBLOCK);

	query->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (query->timer_fd < 0) {
		SYSERROR("Failed to create timer fd");
		close(query->query_fd);
		return;
	}

	struct itimerspec timeout = {
		.it_value = { QUERY_TIMEOUT_SEC, 0 },
		.it_interval = { 0, 0 }
	};
	timerfd_settime(query->timer_fd, 0, &timeout, NULL);

	union {
		int fd;
		uint64_t u64;
		void *ptr;
	} data;

	data.u64 = ((uint64_t)slot << 32) | 1; /* type=1 is response fd */
	ev.events = EPOLLIN;
	ev.data.u64 = data.u64;
	if (epoll_ctl(netd->epoll_fd, EPOLL_CTL_ADD, query->query_fd, &ev) < 0) {
		SYSERROR("Failed to add query fd to epoll");
		close(query->query_fd);
		close(query->timer_fd);
		return;
	}

	data.u64 = ((uint64_t)slot << 32) | 2; /* type=2 is timerfd */
	ev.events = EPOLLIN;
	ev.data.u64 = data.u64;
	if (epoll_ctl(netd->epoll_fd, EPOLL_CTL_ADD, query->timer_fd, &ev) < 0) {
		SYSERROR("Failed to add timer fd to epoll");
		epoll_ctl(netd->epoll_fd, EPOLL_CTL_DEL, query->query_fd, NULL);
		close(query->query_fd);
		close(query->timer_fd);
		return;
	}

	query->active = true;
	netd->query_count++;

	DEBUG("Query forwarded, fd: %d, timer: %d, slot: %d, active: %d",
		  query->query_fd, query->timer_fd, slot, netd->query_count);
}

/* Create server socket */
static int create_server_socket(struct lxc_networkd *netd)
{
	struct sockaddr_in server_addr;
	int flags;

	/* NOT USE SO_REUSEADDR for systemd-resolved */
	netd->server_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (netd->server_fd < 0) {
		SYSERROR("Failed to create socket");
		return -1;
	}

	if (netd->server_fd <= 2) {
		int new_fd = fcntl(netd->server_fd, F_DUPFD, 3);
		if (new_fd < 0) {
			SYSERROR("Failed to duplicate server fd");
			close(netd->server_fd);
			return -1;
		}
		close(netd->server_fd);
		netd->server_fd = new_fd;
	}

	flags = fcntl(netd->server_fd, F_GETFL, 0);
	if (flags >= 0) {
		if (fcntl(netd->server_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			SYSERROR("Failed to set non-blocking mode");
			close(netd->server_fd);
			return -1;
		}
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(netd->bind_port);

	if (inet_pton(AF_INET, netd->bind_address, &server_addr.sin_addr) <= 0) {
		SYSERROR("Invalid address");
		close(netd->server_fd);
		return -1;
	}

	if (bind(netd->server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		SYSERROR("Failed to bind to address");
		close(netd->server_fd);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	char bind_address[INET_ADDRSTRLEN] = DEFAULT_BIND_ADDRESS;
	int bind_port = DNS_PORT;
	char pid_file[PATH_MAX] = {0};
	bool have_pid_file = false;
	bool foreground = false;
	bool server_created = false;
	struct epoll_event events[MAX_EVENTS];
	int nfds;

	static struct option long_options[] = {
		{"foreground", no_argument,       0, 'f'},
		{"address",    required_argument, 0, 'a'},
		{"port",       required_argument, 0, 'p'},
		{"pid-file",   required_argument, 0, 'P'},
		{"help",       no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "fa:p:P:h", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'f':
			foreground = true;
			break;
		case 'a':
			strncpy(bind_address, optarg, INET_ADDRSTRLEN - 1);
			bind_address[INET_ADDRSTRLEN - 1] = '\0';
			break;
		case 'p':
			bind_port = atoi(optarg);
			if (bind_port <= 0 || bind_port > 65535) {
				fprintf(stderr, "Invalid port: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'P':
			strncpy(pid_file, optarg, PATH_MAX - 1);
			pid_file[PATH_MAX - 1] = '\0';
			have_pid_file = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Initialize networkd context */
	memset(&networkd, 0, sizeof(networkd));
	strncpy(networkd.bind_address, bind_address, INET_ADDRSTRLEN - 1);
	networkd.bind_address[INET_ADDRSTRLEN - 1] = '\0';
	networkd.bind_port = bind_port;
	networkd.foreground = foreground;
	networkd.have_pid_file = have_pid_file;
	if (have_pid_file) {
		strncpy(networkd.pid_file, pid_file, PATH_MAX - 1);
		networkd.pid_file[PATH_MAX - 1] = '\0';
	}
	networkd.server_fd = -1;
	networkd.epoll_fd = -1;
	networkd.query_count = 0;

	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		networkd.queries[i].query_fd = -1;
		networkd.queries[i].timer_fd = -1;
		networkd.queries[i].active = false;
	}

	/* Create server socket (IPv4) */
	if (create_server_socket(&networkd) < 0)
		exit(EXIT_FAILURE);
	
	server_created = true;

	/* Create epoll fd */
	networkd.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (networkd.epoll_fd < 0) {
		SYSERROR("Failed to create epoll");
		goto cleanup;
	}

	if (networkd.epoll_fd <= 2) {
		int new_fd = fcntl(networkd.epoll_fd, F_DUPFD, 3);
		if (new_fd < 0) {
			SYSERROR("Failed to duplicate epoll fd");
			goto cleanup;
		}
		close(networkd.epoll_fd);
		networkd.epoll_fd = new_fd;
	}

	/* Add IPv4 server socket to epoll */
	struct epoll_event ev;
	union {
		int fd;
		uint64_t u64;
		void *ptr;
	} data;

	data.fd = networkd.server_fd;
	data.u64 = 0; /* type=0 is server fd */
	ev.events = EPOLLIN;
	ev.data.u64 = data.u64;
	if (epoll_ctl(networkd.epoll_fd, EPOLL_CTL_ADD, networkd.server_fd, &ev) < 0) {
		SYSERROR("Failed to add server fd to epoll");
		goto cleanup;
	}

	/* Daemonize unless foreground mode */
	if (!foreground) {
		if (daemonize() < 0) {
			SYSERROR("Failed to daemonize");
			goto cleanup;
		}
	} else {
		printf("DNS server listening on %s:%d\n", networkd.bind_address, networkd.bind_port);
		if (have_pid_file) {
			write_pid_file(pid_file);
		}
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	INFO("lxc-networkd started on %s:%d (pid %d, epoll, %s%s)",
		 networkd.bind_address, networkd.bind_port, getpid(),
		 foreground ? "foreground" : "daemon",
		 have_pid_file ? ", pidfile" : "");

	/* Main event loop */
	while (running) {
		nfds = epoll_wait(networkd.epoll_fd, events, MAX_EVENTS, 1000);

		if (nfds < 0) {
			if (errno != EINTR) {
				SYSERROR("Failed to wait for events");
				usleep(10000);
			}
			continue;
		}

		for (int i = 0; i < nfds; i++) {
			uint64_t ev_data = events[i].data.u64;
			int slot = (ev_data >> 32) & 0xFFFFFFFF;
			int type = ev_data & 0xFFFFFFFF;

			if (type == 0) {
				/* Handle new DNS query */
				handle_new_query(&networkd, networkd.server_fd);
			} else if (type == 1) {
				if (slot >= 0 && slot < MAX_CONCURRENT_QUERIES &&
					networkd.queries[slot].active) {
					if (events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR))
						handle_dns_response(&networkd, slot);
				}
			} else if (type == 2) {
				if (slot >= 0 && slot < MAX_CONCURRENT_QUERIES &&
					networkd.queries[slot].active) {
					if (events[i].events & EPOLLIN)
						handle_query_timeout(&networkd, slot);
				}
			}
		}
	}

	INFO("Shutting down");

cleanup:
	for (int i = 0; i < MAX_CONCURRENT_QUERIES; i++) {
		if (networkd.queries[i].active) {
			if (networkd.queries[i].query_fd > 2) {
				epoll_ctl(networkd.epoll_fd, EPOLL_CTL_DEL,
					  networkd.queries[i].query_fd, NULL);
				close(networkd.queries[i].query_fd);
			}
			if (networkd.queries[i].timer_fd > 2) {
				epoll_ctl(networkd.epoll_fd, EPOLL_CTL_DEL,
					  networkd.queries[i].timer_fd, NULL);
				close(networkd.queries[i].timer_fd);
			}
		}
	}

	if (server_created && networkd.server_fd > 2) {
		epoll_ctl(networkd.epoll_fd, EPOLL_CTL_DEL, networkd.server_fd, NULL);
		close(networkd.server_fd);
	}

	if (networkd.epoll_fd > 2)
		close(networkd.epoll_fd);

	if (have_pid_file)
		remove_pid_file();

	if (foreground)
		printf("DNS server stopped\n");

	exit(EXIT_SUCCESS);
}

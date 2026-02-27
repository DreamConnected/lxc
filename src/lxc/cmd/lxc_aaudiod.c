/* SPDX-License-Identifier: LGPL-2.1+ */

#include <aaudio/AAudio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "memory_utils.h"
#include "mainloop.h"
#include "process_utils.h"
#include "string_utils.h"

typedef struct {
	char play_fifo_path[256];
	char record_fifo_path[256];
	int sample_rate;
	int channels;
	aaudio_format_t format;
} AudioConfig;

static const AudioConfig default_config = {
	.play_fifo_path = "/data/local/tmp/.aaudio_play",
	.record_fifo_path = "/data/local/tmp/.aaudio_rec",
	.sample_rate = 48000,
	.channels = 2,
	.format = AAUDIO_FORMAT_PCM_I16
};

#define DEFAULT_PLAY_FIFO_PATH default_config.play_fifo_path
#define DEFAULT_RECORD_FIFO_PATH default_config.record_fifo_path
#define DEFAULT_SAMPLE_RATE default_config.sample_rate
#define DEFAULT_CHANNELS default_config.channels
#define DEFAULT_FORMAT default_config.format
#define BUFFER_SIZE 8192
#define MAX_CONTAINER_NAME_LENGTH 200

lxc_log_define(lxc_aaudiod, lxc);

typedef struct {
	AAudioStream *output_stream;
	AAudioStream *input_stream;
	int play_fifo_fd;
	int record_fifo_fd;
	volatile bool running;
	char play_fifo_path[256];
	char record_fifo_path[256];
	char container_name[256];
	int sample_rate;
	int channels;
	aaudio_format_t format;
	int bytes_per_frame;
	bool daemonized;
	struct lxc_async_descr descr;
} AudioBridge;

static AudioBridge g_bridge = {0};

static int quit;

static void cleanup_bridge(AudioBridge *bridge);

static int create_play_fifo(const char *path);

static void signal_handler(int sig)
{
	g_bridge.running = false;
	quit = LXC_MAINLOOP_CLOSE;
}

static int audio_play_handler(int fd, uint32_t events, void *data, struct lxc_async_descr *descr)
{
	AudioBridge *bridge = data;
	char buffer[BUFFER_SIZE];
	ssize_t nread;
	aaudio_result_t result;
	int frames;

	if (events & EPOLLHUP) {
		INFO("Play FIFO closed, reopening...");
		lxc_mainloop_del_handler(&bridge->descr, fd);
		close(bridge->play_fifo_fd);
		bridge->play_fifo_fd = create_play_fifo(bridge->play_fifo_path);
		if (bridge->play_fifo_fd < 0) {
			ERROR("Failed to reopen play FIFO");
			return LXC_MAINLOOP_CLOSE;
		}

		if (lxc_mainloop_add_handler(&bridge->descr, bridge->play_fifo_fd,
								   audio_play_handler, default_cleanup_handler,
								   bridge, "audio_play_handler") < 0) {
			ERROR("Failed to re-add play handler to mainloop");
			return LXC_MAINLOOP_CLOSE;
		}
		return LXC_MAINLOOP_CONTINUE;
	} else if (events & EPOLLERR) {
		INFO("Play FIFO error, reopening...");
		lxc_mainloop_del_handler(&bridge->descr, fd);
		close(bridge->play_fifo_fd);
		bridge->play_fifo_fd = create_play_fifo(bridge->play_fifo_path);

		if (bridge->play_fifo_fd < 0) {
			ERROR("Failed to reopen play FIFO");
			return LXC_MAINLOOP_CLOSE;
		}

		if (lxc_mainloop_add_handler(&bridge->descr, bridge->play_fifo_fd,
								   audio_play_handler, default_cleanup_handler,
								   bridge, "audio_play_handler") < 0) {
			ERROR("Failed to re-add play handler to mainloop");
			return LXC_MAINLOOP_CLOSE;
		}

		return LXC_MAINLOOP_CONTINUE;
	}

	if (events & EPOLLIN) {
		nread = read(fd, buffer, sizeof(buffer));
		if (nread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(100000);
				return LXC_MAINLOOP_CONTINUE;
			}
			ERROR("Play FIFO read error: %s", strerror(errno));
			return LXC_MAINLOOP_CLOSE;
		} else if (nread == 0) {
			INFO("Play FIFO closed, reopening...");
			lxc_mainloop_del_handler(&bridge->descr, fd);
			close(bridge->play_fifo_fd);
			bridge->play_fifo_fd = create_play_fifo(bridge->play_fifo_path);

			if (bridge->play_fifo_fd < 0) {
				ERROR("Failed to reopen play FIFO");
				return LXC_MAINLOOP_CLOSE;
			}

			if (lxc_mainloop_add_handler(&bridge->descr, bridge->play_fifo_fd,
								   audio_play_handler, default_cleanup_handler,
								   bridge, "audio_play_handler") < 0) {
				ERROR("Failed to re-add play handler to mainloop");
				return LXC_MAINLOOP_CLOSE;
			}
			
			return LXC_MAINLOOP_CONTINUE;
		}

		frames = nread / bridge->bytes_per_frame;
		result = AAudioStream_write(
			bridge->output_stream,
			buffer,
			frames,
			1000000000LL
		);

		if (result < 0) {
			if (result == AAUDIO_ERROR_DISCONNECTED) {
				ERROR("AAudio stream disconnected");
				return LXC_MAINLOOP_CLOSE;
			}
			ERROR("AAudio write error: %d", result);
		}
	}

	return LXC_MAINLOOP_CONTINUE;
}

static AAudioStream *init_aaudio_stream(bool is_output, AudioBridge *bridge)
{
	AAudioStreamBuilder *builder;
	AAudioStream *stream;
	aaudio_result_t result;

	result = AAudio_createStreamBuilder(&builder);
	if (result != AAUDIO_OK) {
		ERROR("Failed to create %s stream builder: %d",
			  is_output ? "output" : "input", result);
		return NULL;
	}

	AAudioStreamBuilder_setDirection(builder,
		is_output ? AAUDIO_DIRECTION_OUTPUT : AAUDIO_DIRECTION_INPUT);
	AAudioStreamBuilder_setSampleRate(builder, bridge->sample_rate);
	AAudioStreamBuilder_setChannelCount(builder, bridge->channels);
	AAudioStreamBuilder_setFormat(builder, bridge->format);
	AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
	AAudioStreamBuilder_setDataCallback(builder, NULL, NULL);

	result = AAudioStreamBuilder_openStream(builder, &stream);
	AAudioStreamBuilder_delete(builder);

	if (result != AAUDIO_OK) {
		ERROR("Failed to open %s stream: %d", is_output ? "output" : "input", result);
		return NULL;
	}

	result = AAudioStream_requestStart(stream);
	if (result != AAUDIO_OK) {
		ERROR("Failed to start %s stream: %d", is_output ? "output" : "input", result);
		AAudioStream_close(stream);
		return NULL;
	}

	int actual_rate = AAudioStream_getSampleRate(stream);
	int actual_channels = AAudioStream_getChannelCount(stream);
	aaudio_format_t actual_format = AAudioStream_getFormat(stream);

	INFO("%s stream started: %d Hz, %d ch, format: %d",
		  is_output ? "Output" : "Input",
		  actual_rate, actual_channels, actual_format);

	return stream;
}

static int create_fifo(const char *path, int flags, const char *type)
{
	int fd;

	if (access(path, F_OK) == 0) {
		INFO("%s FIFO already exists: %s", type, path);
	} else {
		if (mkfifo(path, 0777) < 0) {
			ERROR("mkfifo(%s) failed: %s", path, strerror(errno));
			return -1;
		}
		INFO("%s FIFO created: %s", type, path);
		chmod(path, 0777);
	}

	fd = open(path, flags);
	if (fd < 0) {
		ERROR("open(%s) failed: %s", path, strerror(errno));
		return -1;
	}

	return fd;
}

static int create_play_fifo(const char *path)
{
	return create_fifo(path, O_RDONLY | O_NONBLOCK, "Playback");
}

static int create_record_fifo(const char *path)
{
	return create_fifo(path, O_RDWR | O_NONBLOCK, "Record");
}

static void *record_thread_func(void *arg)
{
	AudioBridge *bridge = arg;
	char buffer[BUFFER_SIZE];
	int max_frames_per_read = sizeof(buffer) / bridge->bytes_per_frame;
	aaudio_result_t frames_read;
	ssize_t bytes_to_send, written;

	INFO("Record thread started");

	while (bridge->running) {
		frames_read = AAudioStream_read(
			bridge->input_stream,
			buffer,
			max_frames_per_read,
			1000000000LL
		);

		if (frames_read == AAUDIO_ERROR_TIMEOUT) {
			usleep(10000);
			continue;
		} else if (frames_read < 0) {
			if (frames_read == AAUDIO_ERROR_DISCONNECTED) {
				ERROR("AAudio input stream disconnected");
				break;
			}
			ERROR("AAudio read error: %d", frames_read);
			usleep(10000);
			continue;
		}

		if (frames_read > 0) {
			bytes_to_send = frames_read * bridge->bytes_per_frame;
			written = write(bridge->record_fifo_fd, buffer, bytes_to_send);

			if (written < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					usleep(10000);
					continue;
				}
				ERROR("Write to record FIFO failed: %s", strerror(errno));
				break;
			}
		}
	}

	return NULL;
}

static void cleanup_bridge(AudioBridge *bridge)
{
	if (!bridge)
		return;

	bridge->running = false;

	if (bridge->play_fifo_fd >= 0) {
		close(bridge->play_fifo_fd);
		bridge->play_fifo_fd = -1;
	}

	if (bridge->record_fifo_fd >= 0) {
		close(bridge->record_fifo_fd);
		bridge->record_fifo_fd = -1;
	}

	if (bridge->output_stream) {
		AAudioStream_requestStop(bridge->output_stream);
		AAudioStream_close(bridge->output_stream);
		bridge->output_stream = NULL;
	}

	if (bridge->input_stream) {
		AAudioStream_requestStop(bridge->input_stream);
		AAudioStream_close(bridge->input_stream);
		bridge->input_stream = NULL;
	}

	if (bridge->container_name[0] != '\0') {
		char pid_file_path[256];
		snprintf(pid_file_path, sizeof(pid_file_path), "/data/local/tmp/.aaudio_pid_%s", bridge->container_name);
		if (access(pid_file_path, F_OK) == 0) {
			unlink(pid_file_path);
			INFO("Removed PID file: %s", pid_file_path);
		}
	}

	INFO("Cleanup complete");
}

static void construct_fifo_paths(const char *container_name, char *play_path, char *record_path, char *pid_path)
{
	if (container_name) {
		snprintf(play_path, 256, "/data/local/tmp/.aaudio_play_%s", container_name);
		snprintf(record_path, 256, "/data/local/tmp/.aaudio_rec_%s", container_name);
		snprintf(pid_path, 256, "/data/local/tmp/.aaudio_pid_%s", container_name);
	} else {
		strcpy(play_path, DEFAULT_PLAY_FIFO_PATH);
		strcpy(record_path, DEFAULT_RECORD_FIFO_PATH);
		snprintf(pid_path, 256, "/data/local/tmp/.aaudio_pid");
	}
}

static int init_output_stream(AudioBridge *bridge)
{
	bridge->output_stream = init_aaudio_stream(true, bridge);
	if (!bridge->output_stream) {
		ERROR("Output stream initialization failed");
		return -1;
	}

	bridge->play_fifo_fd = create_play_fifo(bridge->play_fifo_path);
	if (bridge->play_fifo_fd < 0) {
		ERROR("Failed to create play FIFO");
		return -1;
	}

	return 0;
}

static int init_input_stream(AudioBridge *bridge, bool input_only, pthread_t *record_thread)
{
	bridge->input_stream = init_aaudio_stream(false, bridge);
	if (!bridge->input_stream) {
		if (input_only) {
			ERROR("Input stream initialization failed in input-only mode");
			return -1;
		}
		WARN("Input stream initialization failed, recording disabled");
		return 0;
	}

	bridge->record_fifo_fd = create_record_fifo(bridge->record_fifo_path);
	if (bridge->record_fifo_fd < 0) {
		if (input_only) {
			ERROR("Failed to create record FIFO in input-only mode");
			return -1;
		}
		WARN("Failed to create record FIFO, recording disabled");
		return 0;
	}

	if (pthread_create(record_thread, NULL, record_thread_func, bridge) != 0) {
		ERROR("Failed to create record thread");
		return 0;
	}

	pthread_detach(*record_thread);
	INFO("Record thread started");
	return 0;
}

static int handle_kill_mode(const char *container_name)
{
	if (container_name) {
		INFO("Killing audio streams for container: %s", container_name);
		char play_fifo_path[256], record_fifo_path[256], pid_file_path[256];
		construct_fifo_paths(container_name, play_fifo_path, record_fifo_path, pid_file_path);
		
		__do_fclose FILE *pid_file = fopen(pid_file_path, "r");
		if (pid_file) {
			pid_t pid;
			if (fscanf(pid_file, "%d", &pid) == 1) {
				if (kill(pid, SIGTERM) == 0) {
					INFO("Sent SIGTERM to process: %d", pid);
					sleep(1);
					if (kill(pid, 0) == 0) {
						INFO("Process %d is still running, sending SIGKILL", pid);
						kill(pid, SIGKILL);
						sleep(1);
					}
				} else {
					ERROR("Failed to send SIGTERM to process: %d", pid);
				}
			}
			unlink(pid_file_path);
			INFO("Removed PID file: %s", pid_file_path);
		}

		if (access(play_fifo_path, F_OK) == 0) {
			unlink(play_fifo_path);
			INFO("Removed playback FIFO: %s", play_fifo_path);
		}

		if (access(record_fifo_path, F_OK) == 0) {
			unlink(record_fifo_path);
			INFO("Removed record FIFO: %s", record_fifo_path);
		}
	} else {
		INFO("Killing all audio streams");
		__do_closedir DIR *dir = opendir("/data/local/tmp");
		if (dir) {
			struct dirent *entry;
			while ((entry = readdir(dir)) != NULL) {
				if (strstr(entry->d_name, ".aaudio_pid") == entry->d_name) {
					char pid_file_path[256];
					snprintf(pid_file_path, sizeof(pid_file_path), "/data/local/tmp/%s", entry->d_name);
					__do_fclose FILE *pid_file = fopen(pid_file_path, "r");
					if (pid_file) {
						pid_t pid;
						if (fscanf(pid_file, "%d", &pid) == 1) {
							if (kill(pid, SIGTERM) == 0) {
								INFO("Sent SIGTERM to process: %d", pid);
								sleep(1);
								if (kill(pid, 0) == 0) {
									INFO("Process %d is still running, sending SIGKILL", pid);
									kill(pid, SIGKILL);
									sleep(1);
								}
							} else {
								ERROR("Failed to send SIGTERM to process: %d", pid);
							}
						}
						unlink(pid_file_path);
						INFO("Removed PID file: %s", pid_file_path);
					}
				}
				if (strstr(entry->d_name, ".aaudio_play") == entry->d_name ||
					strstr(entry->d_name, ".aaudio_rec") == entry->d_name) {
					char fifo_path[256];
					snprintf(fifo_path, sizeof(fifo_path), "/data/local/tmp/%s", entry->d_name);
					unlink(fifo_path);
					INFO("Removed FIFO: %s", fifo_path);
				}
			}
		}
	}
	return 0;
}

static void show_help(const char *progname)
{
	printf("Usage: %s [options]\n\n", progname);
	printf("Options:\n");
	printf("  -p, --play PATH      Playback FIFO path (default: %s)\n", DEFAULT_PLAY_FIFO_PATH);
	printf("  -r, --record PATH    Record FIFO path (default: %s)\n", DEFAULT_RECORD_FIFO_PATH);
	printf("  -R, --rate HZ        Sample rate (default: %d)\n", DEFAULT_SAMPLE_RATE);
	printf("  -C, --channels N     Channel count (default: %d)\n", DEFAULT_CHANNELS);
	printf("  -i, --input-only     Input only mode (disable output)\n");
	printf("  -o, --output-only    Output only mode (disable input)\n");
	printf("  -f, --foreground     Run in foreground (default is background)\n");
	printf("  -n, --name NAME      Container name (adds suffix to FIFO paths)\n");
	printf("  -k, --kill           Kill audio streams (for specified container or all)\n");
	printf("  -d, --daemon         Run as daemon (persistent)\n");
	printf("  -h, --help           Show this help\n");
	printf("\n");
	printf("FIFO mode:\n");
	printf("  Playback: module-pipe-sink file=<PLAY_FIFO>\n");
	printf("  Recording: module-pipe-source file=<RECORD_FIFO>\n");
	printf("\n");
	printf("NOTE: lxc-aaudiod is intended for use by lxc internally\n");
	printf("      and does not need to be run by hand\n\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	bool input_only = false;
	bool output_only = false;
	bool foreground = false;
	bool kill_mode = false;
	int sample_size = 2;
	pthread_t record_thread = 0;
	char *container_name = NULL;
	bool persistent = false;
	int pipefd = -1;
	int ret = EXIT_FAILURE;
	sigset_t mask;
	bool mainloop_opened = false;

	static struct option long_options[] = {
	{"play",        required_argument, 0, 'p'},
	{"record",      required_argument, 0, 'r'},
	{"rate",        required_argument, 0, 'R'},
	{"channels",    required_argument, 0, 'C'},
	{"input-only",  no_argument,       0, 'i'},
	{"output-only", no_argument,       0, 'o'},
	{"foreground",  no_argument,       0, 'f'},
	{"help",        no_argument,       0, 'h'},
	{"name",        required_argument, 0, 'n'},
	{"kill",        no_argument,       0, 'k'},
	{"daemon",      no_argument,       0, 'd'},
	{0, 0, 0, 0}
};

	int daemon_arg_index = -1;
	int pipefd_arg_index = -1;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--daemon")) {
			daemon_arg_index = i;
			persistent = true;
			
			if (i + 1 < argc && lxc_safe_int(argv[i + 1], &pipefd) == 0) {
				pipefd_arg_index = i + 1;
				break;
			}
			break;
		}
	}

	int new_argc = 1;
	char **new_argv = malloc((argc + 1) * sizeof(char *));
	if (!new_argv) {
		ERROR("Failed to allocate memory for new argv");
		exit(EXIT_FAILURE);
	}
	new_argv[0] = argv[0];

	for (i = 1; i < argc; i++) {
		if (i == daemon_arg_index || i == pipefd_arg_index) {
			continue;
		}
		new_argv[new_argc++] = argv[i];
	}
	new_argv[new_argc] = NULL;

	memset(&g_bridge, 0, sizeof(g_bridge));
	strcpy(g_bridge.play_fifo_path, DEFAULT_PLAY_FIFO_PATH);
	strcpy(g_bridge.record_fifo_path, DEFAULT_RECORD_FIFO_PATH);
	g_bridge.sample_rate = DEFAULT_SAMPLE_RATE;
	g_bridge.channels = DEFAULT_CHANNELS;
	g_bridge.format = DEFAULT_FORMAT;
	g_bridge.daemonized = false;

	option_index = 0;
	while ((opt = getopt_long(new_argc, new_argv, "p:r:iofhn:kR:C:d", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'p':
			strlcpy(g_bridge.play_fifo_path, optarg, sizeof(g_bridge.play_fifo_path));
			break;
		case 'r':
			strlcpy(g_bridge.record_fifo_path, optarg, sizeof(g_bridge.record_fifo_path));
			break;
		case 'R':
			g_bridge.sample_rate = atoi(optarg);
			if (g_bridge.sample_rate <= 0) {
				fprintf(stderr, "Invalid sample rate: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'C':
			g_bridge.channels = atoi(optarg);
			if (g_bridge.channels <= 0 || g_bridge.channels > 8) {
				fprintf(stderr, "Invalid channel count: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			input_only = true;
			break;
		case 'o':
			output_only = true;
			break;
		case 'f':
			foreground = true;
			break;
		case 'h':
			show_help(argv[0]);
			exit(EXIT_SUCCESS);
		case 'n':
			container_name = optarg;
			strlcpy(g_bridge.container_name, optarg, sizeof(g_bridge.container_name));
			break;
		case 'k':
			kill_mode = true;
			break;
		case 'd':
			persistent = true;
			break;
		default:
			show_help(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	int new_optind = optind;
	if (new_optind < new_argc) {
		if (!container_name) {
			container_name = new_argv[new_optind];
			strlcpy(g_bridge.container_name, container_name, sizeof(g_bridge.container_name));
			new_optind++;
		}
		
		if (new_optind < new_argc) {
			fprintf(stderr, "Invalid argument: %s\n", new_argv[new_optind]);
			show_help(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	free(new_argv);

	if (container_name) {
		if (strlen(container_name) > MAX_CONTAINER_NAME_LENGTH) {
			ERROR("Container name too long");
			exit(EXIT_FAILURE);
		}
		char play_fifo_path[256];
		char record_fifo_path[256];
		snprintf(play_fifo_path, sizeof(play_fifo_path), "/data/local/tmp/.aaudio_play_%s", container_name);
		snprintf(record_fifo_path, sizeof(record_fifo_path), "/data/local/tmp/.aaudio_rec_%s", container_name);
		strlcpy(g_bridge.play_fifo_path, play_fifo_path, sizeof(g_bridge.play_fifo_path));
		strlcpy(g_bridge.record_fifo_path, record_fifo_path, sizeof(g_bridge.record_fifo_path));
	}

	if (kill_mode) {
		ret = handle_kill_mode(container_name);
		exit(ret);
	}

	if (input_only && output_only) {
		ERROR("Cannot specify both --input-only and --output-only");
		exit(EXIT_FAILURE);
	}

	if (g_bridge.format == AAUDIO_FORMAT_PCM_FLOAT ||
		g_bridge.format == AAUDIO_FORMAT_PCM_I32)
		sample_size = 4;

	g_bridge.bytes_per_frame = g_bridge.channels * sample_size;

	if (sigfillset(&mask) ||
		sigdelset(&mask, SIGILL)  ||
		sigdelset(&mask, SIGSEGV) ||
		sigdelset(&mask, SIGBUS)  ||
		sigdelset(&mask, SIGTERM) ||
		sigdelset(&mask, SIGINT)  ||
		pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
		SYSERROR("Failed to set signal mask");
		exit(EXIT_FAILURE);
	}

	signal(SIGILL,  signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS,  signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGINT,  signal_handler);

	INFO("AAudio FIFO Bridge starting...");
	INFO("Configuration: %d Hz, %d ch, %d bytes/frame",
		 g_bridge.sample_rate, g_bridge.channels, g_bridge.bytes_per_frame);

	if (lxc_mainloop_open(&g_bridge.descr)) {
		ERROR("Failed to create mainloop");
		ret = EXIT_FAILURE;
		goto cleanup;
	}
	mainloop_opened = true;

	if (!input_only) {
		if (init_output_stream(&g_bridge) < 0) {
			ERROR("Failed to initialize output stream");
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}

	if (!output_only) {
		if (init_input_stream(&g_bridge, input_only, &record_thread) < 0) {
			ERROR("Failed to initialize input stream");
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}

	if (!g_bridge.output_stream && !g_bridge.input_stream) {
		ERROR("No audio streams available, exiting");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	if (pipefd != -1) {
		if (lxc_write_nointr(pipefd, "S", 1)) {
			;
		}
		close(pipefd);
	}

	if (g_bridge.output_stream && g_bridge.play_fifo_fd >= 0) {
		if (lxc_mainloop_add_handler(&g_bridge.descr, g_bridge.play_fifo_fd,
								   audio_play_handler, default_cleanup_handler,
								   &g_bridge, "audio_play_handler") < 0) {
			ERROR("Failed to add play handler to mainloop");
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}

	g_bridge.running = true;
	quit = LXC_MAINLOOP_CONTINUE;

	if (foreground) {
		INFO("Bridge ready.");
		if (g_bridge.output_stream)
			INFO("Playback FIFO: %s", g_bridge.play_fifo_path);
		if (g_bridge.input_stream && g_bridge.record_fifo_fd >= 0)
			INFO("Record FIFO: %s", g_bridge.record_fifo_path);
		INFO("Press Ctrl+C to exit");
	} else {
		INFO("Bridge ready. PID: %d", lxc_raw_getpid());
	}

	if (container_name) {
		char pid_file_path[256];
		snprintf(pid_file_path, sizeof(pid_file_path), "/data/local/tmp/.aaudio_pid_%s", container_name);
		__do_fclose FILE *pid_file = fopen(pid_file_path, "w");
		if (pid_file) {
			fprintf(pid_file, "%d", lxc_raw_getpid());
			INFO("Created PID file: %s, PID: %d", pid_file_path, lxc_raw_getpid());
		} else {
			ERROR("Failed to create PID file: %s", pid_file_path);
		}
	}

	for (;;) {
		ret = lxc_mainloop(&g_bridge.descr, persistent ? -1 : 1000);
		if (ret < 0) {
			ERROR("Mainloop error: %d", ret);
			break;
		}

		if (quit == LXC_MAINLOOP_CLOSE || !g_bridge.running) {
			INFO("Got quit command or signal. AAudio FIFO Bridge is exiting");
			break;
		}
	}

	ret = EXIT_SUCCESS;

cleanup:
	if (g_bridge.running)
		g_bridge.running = false;

	cleanup_bridge(&g_bridge);

	if (mainloop_opened)
		lxc_mainloop_close(&g_bridge.descr);

	exit(ret);
}

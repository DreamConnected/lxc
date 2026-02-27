/* SPDX-License-Identifier: LGPL-2.1+ */

#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "log.h"
#include "aaudio.h"
#include "confile.h"
#include "memory_utils.h"
#include "process_utils.h"
#include "string_utils.h"
#include "start.h"
#include "utils.h"

#define LXC_AAUDIOD_PATH LIBEXECDIR "/lxc/lxc-aaudiod"
#define LXC_AAUDIOD_TMP "/data/local/tmp"

lxc_log_define(aaudio, lxc);

#if USE_ANDROID_AUDIO

/* Used to spawn a aaudiod when starting a container */
static int lxc_aaudiod_spawn(const char *name)
{
	int ret;
	int pipefd[2];
	char pipefd_str[INTTYPE_TO_STRLEN(int)];
	pid_t pid1, pid2;

	char *const args[] = {
		LXC_AAUDIOD_PATH,
		"--name",
		(char *)name,
		"--daemon",
		pipefd_str,
		NULL,
	};

	/* double fork to avoid zombies when aaudiod exits */
	pid1 = fork();
	if (pid1 < 0) {
		SYSERROR("Failed to fork()");
		return -1;
	}

	if (pid1) {
		if (waitpid(pid1, NULL, 0) != pid1)
			return -1;

		return 0;
	}

	if (pipe(pipefd) < 0) {
		SYSERROR("Failed to create pipe");
		_exit(EXIT_FAILURE);
	}

	pid2 = fork();
	if (pid2 < 0) {
		SYSERROR("Failed to fork()");
		_exit(EXIT_FAILURE);
	}

	if (pid2) {
		char c;

		/* Wait for daemon to create FIFO files */
		close(pipefd[1]);

		/* Sync with child, we're ignoring the return from read
		 * because regardless if it works or not, either way we've
		 * synced with the child process. the if-empty-statement
		 * construct is to quiet the warn-unused-result warning.
		 */
		if (lxc_read_nointr(pipefd[0], &c, 1)) {
			;
		}

		close(pipefd[0]);

		_exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		SYSERROR("Failed to setsid()");
		_exit(EXIT_FAILURE);
	}

	/* Close all inherited file descriptors except pipefd[1] */
	if (lxc_check_inherited(NULL, true, &pipefd[1], 1) < 0) {
		SYSERROR("Failed to check inherited file descriptors");
		_exit(EXIT_FAILURE);
	}
	
	if (null_stdfds() < 0) {
		ERROR("Failed to dup2() standard file descriptors to /dev/null");
		_exit(EXIT_FAILURE);
	}

	close(pipefd[0]);

	ret = snprintf(pipefd_str, sizeof(pipefd_str), "%d", pipefd[1]);
	if (ret < 0 || (size_t)ret >= sizeof(pipefd_str)) {
		ERROR("Failed to create pipefd argument to pass to aaudiod");
		_exit(EXIT_FAILURE);
	}

	execvp(args[0], args);
	SYSERROR("Failed to exec lxc-aaudiod");

	_exit(EXIT_FAILURE);
}

int lxc_aaudio_setup(const char *name, struct lxc_conf *conf)
{
	__do_free char *play_entry = NULL;
	__do_free char *rec_entry = NULL;
	int ret;

	if (lxc_aaudiod_spawn(name) < 0)
		return log_error(-1, "Failed to spawn lxc-aaudiod");

	ret = asprintf(&play_entry, "%s/.aaudio_play_%s opt/.aaudio_play none bind,create=file 0 0", LXC_AAUDIOD_TMP, name);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to allocate memory for play entry");

	ret = asprintf(&rec_entry, "%s/.aaudio_rec_%s opt/.aaudio_rec none bind,create=file 0 0", LXC_AAUDIOD_TMP, name);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to allocate memory for rec entry");

	if (add_elem_to_mount_list(play_entry, conf) < 0) {
		log_error(-1, "Failed to add play mount entry");
		return -1;
	}

	if (add_elem_to_mount_list(rec_entry, conf) < 0) {
		log_error(-1, "Failed to add rec mount entry");
		return -1;
	}

	return 0;
}

int lxc_aaudio_kill(const char *name)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return log_error_errno(-1, errno, "Failed to fork for lxc-aaudiod kill");

	if (pid == 0) {
		execl(LXC_AAUDIOD_PATH, "lxc-aaudiod", "--name", name, "--kill", NULL);
		log_error_errno(-1, errno, "Failed to execute lxc-aaudiod kill");
		_exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &status, 0) < 0)
		return log_error_errno(-1, errno, "Failed to wait for lxc-aaudiod kill");

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return log_error(-1, "lxc-aaudiod failed to stop");

	return 0;
}
#else
int lxc_aaudio_setup(const char *name, struct lxc_conf *conf)
{
	return 0;
}

int lxc_aaudio_kill(const char *name)
{
	return 0;
}
#endif

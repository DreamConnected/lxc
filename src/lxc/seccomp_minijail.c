/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <linux/filter.h>

#include "log.h"
#include "mainloop.h"
#include "lxcseccomp.h"

#undef ARRAY_SIZE
#include <libminijail/util.h>

lxc_log_define(seccomp_minijail, lxc);

#define MAX_CGROUPS 10 /* 10 different controllers supported by Linux. */
#define MAX_RLIMITS 32 /* Currently there are 15 supported by Linux. */
#define MAX_PRESERVED_FDS 128U

struct minijail_rlimit {
	int type;
	rlim_t cur;
	rlim_t max;
};

struct preserved_fd {
	int parent_fd;
	int child_fd;
};

struct minijail {
	/*
	 * WARNING: new bool flags should always be added to this struct,
	 * unless you’re certain they don’t need to remain after marshaling.
	 * If you add a flag here you need to make sure it's
	 * accounted for in minijail_pre{enter|exec}() below.
	 */
	struct {
		bool uid : 1;
		bool gid : 1;
		bool inherit_suppl_gids : 1;
		bool set_suppl_gids : 1;
		bool keep_suppl_gids : 1;
		bool use_caps : 1;
		bool capbset_drop : 1;
		bool set_ambient_caps : 1;
		bool vfs : 1;
		bool enter_vfs : 1;
		bool pids : 1;
		bool ipc : 1;
		bool uts : 1;
		bool net : 1;
		bool net_loopback : 1;
		bool enter_net : 1;
		bool ns_cgroups : 1;
		bool userns : 1;
		bool disable_setgroups : 1;
		bool seccomp : 1;
		bool remount_proc_ro : 1;
		bool no_new_privs : 1;
		bool seccomp_filter : 1;
		bool seccomp_filter_tsync : 1;
		bool seccomp_filter_logging : 1;
		bool seccomp_filter_allow_speculation : 1;
		bool chroot : 1;
		bool pivot_root : 1;
		bool mount_dev : 1;
		bool mount_tmp : 1;
		bool do_init : 1;
		bool run_as_init : 1;
		bool pid_file : 1;
		bool cgroups : 1;
		bool alt_syscall : 1;
		bool reset_signal_mask : 1;
		bool reset_signal_handlers : 1;
		bool close_open_fds : 1;
		bool new_session_keyring : 1;
		bool forward_signals : 1;
		bool setsid : 1;
		bool using_minimalistic_mountns : 1;
		bool enable_fs_restrictions : 1;
		bool enable_profile_fs_restrictions : 1;
		bool enable_default_runtime : 1;
		bool enable_new_sessions : 1;
	} flags;
	uid_t uid;
	gid_t gid;
	gid_t usergid;
	char *user;
	size_t suppl_gid_count;
	gid_t *suppl_gid_list;
	uint64_t caps;
	uint64_t cap_bset;
	pid_t initpid;
	int mountns_fd;
	int netns_fd;
	int fs_rules_fd;
	int fs_rules_landlock_abi;
	char *chrootdir;
	char *pid_file_path;
	char *uidmap;
	char *gidmap;
	char *hostname;
	char *preload_path;
	/*
	 * Filename that will be executed, unless an ELF fd is used instead.
	 * This field is only used for logs and isn't included in marshaling.
	 */
	char *filename;
	size_t filter_len;
	struct sock_fprog *filter_prog;
	char *alt_syscall_table;
	struct mountpoint *mounts_head;
	struct mountpoint *mounts_tail;
	size_t mounts_count;
	unsigned long remount_mode;
	struct minijail_remount *remounts_head;
	struct minijail_remount *remounts_tail;
	size_t tmpfs_size;
	struct fs_rule *fs_rules_head;
	struct fs_rule *fs_rules_tail;
	size_t fs_rules_count;
	char *cgroups[MAX_CGROUPS];
	size_t cgroup_count;
	struct minijail_rlimit rlimits[MAX_RLIMITS];
	size_t rlimit_count;
	uint64_t securebits_skip_mask;
	struct hook *hooks_head;
	struct hook *hooks_tail;
	struct preserved_fd preserved_fds[MAX_PRESERVED_FDS];
	size_t preserved_fd_count;
	char *seccomp_policy_path;
};

void seccomp_conf_init(struct lxc_conf *conf)
{
	conf->seccomp.seccomp = NULL;
	conf->seccomp.minijail = minijail_new();
}

int parse_config(FILE *f, char *line, size_t *line_bufsz, struct lxc_conf *conf)
{
	int ret = 0;
	char cn[256];

	while (fgets(line, 1024, f) != NULL) {
		if (line[0] == '#' || line[0] == '\n')
			continue;

		if (sscanf(line, "%255[^:]", cn) >= 2) {
			ERROR("Failed to parse line: %s", line);
			ret = -1;
			break;
		}

		int syscall_nr = lookup_syscall(cn, NULL);
		if (syscall_nr < 0) {
			WARN("Unknown syscall '%s' in seccomp policy", cn);
			continue;
		}
	}

	return ret;
}

int lxc_read_seccomp_config(struct lxc_conf *conf) 
{ 
	__do_fclose FILE *f = NULL; 
	char line[1024]; 
	size_t line_bufsz = 0; 

	if (!conf->seccomp.seccomp) 
		return 0; 

	if (!conf->seccomp.minijail) { 
		ERROR("Failed initializing seccomp"); 
		return -1; 
	} 

	f = fopen(conf->seccomp.seccomp, "re"); 
	if (!f) { 
		SYSERROR("Failed to open seccomp policy file %s", conf->seccomp.seccomp); 
		return -1; 
	} 

	if (parse_config(f, line, &line_bufsz, conf) != 0) { 
		ERROR("Failed parse seccomp conf"); 
		return -1; 
	} 

	rewind(f); 

	minijail_log_to_fd(STDERR_FILENO, ANDROID_LOG_UNKNOWN);
	minijail_log_seccomp_filter_failures(conf->seccomp.minijail);
	//minijail_set_seccomp_filter_tsync(conf->seccomp.minijail);
	minijail_use_seccomp_filter(conf->seccomp.minijail); 
	minijail_parse_seccomp_filters(conf->seccomp.minijail, conf->seccomp.seccomp);

	conf->seccomp.minijail->flags.no_new_privs = 1;
	//conf->seccomp.minijail->flags.seccomp_filter_logging = 1;
	conf->seccomp.minijail->flags.setsid = 1;
	conf->seccomp.minijail->flags.enable_new_sessions = 1;

	return 0; 
}

int lxc_seccomp_load(struct lxc_conf *conf)
{
	if (!conf->seccomp.seccomp)
		return 0;

	minijail_enter(conf->seccomp.minijail); 
	return 0;
}

void lxc_seccomp_free(struct lxc_seccomp *seccomp)
{
	free_disarm(seccomp->seccomp);
	minijail_destroy(seccomp->minijail);
}

int seccomp_notify_handler(int fd, uint32_t events, void *data,
			   struct lxc_async_descr *descr)
{
	return LXC_MAINLOOP_CONTINUE;
}

int seccomp_notify_cleanup_handler(int fd, void *data)
{
	return 0;
}

int lxc_seccomp_setup_proxy(struct lxc_seccomp *seccomp,
				struct lxc_async_descr *descr,
				struct lxc_handler *handler)
{
	return 0;
}

int lxc_seccomp_send_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd)
{
	return 0;
}

int lxc_seccomp_recv_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd)
{
	return 0;
}

int lxc_seccomp_add_notifier(const char *name, const char *lxcpath,
				 struct lxc_seccomp *seccomp)
{
	return 0;
}

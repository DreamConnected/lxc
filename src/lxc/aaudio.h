/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_AAUDIO_H
#define __LXC_AAUDIO_H

#include "conf.h"

extern int lxc_aaudio_setup(const char *name, struct lxc_conf *conf);
extern int lxc_aaudio_kill(const char *name);

#endif /* __LXC_AAUDIO_H */

/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+ *
 *
 */

#ifndef _PTHREAD_EXT_H
#define _PTHREAD_EXT_H

#include "../lxc/compiler.h"

#ifndef PTHREAD_CANCELED
#define PTHREAD_CANCELED ((void *)-1)
#endif

__hidden extern int pthread_setcancelstate(int, int *);

#endif

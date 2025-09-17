/* liblxcapi
 *
 * SPDX-License-Identifier: LGPL-2.1+ *
 *
 * This is not a standard implementation.
 * It only protects getgrgid_r().
 */

#include <pthread.h>
#include "pthread_ext.h"

static const int signals[] = {
	SIGINT,
	SIGTERM,
	SIGQUIT,
};

int pthread_setcancelstate(int state, int *oldstate) 
{
	sigset_t signal_set;
	sigset_t old_mask;
	sigemptyset(&signal_set);

	for (size_t i = 0; i < sizeof(signals)/sizeof(signals[0]); i++)
		sigaddset(&signal_set, signals[i]);
	
	int operation = (state == 1) ? SIG_UNBLOCK : SIG_BLOCK;
	return pthread_sigmask(operation, &signal_set, &old_mask);
}

#include <darlingserver/duct-tape/condvar.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/hooks.internal.h>

// an extremely unoptimized (and honestly, half-assed) implementation of condition variables for duct-taped code

void dtape_condvar_init(dtape_condvar_t* condvar) {
	libsimple_lock_init(&condvar->queue_lock);
	TAILQ_INIT(&condvar->queue_head);
};

void dtape_condvar_signal(dtape_condvar_t* condvar, size_t count) {
	libsimple_lock_lock(&condvar->queue_lock);
	while (count > 0) {
		dtape_mutex_link_t* link = TAILQ_FIRST(&condvar->queue_head);
		if (!link) {
			break;
		}

		TAILQ_REMOVE(&condvar->queue_head, link, link);
		link->link.tqe_prev = NULL; // x86Code: dequeued (see dtape_condvar_wait)
		dtape_thread_t* thread = __container_of(link, dtape_thread_t, mutex_link);
		dtape_hooks->thread_resume(thread->context);

		--count;
	}
	libsimple_lock_unlock(&condvar->queue_lock);
};

void dtape_condvar_wait(dtape_condvar_t* condvar, dtape_mutex_t* mutex) {
	dtape_thread_t* thread = dtape_thread_for_xnu_thread(current_thread());

	libsimple_lock_lock(&condvar->queue_lock);

	// unlocking the mutex here is safe;
	// we can't be signaled until we drop the queue lock,
	// which we only do once we actually suspend ourselves,
	// so there's no chance for us to miss a wakeup here.
	dtape_mutex_unlock(mutex);

	// add ourselves to the wait queue
	TAILQ_INSERT_TAIL(&condvar->queue_head, &thread->mutex_link, link);

	// now let's suspend ourselves to wait;
	// this also drops the queue lock.
	dtape_hooks->thread_suspend(thread->context, NULL, NULL, &condvar->queue_lock);

	// x86Code (Input 3): a resume that wasn't our signal (Thread::resume() from elsewhere) returns here with our link
	// still queued. Callers wait in a loop (thread_wait), and the next wait inserted the queued link again: tqe_next
	// pointing at itself, and the next dtape_condvar_signal(SIZE_MAX) resumed the same thread for ever, darlingserver at
	// 100% CPU and every Darling process stalled in its RPCs (an extension's thread_suspend of its own thread, after an
	// app SIGKILL on the iPad). Take the link out ourselves if no signal did.
	libsimple_lock_lock(&condvar->queue_lock);
	if (thread->mutex_link.link.tqe_prev != NULL) {
		TAILQ_REMOVE(&condvar->queue_head, &thread->mutex_link, link);
		thread->mutex_link.link.tqe_prev = NULL;
	}
	libsimple_lock_unlock(&condvar->queue_lock);

	// we've been awoken; reacquire the mutex
	dtape_mutex_lock(mutex);
};

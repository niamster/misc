#include <semaphore.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>

struct rw_lock *rw;
int *counter;

struct rw_lock {
	sem_t wbl;
	sem_t rbl;
	sem_t r;
	sem_t w;
	int limit;
	pid_t writer;
	pid_t *readers;
};

void init_rwlock(struct rw_lock **rw, int limit)
{
	*rw = mmap(NULL, sizeof(struct rw_lock), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

	sem_init(&(*rw)->r, 1, limit);
	sem_init(&(*rw)->w, 1, 1);
	sem_init(&(*rw)->wbl, 1, 1);
	sem_init(&(*rw)->rbl, 1, 1);
	(*rw)->limit = limit;
	(*rw)->writer = 0;
	(*rw)->readers = mmap(NULL, sizeof(pid_t)*limit, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
}

void rlock(struct rw_lock *rw)
{
	int i;
	struct timespec to = {
		.tv_sec = 1,
		.tv_nsec = 0
	};

	sem_wait(&rw->w);

	do {
		if (sem_timedwait(&rw->r, &to) == 0) {
			break;
		} else if (errno == ETIMEDOUT) {
			sem_wait(&rw->rbl);
			for (i=0;i<rw->limit;++i)
				if (rw->readers[i] && kill(rw->readers[i], 0) == -1 && errno == ESRCH) {
					printf("deadlock detected: process invoked rlock died(%d)\n", rw->readers[i]), fflush(NULL);
					rw->readers[i] = 0;
					sem_post(&rw->r);

					break;
				}
			sem_post(&rw->rbl);
		}
	} while (1);

	sem_wait(&rw->rbl);
	for (i=0;i<rw->limit;++i)
		if (rw->readers[i] == 0) {
			rw->readers[i] = getpid();

			break;
		}
	sem_post(&rw->rbl);

	sem_post(&rw->w);
}

void runlock(struct rw_lock *rw)
{
	int i, current = getpid();

	sem_wait(&rw->rbl);
	for (i=0;i<rw->limit;++i)
		if (rw->readers[i] == current) {
			rw->readers[i] = 0;

			break;
		}
	sem_post(&rw->rbl);

	sem_post(&rw->r);
}

void wlock(struct rw_lock *rw)
{
	int val;
	pid_t current = getpid();
	struct timespec to = {
		.tv_sec = 1,
		.tv_nsec = 0
	};
	time_t wfr0, wfr1;

	do {
		if (sem_timedwait(&rw->w, &to) == 0) {
			break;
		} else if (errno == ETIMEDOUT) {
			sem_wait(&rw->wbl);
			if (rw->writer && kill(rw->writer, 0) == -1 && errno == ESRCH) {
				printf("deadlock detected: process invoked wlock died(%d)\n", rw->writer), fflush(NULL);
				rw->writer = 0;
				sem_post(&rw->w);
			}
			sem_post(&rw->wbl);
		}
	} while (1);
	sem_wait(&rw->wbl);
	rw->writer = current;
	sem_post(&rw->wbl);

	wfr0 = time(NULL);
	do {
		wfr1 = time(NULL);
		if ((wfr1 - wfr0) > 1) {
			int i;
			sem_wait(&rw->rbl);
			for (i=0;rw->limit;++i)
				if (rw->readers[i] && kill(rw->readers[i], 0) == -1 && errno == ESRCH) {
					printf("deadlock detected: process invoked rlock died(%d)\n", rw->readers[i]), fflush(NULL);
					rw->readers[i] = 0;
					sem_post(&rw->r);

					break;
				}
			sem_post(&rw->rbl);
			wfr0 = wfr1;
		}

		sem_getvalue(&rw->r, &val);

	} while (val != rw->limit);
}

void wunlock(struct rw_lock *rw)
{
	sem_wait(&rw->wbl);
	rw->writer = 0;
	sem_post(&rw->wbl);

	sem_post(&rw->w);
}

void reader(void)
{
	while (1) {
		rlock(rw);
		if (*counter == 1024*4) {
			runlock(rw);
			break;
		}
		if (*counter !=0 && *counter%1024 == 0) {
			printf("reader died(counter: %d, pid: %d)\n", *counter,getpid()), fflush(NULL);
			*(int *)0 = 0;
		}
		runlock(rw);
	}
}

void writer(void)
{
	while (1) {
		wlock(rw);
		if (*counter == 2048*2) {
			wunlock(rw);
			break;
		}
		++*counter;
		if (*counter !=0 && *counter%2048 == 0) {
			printf("writer died(counter: %d, pid: %d)\n", *counter, getpid()), fflush(NULL);
			*(int *)0 = 0;
		}
		wunlock(rw);
	}
}

int main(int argc, char **argv)
{
	int i;

	counter = mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

	init_rwlock(&rw, 5);

	for (i=0;i<10;++i)
		if (fork() == 0) {
			reader();

			return 0;
		}

	for (i=0;i<5;++i)
		if (fork() == 0) {
			writer();

			return 0;
		}

	for (i=0;i<15;++i)
		wait(NULL);

	printf("counter: %d\n", *counter);

	return 0;
}

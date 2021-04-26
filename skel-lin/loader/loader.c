/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "exec_parser.h"

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);					\
		}							\
	} while (0)

#define FILE_MAPPED 0x01
#define MEMM_MAPPED 0x02

static so_exec_t *exec;


static int page_size;
static struct sigaction old_action;
static int fd;

int get_page_from_addr(uintptr_t seg_base_addr, uintptr_t addr)
{
	return (addr - seg_base_addr) / page_size;
}

void *page_alligned_addr(void *addr)
{
	char *p = addr;

	return (void *) (((p - (char *)0) / page_size) * page_size);
}

int no_of_pages(so_seg_t *segment)
{
	return segment->mem_size / page_size;
}

void init_data(so_seg_t *segment)
{
	int i = 0;

	if (segment->data)
		return;

	i = no_of_pages(segment);

	segment->data = calloc(i, sizeof(char));
}


int do_segment(so_seg_t *crt_segment, uintptr_t addr)
{
	uintptr_t segment_start;
	uintptr_t segment_file_end;

	uintptr_t page_start;
	uintptr_t page_end;

	void *mmap_ret = MAP_FAILED;

	int page_number;

	segment_start = crt_segment->vaddr;
	segment_file_end = segment_start + crt_segment->file_size;

	page_number = get_page_from_addr(segment_start, addr);

	page_start = segment_start + page_number * page_size;
	page_end = page_start + page_size;

	// 4 cases:
	//	full file page
	//	part file page
	//	part memm page
	//	full memm page

	if (page_end <= segment_file_end) {
		// full file page case

		if (((char *)crt_segment->data)[page_number] & FILE_MAPPED)
			return 1;

		mmap_ret = mmap((void *)page_start,
				page_size,
				crt_segment->perm,
				MAP_PRIVATE | MAP_FIXED,
				fd,
				crt_segment->offset +
				page_number *
				page_size);
		DIE(mmap_ret == MAP_FAILED, "full file page mmap failed");

		((char *)crt_segment->data)[page_number] |= FILE_MAPPED;

	} else if (page_start < segment_file_end &&
		segment_file_end <= page_end) {

		if (((char *)crt_segment->data)[page_number] & FILE_MAPPED)
			return 1;

		mmap_ret = mmap((void *)page_start,
				segment_file_end - page_start,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED,
				fd,
				crt_segment->offset +
				page_number *
				page_size);

		DIE(mmap_ret == MAP_FAILED, "part file page mmap failed");

		memset((void *)segment_file_end, 0,
			page_end - segment_file_end);

		mprotect((void *)page_start, page_size, crt_segment->perm);

		((char *)crt_segment->data)[page_number] |= FILE_MAPPED;

	} else {
		// full memm page

		if (((char *)crt_segment->data)[page_number] & MEMM_MAPPED)
			return 1;

		mmap_ret = mmap((void *)page_start,
				page_size,
				crt_segment->perm,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
				-1,
				0);

		DIE(mmap_ret == MAP_FAILED, "full memm page mmap failed");

		((char *)crt_segment->data)[page_number] |= MEMM_MAPPED;
	}

	return 0;
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	uintptr_t addr;
	uintptr_t segment_start;
	uintptr_t segment_end;
	so_seg_t *crt_segment;
	int i;

	addr = (uintptr_t) info->si_addr;

	for (i = 0; i < exec->segments_no; i++) {
		crt_segment = exec->segments + i;
		segment_start = crt_segment->vaddr;
		segment_end = segment_start + crt_segment->mem_size;

		if (!crt_segment->data)
			init_data(crt_segment);

		if (addr >= segment_start && addr < segment_end) {
			if (do_segment(crt_segment, addr))
				old_action.sa_sigaction(signum, info, context);

			return;
		}

	}
	old_action.sa_sigaction(signum, info, context);
}

static void set_signal(void)
{
	struct sigaction action;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	sigaction(SIGSEGV, &action, &old_action);
}

int so_init_loader(void)
{
	/* TODO: initialize on-demand loader */
	page_size = getpagesize();
	set_signal();

	return 0;
}




int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	so_start_exec(exec, argv);
	close(fd);

	return -1;
}

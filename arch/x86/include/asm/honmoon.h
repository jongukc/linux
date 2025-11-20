#ifndef _ASM_X86_HONMOON_H
#define _ASM_X86_HONMOON_H

#include <linux/init.h>
#include <linux/kvm_para.h>

#define KVM_HC_HOONMOON_LOCK 0x6000

void honmoon_lock(void);

static inline long hypercall_honmoon_lock(unsigned long hlat_root_gpa)
{
	return kvm_hypercall1(KVM_HC_HOONMOON_LOCK, hlat_root_gpa);
}

#endif /* _ASM_X86_HONMOON_H */
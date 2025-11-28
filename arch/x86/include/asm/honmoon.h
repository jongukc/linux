#ifndef _ASM_X86_HONMOON_H
#define _ASM_X86_HONMOON_H

#include <linux/init.h>
#include <linux/kvm_para.h>

#define KVM_HC_HOONMOON_LOCK 0x100

bool is_honmoon_enabled(void);
void honmoon_activate(void);
int honmoon_test_remap_1(void);
int honmoon_test_remap_2(void);
int honmoon_test_alias(void);

static inline long hypercall_set_hlatp(unsigned long hlat_root_gpa)
{
	return kvm_hypercall1(KVM_HC_HOONMOON_LOCK, hlat_root_gpa);
}

#endif /* _ASM_X86_HONMOON_H */
#define pr_fmt(fmt) "kvm-vmx-honmoon: " fmt

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/vmx.h>
#include <asm/page.h>
#include <mmu/spte.h>
#include "vmx.h"

#define HLAT_RESTART_BIT BIT_ULL(11)
#define HLAT_PRESENT_BIT BIT_ULL(0)

#define SPTE_PHYS_MASK ((BIT_ULL(52) - 1) & PAGE_MASK)

bool __read_mostly enable_honmoon = 1;
module_param_named(honmoon, enable_honmoon, bool, 0444);

u64 *honmoon_get_ept_leaf(struct kvm_vcpu *vcpu, gpa_t gpa, bool split)
{
	hpa_t root_hpa = vcpu->arch.mmu->root.hpa;
	u64 *sptep;
	int level;
	u64 spte;

	if (!VALID_PAGE(root_hpa))
		return NULL;

	if (!pfn_valid(root_hpa >> PAGE_SHIFT)) {
		pr_err_ratelimited("Invalid root HPA: %llx\n", root_hpa);
		return NULL;
	}

	sptep = (u64 *)__va(root_hpa);
	level = vcpu->arch.mmu->root_role.level;

	for (; level > 1; --level) {
		int index = (gpa >> (12 + (level - 1) * 9)) & 0x1FF;
		sptep = &sptep[index];
		spte = *sptep;

		if (!(spte & 0x7))
			return NULL;

		if (spte & (1ULL << 7)) {
			if (!split)
				return sptep;

			/* Split huge pages */
			u64 *new_table;
			struct page *page;
			int i;
			u64 huge_pfn;
			u64 new_table_pa;
			u64 pages_per_child;

			page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
			if (!page) {
				pr_err("Failed to allocate page for splitting huge page\n");
				return NULL;
			}
			new_table = page_address(page);
			new_table_pa = __pa(new_table);

			huge_pfn = (spte & SPTE_PHYS_MASK) >> PAGE_SHIFT;
			pages_per_child = 1ULL << ((level - 2) * 9);

			for (i = 0; i < 512; i++) {
				u64 child_spte = spte;

				if (level == 2)
					child_spte &= ~(1ULL << 7);

				child_spte &= ~SPTE_PHYS_MASK;
				child_spte |= ((huge_pfn + i * pages_per_child)
					       << PAGE_SHIFT) &
					      SPTE_PHYS_MASK;

				new_table[i] = child_spte;
			}

			*sptep = new_table_pa | 0x7;

			sptep = new_table;
			continue;
		}

		u64 next_hpa = spte & SPTE_PHYS_MASK;
		if (!pfn_valid(next_hpa >> PAGE_SHIFT))
			return NULL;

		sptep = (u64 *)__va(next_hpa);
	}

	int index = (gpa >> 12) & 0x1FF;
	return &sptep[index];
}

static void honmoon_update_ept(struct kvm_vcpu *vcpu, gpa_t gpa, u64 set_bits,
			       u64 clear_bits)
{
	write_lock(&vcpu->kvm->mmu_lock);
	u64 *sptep = honmoon_get_ept_leaf(vcpu, gpa, true);
	if (sptep) {
		u64 spte = *sptep;
		spte &= ~clear_bits;
		spte |= set_bits;
		WRITE_ONCE(*sptep, spte);
	} else {
		pr_err("Failed to find EPT entry for GPA %llx\n", gpa);
	}
	write_unlock(&vcpu->kvm->mmu_lock);
}

static void honmoon_protect_hlat(struct kvm_vcpu *vcpu, gpa_t table_gpa,
				 int level)
{
	int i;
	struct kvm *kvm = vcpu->kvm;

	for (i = 0; i < 512; i++) {
		u64 entry;

		if (kvm_read_guest(kvm, table_gpa + i * sizeof(u64), &entry,
				   sizeof(entry))) {
			pr_err("Failed to read HLAT entry at %llx\n",
			       table_gpa + i * sizeof(u64));
			continue;
		}

		if (!(entry & HLAT_PRESENT_BIT))
			continue;
		if (entry & HLAT_RESTART_BIT)
			continue;

		gpa_t child_gpa = entry & SPTE_PHYS_MASK;

		if (level > 1 && (entry & (1ULL << 7))) {
			unsigned long pages = 1UL << ((level - 1) * 9);
			unsigned long k;

			for (k = 0; k < pages; k++) {
				gpa_t target = child_gpa + k * PAGE_SIZE;

				kvm_mmu_page_fault(vcpu, target,
						   PFERR_WRITE_MASK, NULL, 0);
			}

			for (k = 0; k < pages; k++) {
				gpa_t target = child_gpa + k * PAGE_SIZE;

				honmoon_update_ept(vcpu, target, EPT_SPTE_VPW,
						   VMX_EPT_WRITABLE_MASK);
			}
			continue;
		}

		kvm_mmu_page_fault(vcpu, child_gpa, PFERR_WRITE_MASK, NULL, 0);

		if (level > 1) {
			honmoon_protect_hlat(vcpu, child_gpa, level - 1);
			honmoon_update_ept(vcpu, table_gpa, EPT_SPTE_PW,
					   VMX_EPT_WRITABLE_MASK);
		} else {
			honmoon_update_ept(vcpu, child_gpa, EPT_SPTE_VPW,
					   VMX_EPT_WRITABLE_MASK);
		}
	}
}

long vmx_handle_honmoon_activate(struct kvm_vcpu *vcpu,
				 unsigned long hlat_root_gpa)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
	u32 tertiary_exec;
	int ret, level;

	if (vmx->honmoon_activated) {
		kvm_queue_exception(vcpu, X86_TRAP_VE);
		return -EPERM;
	}

	tertiary_exec = vmcs_read64(TERTIARY_VM_EXEC_CONTROL);
	if (tertiary_exec & TERTIARY_EXEC_ENABLE_HLAT)
		return -EPERM;

	pr_info("Hypercall in VCPU %d, HLAT Root: %lx\n", vcpu->vcpu_id,
		hlat_root_gpa);

	if (kvm_read_cr4_bits(vcpu, X86_CR4_LA57))
		level = 5;
	else
		level = 4;

	honmoon_protect_hlat(vcpu, hlat_root_gpa, level);

	struct kvm_host_map map;
	ret = kvm_vcpu_map(vcpu, hlat_root_gpa >> PAGE_SHIFT, &map);
	if (ret) {
		pr_err("Failed to map HLAT root GPA: %lx (%d)\n", hlat_root_gpa,
		       ret);
		return -EINVAL;
	}

	/* Ensure alignment */
	if (hlat_root_gpa & ~PAGE_MASK) {
		pr_err("HLAT root GPA not aligned: %lx\n", hlat_root_gpa);
		kvm_vcpu_unmap(vcpu, &map);
		return -EINVAL;
	}

	/* Note: We are holding a reference to the page (pinning it) via kvm_vcpu_map.
	 * We intentionally do NOT call kvm_vcpu_unmap() here to ensure the PFN remains
	 * valid for the VMCS HLAT_POINTER.
	 * TODO: Properly track and unmap this when the VCPU is destroyed or
	 * HLAT disabled.
	 */
	// kvm_release_page_clean(page);

	kvm_flush_remote_tlbs(vcpu->kvm);

	vmx->honmoon_activated = true;
	mutex_lock(&vcpu->kvm->lock);
	if (!kvm_vmx->honmoon_activated_global) {
		kvm_vmx->honmoon_activated_global = true;
		kvm_vmx->hlat_root_gpa = hlat_root_gpa;
	}
	mutex_unlock(&vcpu->kvm->lock);

	tertiary_exec_controls_setbit(vmx, TERTIARY_EXEC_ENABLE_HLAT);
	tertiary_exec_controls_setbit(vmx, TERTIARY_EXEC_EPT_PW);
	tertiary_exec_controls_setbit(vmx, TERTIARY_EXEC_GPV);

	vmcs_write64(HLAT_POINTER, hlat_root_gpa);
	vmcs_write16(HLAT_PLR_PREFIX_SIZE, 1);

	pr_info("HLAT enabled for VCPU %d\n", vcpu->vcpu_id);

	return 0;
}

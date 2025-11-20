#define pr_fmt(fmt) "Honmoon-guest: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/honmoon.h>

#define HLAT_RESTART_BIT (1UL << 11)
#define HLAT_PRESENT (1UL << 0)
#define HLAT_RW (1UL << 1)
#define HLAT_USER (1UL << 2)
#define HLAT_XD (1UL << 63)

static void *alloc_hlat_page(void)
{
	return (void *)get_zeroed_page(GFP_KERNEL);
}

static void hlat_map_page(unsigned long *pml4, unsigned long va,
			  unsigned long pa, unsigned long flags)
{
	unsigned long pml4_idx = pgd_index(va);
	unsigned long pdpt_idx = pud_index(va);
	unsigned long pd_idx = pmd_index(va);
	unsigned long pt_idx = pte_index(va);

	unsigned long *pdpt, *pd, *pt;

	if (!(pml4[pml4_idx] & HLAT_PRESENT)) {
		pdpt = alloc_hlat_page();
		pml4[pml4_idx] = __pa(pdpt) | HLAT_PRESENT | HLAT_RW |
				 HLAT_USER;
	}
	pdpt = __va(pml4[pml4_idx] & PAGE_MASK);

	if (!(pdpt[pdpt_idx] & HLAT_PRESENT)) {
		pd = alloc_hlat_page();
		pdpt[pdpt_idx] = __pa(pd) | HLAT_PRESENT | HLAT_RW | HLAT_USER;
	}
	pd = __va(pdpt[pdpt_idx] & PAGE_MASK);

	if (!(pd[pd_idx] & HLAT_PRESENT)) {
		pt = alloc_hlat_page();
		pd[pd_idx] = __pa(pt) | HLAT_PRESENT | HLAT_RW | HLAT_USER;
	}
	pt = __va(pd[pd_idx] & PAGE_MASK);

	pt[pt_idx] = pa | flags;
}

void honmoon_lock(void)
{
	unsigned long *hlat_root;
	unsigned long addr, ret;
	int i;

	if (!kvm_para_available()) {
		pr_info("Not running on KVM.\n");
		return;
	}

	hlat_root = alloc_hlat_page();
	if (!hlat_root)
		return;

	for (i = 0; i < 512; i++) {
		hlat_root[i] = HLAT_RESTART_BIT | HLAT_PRESENT | HLAT_RW |
			       HLAT_USER;
	}

	pr_info("Building HLAT for text range: %lx - %lx\n",
		(unsigned long)_text, (unsigned long)_etext);

	for (addr = (unsigned long)_text; addr < (unsigned long)_etext;
	     addr += PAGE_SIZE) {
		phys_addr_t pa = __pa_symbol(addr);
		unsigned long direct_map_va = (unsigned long)__va(pa);

		/* Kernel text region */
		hlat_map_page(hlat_root, addr, pa, HLAT_PRESENT | HLAT_USER);

		/* Direct mapping region */
		hlat_map_page(hlat_root, direct_map_va, pa,
			      HLAT_PRESENT | HLAT_USER | HLAT_XD);
	}

  /* Hypercall invocation */
	pr_info("Invoking Hypercall with HLAT Root GPA: %lx\n",
		__pa(hlat_root));
	ret = hypercall_honmoon_lock(__pa(hlat_root));
	if (ret) {
		pr_err("HLAT Lock Code Mappings Hypercall failed: %lx\n", ret);
	} else {
		pr_info("HLAT successfully enabled for code pages.\n");
	}
}
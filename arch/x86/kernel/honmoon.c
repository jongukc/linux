#define pr_fmt(fmt) "honmoon-guest: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/kvm_para.h>
#include <asm/honmoon.h>
#include <asm/pgtable.h>

#define HLAT_RESTART (1UL << 11)
#define HLAT_PRESENT (1UL << 0)
#define HLAT_RW (1UL << 1)
#define HLAT_USER (1UL << 2)
#define HLAT_ACCESSED (1UL << 5)
#define HLAT_DIRTY (1UL << 6)
#define HLAT_XD (1UL << 63)

static bool honmoon_enabled;

static void *make_hlat_page(void)
{
	void *root = (void *)get_zeroed_page(GFP_KERNEL);
	int i;

	if (!root)
		pr_err("Failed to allocate HLAT root page.\n");

	/* Initialize page entries (all present, all restart) */
	for (i = 0; i < 512; i++) {
		((unsigned long *)root)[i] = HLAT_PRESENT | HLAT_RESTART;
	}

	return root;
}

static void hlat_map_page(unsigned long *hlat_root, unsigned long va,
			  unsigned long pa, int target_level,
			  unsigned long prot)
{
	unsigned long *pdpt, *pd, *pt;
	unsigned long pml4_idx = pgd_index(va);
	unsigned long pdpt_idx = pud_index(va);
	unsigned long pd_idx = pmd_index(va);
	unsigned long pt_idx = pte_index(va);

	/* Level 4: PML4 */
	if (hlat_root[pml4_idx] & HLAT_RESTART) {
		pdpt = make_hlat_page();
		hlat_root[pml4_idx] = __pa(pdpt) | HLAT_PRESENT | HLAT_RW |
				      HLAT_USER;
	} else {
		pdpt = __va(hlat_root[pml4_idx] & PTE_PFN_MASK);
	}

	if (target_level == 4)
		return;

	/* Level 3: PDPT */
	if (target_level == 3) {
		pdpt[pdpt_idx] = pa | prot | HLAT_PRESENT | _PAGE_PSE;
		return;
	}

	if (pdpt[pdpt_idx] & HLAT_RESTART) {
		pd = make_hlat_page();
		pdpt[pdpt_idx] = __pa(pd) | HLAT_PRESENT | HLAT_RW | HLAT_USER;
	} else {
		pd = __va(pdpt[pdpt_idx] & PTE_PFN_MASK);
	}

	/* Level 2: PD */
	if (target_level == 2) {
		pd[pd_idx] = pa | prot | HLAT_PRESENT | _PAGE_PSE;
		return;
	}

	if (pd[pd_idx] & HLAT_RESTART) {
		pt = make_hlat_page();
		pd[pd_idx] = __pa(pt) | HLAT_PRESENT | HLAT_RW | HLAT_USER;
	} else {
		pt = __va(pd[pd_idx] & PTE_PFN_MASK);
	}

	/* Level 1: PT */
	pt[pt_idx] = pa | prot | HLAT_PRESENT;
}

static int __init honmoon_setup(char *str)
{
	if (!str || !*str) {
		// Just "honmoon" with no value means enable
		honmoon_enabled = true;
	} else if (!strcmp(str, "1") || !strcmp(str, "on") ||
		   !strcmp(str, "y")) {
		honmoon_enabled = true;
	} else if (!strcmp(str, "0") || !strcmp(str, "off") ||
		   !strcmp(str, "n")) {
		honmoon_enabled = false;
	} else {
		return 0;
	}

	pr_info("feature %s\n",
		honmoon_enabled ? "enabled" : "disabled");
	return 1;
}
__setup("honmoon=", honmoon_setup);

bool is_honmoon_enabled(void)
{
	(void)honmoon_setup;
	return honmoon_enabled;
}

void honmoon_activate(void)
{
	unsigned long *hlat_root;
	unsigned long va, step;
	unsigned long pa, prot;
	long ret;

	if (!kvm_para_available()) {
		pr_err("Not running on KVM.\n");
		return;
	}

	if (!kvm_para_has_feature(KVM_FEATURE_HONMOON)) {
		pr_err("Honmoon hypervisor not detected.\n");
		return;
	}

	pr_info("Honmoon hypervisor detected.\n");

	hlat_root = make_hlat_page();

	if (!hlat_root) {
		pr_err("Failed to allocate HLAT root.\n");
		return;
	}

	va = (unsigned long)_text;
	step = PAGE_SIZE;

	for (; va < (unsigned long)_etext; va += step) {
		unsigned int level;
		pte_t *ptep;

		ptep = lookup_address(va, &level);
		if (!ptep) {
			step = PAGE_SIZE;
			continue;
		}

		pa = pte_pfn(*ptep) << PAGE_SHIFT;
		prot = *(unsigned long *)(ptep) & PTE_FLAGS_MASK;

		/* Map Kernel Text (RX) */
		hlat_map_page(hlat_root, va, pa, level, prot);

		/* Map Direct Map Alias (R, NX) */
		hlat_map_page(hlat_root, (unsigned long)__va(pa), pa, level,
			      HLAT_PRESENT | HLAT_XD);

		if (level == PG_LEVEL_2M)
			step = PMD_SIZE;
		else if (level == PG_LEVEL_1G)
			step = PUD_SIZE;
		else
			step = PAGE_SIZE;
	}

	/* Hypercall invocation */
	pr_info("Invoking Hypercall with HLAT Root GPA: %lx\n",
		__pa(hlat_root));
	ret = hypercall_set_hlatp(__pa(hlat_root));
	if (ret) {
		pr_err("HLAT Lock Hypercall failed: %ld\n", ret);
	} else {
		pr_info("HLAT successfully enabled.\n");
	}
}

/* Functions for testing page remapping & aliasing attacks */
int __attribute__((section(".text.honmoon_test_remap_1"), aligned(PAGE_SIZE))) honmoon_test_remap_1(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(honmoon_test_remap_1);

int __attribute__((section(".text.honmoon_test_remap_2"), aligned(PAGE_SIZE))) honmoon_test_remap_2(void)
{
	return 1;
}
EXPORT_SYMBOL_GPL(honmoon_test_remap_2);

int __attribute__((section(".text.honmoon_test_alias"), aligned(PAGE_SIZE))) honmoon_test_alias(void)
{
	return 2;
}
EXPORT_SYMBOL_GPL(honmoon_test_alias);

/*
 *  linux/mm/memory.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

/*
 * 05.04.94  -  Multi-page memory management added for v1.1.
 * 		Idea by Alex Bligh (alex@cconcepts.co.uk)
 *
 * 16.07.99  -  Support of BIGMEM added by Gerhard Wichert, Siemens AG
 *		(Gerhard.Wichert@pdb.siemens.de)
 */

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/swapctl.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>

unsigned long max_mapnr;
/*zyq:
 内存映射数组。管理区描述符的zone_mem_map指向它的一个元素。
 用于伙伴系统。
 */
unsigned long num_physpages;
/*zyq:
 高端内存的起始地址，被设置成896MB.
 */
void * high_memory;
struct page *highmem_start_page;

/*
 * We special-case the C-O-W ZERO_PAGE, because it's such
 * a common occurrence (no need to read the page to know
 * that it's zero - better for the cache and memory subsystem).
 */
static inline void copy_cow_page(struct page * from, struct page * to, unsigned long address)
{
	if (from == ZERO_PAGE(address)) {	// 如果是全零界面（即之前由于读访问引发缺页异常，会指向一个全零界面）
		clear_user_highpage(to, address);	// 对内容进行清理 
		return;
	}
	copy_user_highpage(to, from, address);	// 将原有页面的内容复制到新页面中
}

mem_map_t * mem_map;//mem_map数组 用于保存每个物理页面的信息

/*
 * Called by TLB shootdown 
 */
/*zyq:
 释放一个页表项
 */
void __free_pte(pte_t pte)
{
	struct page *page = pte_page(pte);//虚存页page不在内存中，或为系统的保留内存
	if ((!VALID_PAGE(page)) || PageReserved(page))
		return;//无效的页表项，直接返回
	if (pte_dirty(pte))//如果pet是一个脏页表项
		set_page_dirty(page);//	将page设置为一个脏页面		
	free_page_and_swap_cache(page);//释放page的物理地址并交换缓存
}


/*
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
 /*zyq:
 释放二级页目录项和对应的页表、页表项
 */
static inline void free_one_pmd(pmd_t * dir)
{
	pte_t * pte;

	if (pmd_none(*dir))//无效的页表项
		return;
	if (pmd_bad(*dir)) {//如果dir是一个“坏”页表项
		pmd_ERROR(*dir);//二级页目录项错误
		pmd_clear(dir);//清除页目录项内容
		return;
	}
	pte = pte_offset(dir, 0);// 得到整个页表的首地址，也是第一个页表项的地址 
	pmd_clear(dir);// 清除页目录项内容
	pte_free(pte);//释放页表，这时候会回收物理地址，因为没人使用了
}

/*zyq:
释放三级页目录项和相应的页表、页表项
*/
static inline void free_one_pgd(pgd_t * dir)
{
	int j;
	pmd_t * pmd;

	if (pgd_none(*dir))//如果是无效的页表项
		return;//直接返回
	if (pgd_bad(*dir)) {//如果dir是一个“坏”页表项
		pgd_ERROR(*dir);//三级页目录项错误
		pgd_clear(dir);//清除页目录项内容
		return;//返回
	}
	pmd = pmd_offset(dir, 0);// 取得pgd里保存的二级目录表首地址
	pgd_clear(dir);// 清空pgd的内容
	for (j = 0; j < PTRS_PER_PMD ; j++) {  
		prefetchw(pmd+j+(PREFETCH_STRIDE/16));
		free_one_pmd(pmd+j);
	}  // 没有进程使用了，释放每一个二级目录表、目录表保存的页表、页表项
	pmd_free(pmd);// 页目录表引用数减一
}

/* Low and high watermarks for page table cache.
   The system should try to have pgt_water[0] <= cache elements <= pgt_water[1]
 */
int pgt_cache_water[2] = { 25, 50 };//页表缓存边界25-50

/* Returns the number of pages freed */
int check_pgt_cache(void)
{
	return do_check_pgt_cache(pgt_cache_water[0], pgt_cache_water[1]);
}


/*
 * This function clears all user-level page tables of a process - this
 * is needed by execve(), so that old pages aren't in the way.
 */
 /*zyq:
 此函数清除进程的所有用户级页表
 */
void clear_page_tables(struct mm_struct *mm, unsigned long first, int nr)
{
	pgd_t * page_dir = mm->pgd;
    //释放从first开始到first+nr之间的所有三级页目录项和相应的页表、页表项
	spin_lock(&mm->page_table_lock);//上锁（对页表操作的自旋锁）
	page_dir += first;
	do {
		free_one_pgd(page_dir);// 释放三级页目录项和相应的页表、页表项
		page_dir++;
	} while (--nr);//nr=nr-，nr>0时执行do操作
	spin_unlock(&mm->page_table_lock);//开锁（对页表操作的自旋锁）

	/* keep the page table cache within bounds 将页表高速缓存保持在边界内*/
	check_pgt_cache();
}

#define PTE_TABLE_MASK	((PTRS_PER_PTE-1) * sizeof(pte_t))
#define PMD_TABLE_MASK	((PTRS_PER_PMD-1) * sizeof(pmd_t))

/*
 * copy one vm_area from one task to the other. Assumes the page tables
 * already present in the new task to be cleared in the whole range
 * covered by this vma.
 *
 * 08Jan98 Merged into one routine from several inline routines to reduce
 *         variable count and make things faster. -jj
 *
 * dst->page_table_lock is held on entry and exit,
 * but may be dropped within pmd_alloc() and pte_alloc().
 */
 /*zyq:
 在dump_mmap中，插入一个新的线性区描述符后，通过本过程创建必要的页表映射线性区所包含的一组页。
 并且初始化新页表的表项。
 与私有的、可写的页(VM_SHARED标志关闭，VM_MAYWRITE标志打开)所对应的任意页框都标记为对父子进程都是只读
 以便这种页框能用写时复制机制进行处理。
 */
int copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			struct vm_area_struct *vma)
{
	pgd_t * src_pgd, * dst_pgd;//三级页表项
	unsigned long address = vma->vm_start;//无符号长整型变量address=vma所指向区域的起始地址
	unsigned long end = vma->vm_end;//无符号长整型变量end=vma所指向区域的结束地址
	unsigned long cow = (vma->vm_flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;//无符号长整型变量cow

	src_pgd = pgd_offset(src, address)-1;//((src)->pgd + pgd_index(address))-1  src_pgd=src表的起始地址-1
	dst_pgd = pgd_offset(dst, address)-1;//((dst)->pgd + pgd_index(address))-1  dat_pgd=dst表的起始地址-1

	for (;;) {
		pmd_t * src_pmd, * dst_pmd;//二级页表项

		src_pgd++; dst_pgd++;//src表和dst表的起始地址
		
		/* copy_pmd_range 复制二级页目录项和对应的页表、页表项*/
		
		if (pgd_none(*src_pgd))//如果是无效的页表项，跳转执行skip_copy_pmd_range
			goto skip_copy_pmd_range;
		if (pgd_bad(*src_pgd)) {//如果src_pgd是一个“坏”页表项
			pgd_ERROR(*src_pgd);//三级页目录项错误
			pgd_clear(src_pgd);//清除页目录项内容
skip_copy_pmd_range:	address = (address + PGDIR_SIZE) & PGDIR_MASK;//调整起始线性地址
			if (!address || (address >= end))//如果起始线性地址为空或大于终止线性地址
				goto out;//跳转执行out
			continue;//否则，继续运行
		}

		src_pmd = pmd_offset(src_pgd, address);//((src_pgd)->pgd + pgd_index(address)) src_pmd=src_pgd表的起始地址
		dst_pmd = pmd_alloc(dst, dst_pgd, address);//dst_pmd=dst_pgd表的起始地址
		if (!dst_pmd)//如果非dst_pmd为空
			goto nomem;//跳转执行nomem
        //否则
		do {
			pte_t * src_pte, * dst_pte;//一级页表项
		
			/* copy_pte_range 复制三级页目录项和对应的页表、页表项*/
		
			if (pmd_none(*src_pmd))//如果是无效的页表项，跳转执行skip_copy_pte_range
				goto skip_copy_pte_range;
			if (pmd_bad(*src_pmd)) {//如果src_pmd是一个“坏”页表项
				pmd_ERROR(*src_pmd);//二级页目录项错误
				pmd_clear(src_pmd);//清除页目录项内容
skip_copy_pte_range:		address = (address + PMD_SIZE) & PMD_MASK;//调整起始线性地址
				if (address >= end)//如果起始线性地址大于终止线性地址
					goto out;//跳转执行out
				goto cont_copy_pmd_range;//否则跳转执行cont_copy_pmd_range
			}

			src_pte = pte_offset(src_pmd, address);//src_pte=src_pmd的起始地址
			dst_pte = pte_alloc(dst, dst_pmd, address);//dst_pte=dst_pmd的起始地址
			if (!dst_pte)//如果非dst_pte为空
				goto nomem;//跳转执行nomem

			spin_lock(&src->page_table_lock);//上锁（对页表操作的自旋锁）			
			do {
				pte_t pte = *src_pte;
				struct page *ptepage;
				
				/* copy_one_pte 复制一个页表项*/

				if (pte_none(pte))//如果是无效的页表项，跳转执行cont_copy_pte_range_noset
					goto cont_copy_pte_range_noset;
				if (!pte_present(pte)) {//如果页表项没有映射到物理页
					swap_duplicate(pte_to_swp_entry(pte));//将参考条目的引用计数增加 1
					goto cont_copy_pte_range;//跳转执行cont_copy_pte_range
				}
				ptepage = pte_page(pte);
				if ((!VALID_PAGE(ptepage)) || PageReserved(ptepage))//虚存页ptepage不在内存中，或为系统的保留内存
					goto cont_copy_pte_range;//跳转执行cont_copy_pte_range

				/* If it's a COW mapping, write protect it both in the parent and the child 
				   如果是 COW 映射，请在父级和子项中对其进行写保护*/
				if (cow && pte_write(pte)) {//如果是cow映射并且页有写保护
					ptep_set_wrprotect(src_pte);//将父进程的页表项修改为只读
					pte = *src_pte;
				}

				/* If it's a shared mapping, mark it clean in the child 
				   如果是共享映射，请在子映射中将其标记为干净*/
				if (vma->vm_flags & VM_SHARED)//如果是共享映射
					pte = pte_mkclean(pte);//在子映射中将其标记为干净
				pte = pte_mkold(pte);//子映射标记值
				get_page(ptepage);//返回页面内容
				dst->rss++;//dst->rss自加1

cont_copy_pte_range:		set_pte(dst_pte, pte);//将pte写入dst_pte所指的页表项中
cont_copy_pte_range_noset:	address += PAGE_SIZE;//调整起始线性地址
				if (address >= end)//如果起始线性地址大于终止线性地址
					goto out_unlock;//跳转执行out_unlock
				src_pte++;
				dst_pte++;
			} while ((unsigned long)src_pte & PTE_TABLE_MASK);
			spin_unlock(&src->page_table_lock);//开锁（对页表操作的自旋锁）
		
cont_copy_pmd_range:	src_pmd++;
			dst_pmd++;
		} while ((unsigned long)src_pmd & PMD_TABLE_MASK);
	}
out_unlock:
	spin_unlock(&src->page_table_lock);//开锁（对页表操作的自旋锁）
out:
	return 0;//返回0
nomem:
	return -ENOMEM;//返回错误
}

/*
 * Return indicates whether a page was freed so caller can adjust rss
 */
 /*zyq:
 释放页表项对应虚拟地址的物理页
 */
static inline void forget_pte(pte_t page)
{
	if (!pte_none(page)) {
		printk("forget_pte: old mapping existed!\n");
		BUG();
	}
}

/*zyq:
在pmd中从虚拟地址address开始，
长度为size的内存块通过循环调用pte_clear将其页表项清零，
调用free_pte将所含空间中的物理内存或交换空间中的虚存页释放掉。
在释放之前，必须检查从address开始长度为size的内存块有无越过PMD_SIZE.
(溢出则可使指针逃出0～1023的区间)。
*/
static inline int zap_pte_range(mmu_gather_t *tlb, pmd_t * pmd, unsigned long address, unsigned long size)
{
	unsigned long offset;
	pte_t * ptep;
	int freed = 0;

	if (pmd_none(*pmd))//如果是无效的页表项
		return 0;//返回0
	if (pmd_bad(*pmd)) {//如果pmd是一个“坏”页表项
		pmd_ERROR(*pmd);//二级页目录项错误
		pmd_clear(pmd);//清除页目录项内容
		return 0;//返回0
	}
	ptep = pte_offset(pmd, address);// 取得address对应的页表项首地址,address是虚拟内存，里面保存了该页表项的偏移
	offset = address & ~PMD_MASK;// 取得物理页内偏移
	if (offset + size > PMD_SIZE)// 是否超出了该页目录项管理的内存大小
		size = PMD_SIZE - offset;
	size &= PAGE_MASK;// 屏蔽高位  
	for (offset=0; offset < size; ptep++, offset += PAGE_SIZE) {//不超过页目录项管理的内存大小
		pte_t pte = *ptep;// 页表项内容
		if (pte_none(pte))//如果是无效的页表项
			continue;//继续
		if (pte_present(pte)) {//如果页表项映射到物理页
			struct page *page = pte_page(pte);
			if (VALID_PAGE(page) && !PageReserved(page))//虚存页page在内存中，且不为系统的保留内存
				freed ++;//freed++
			/* This will eventually call __free_pte on the pte. 这最终将在 pte 上调用__free_pte。 */
			tlb_remove_page(tlb, ptep, address + offset);
		} else {//否则
			free_swap_and_cache(pte_to_swp_entry(pte));//释放pte的物理地址并交换缓存
			pte_clear(ptep);//清除页目录项内容
		}
	}

	return freed;
}

/*zyq:
函数结构与zap_pte_range类似，
通过调用zap_pte_range完成对所有落在address到address+size区间中的所有pte的清零工作。
zap_pmd_range至多清除4M空间的物理内存。
*/
static inline int zap_pmd_range(mmu_gather_t *tlb, pgd_t * dir, unsigned long address, unsigned long size)
{
	pmd_t * pmd;
	unsigned long end;
	int freed;

	if (pgd_none(*dir))//如果是无效的页表项
		return 0;//返回0
	if (pgd_bad(*dir)) {//如果pmd是一个“坏”页表项
		pgd_ERROR(*dir);//三级页目录项错误
		pgd_clear(dir);//清除页目录项内容
		return 0;//返回0
	}
	pmd = pmd_offset(dir, address);// 取得address对应的页表项首地址
	end = address + size;// 物理地址的结束地址
	if (end > ((address + PGDIR_SIZE) & PGDIR_MASK))//如果结束地址大于物理页内偏移
		end = ((address + PGDIR_SIZE) & PGDIR_MASK);//结束地址大于物理页内偏移
	freed = 0;
	do {
		freed += zap_pte_range(tlb, pmd, address, end - address);//// 重新设置一个页目录项的内容和释放物理页
		address = (address + PMD_SIZE) & PMD_MASK; //物理页内偏移
		pmd++;
	} while (address < end);//address<结束地址
	return freed;
}

/*
 * remove user pages in a given range.
 */
 /*zyq:
 将任务从address开始到address+size长度内的所有对应的pmd都清零。
 zap_page_range的主要功能是在进行内存收缩、释放内存、退出虚存映射或移动页表的过程中，
 将不在使用的物理内存从进程的三级页表中清除。
 （在讨论clear_page_tables时，就提到过当进程退出时，
 释放页表之前，先保证将页表对应项清零，保证在处于退出状态时，进程不占用0～3G的空间。）
 */
void zap_page_range(struct mm_struct *mm, unsigned long address, unsigned long size)
{
	mmu_gather_t *tlb;
	pgd_t * dir;
	unsigned long start = address, end = address + size;
	int freed = 0;

	dir = pgd_offset(mm, address);

	/*
	 * This is a long-lived spinlock. That's fine.
	 * There's no contention, because the page table
	 * lock only protects against kswapd anyway, and
	 * even if kswapd happened to be looking at this
	 * process we _want_ it to get stuck.
	 */
	if (address >= end)
		BUG();
	spin_lock(&mm->page_table_lock);
	flush_cache_range(mm, address, end);
	tlb = tlb_gather_mmu(mm);

	do {
		freed += zap_pmd_range(tlb, dir, address, end - address);
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));

	/* this will flush any remaining tlb entries */
	tlb_finish_mmu(tlb, start, end);

	/*
	 * Update rss for the mm_struct (not necessarily current->mm)
	 * Notice that rss is an unsigned long.
	 */
	if (mm->rss > freed)
		mm->rss -= freed;
	else
		mm->rss = 0;
	spin_unlock(&mm->page_table_lock);
}
/*
 * Do a quick page-table lookup for a single page. 
 */
/*
 zyq
得到线性地址的第一个物理页
 */
static struct page * follow_page(struct mm_struct *mm, unsigned long address, int write) 
{
	pgd_t *pgd;//三级
	pmd_t *pmd;//二级
	pte_t *ptep, pte;//一级

	pgd = pgd_offset(mm, address);// 取得address对应的mm页表项首地址
	if (pgd_none(*pgd) || pgd_bad(*pgd))//如果pgd无效或为“坏”页面，跳转执行out
		goto out;

	pmd = pmd_offset(pgd, address);// 取得address对应的pgd页表项首地址
	if (pmd_none(*pmd) || pmd_bad(*pmd))//如果pmd无效或为“坏”页面，跳转执行out
		goto out;

	ptep = pte_offset(pmd, address);// 取得address对应的pmd页表项首地址,address是虚拟内存，里面保存了该页表项的偏移
	if (!ptep)//如果ptet无内容。跳转执行out
		goto out;

	pte = *ptep;//pte等于ptep的头地址
	if (pte_present(pte)) {//如果pte页在内存中
		if (!write ||(pte_write(pte) && pte_dirty(pte)))//如果不是写操作或者(执行写操作的pte被写过)
			return pte_page(pte);//返回pte_page
	}

out:
	return 0;
}


/* 
 * Given a physical address, is there a useful struct page pointing to
 * it?  This may become more complex in the future if we start dealing
 * with IO-aperture pages in kiobufs.
 */
 /*
 zyq:
 判断得到的物理页面是否合法
 */
static inline struct page * get_page_map(struct page *page)
{
	if (!VALID_PAGE(page))
		return 0;
	return page;
}

/*
 * Please read Documentation/cachetlb.txt before using this function,
 * accessing foreign memory spaces can cause cache coherency problems.
 *
 * Accessing a VM_IO area is even more dangerous, therefore the function
 * fails if pages is != NULL and a VM_IO area is found.
 */
/*
ZYQ：
 得到用户空间缓冲区的页数组，并将其锁在内存中。这允许驱动程序随后对这些内存进行直接IO。
 tsk:指向执行IO的任务。
 mm:描述被映射地址空间的内存管理结构的指针。
 start,len:	start是用户空间缓冲区的地址(页对齐)，len是页内的缓冲区长度(页面数量)。
 write,force:如果write非零，对映射的页有写权限。force标志表示不考虑对指定内存页的保护，直接提供所请求的访问。
 pages,vmas:输出参数。如果调用成功，pages中包含了一个描述用户空间缓冲区page结构的指针列表，vmas包含了相应的VMA指针。
 返回值是实际被映射的页数。
 */
int get_user_pages(struct task_struct *tsk, struct mm_struct *mm, unsigned long start,
		int len, int write, int force, struct page **pages, struct vm_area_struct **vmas)
{
	int i;
	unsigned int flags;

	/*
	 * Require read or write permissions.
	 * If 'force' is set, we only require the "MAY" flags.
	 */
	flags = write ? (VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	flags &= force ? (VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);
	i = 0;

	/*
	找到start对应的第一个VMA
	*/
	do {
		struct vm_area_struct *	vma;

		vma = find_extend_vma(mm, start);//找到start对应的vma

		if ( !vma || (pages && vma->vm_flags & VM_IO) || !(flags & vma->vm_flags) )//没有找到，返回错误
			return i ? : -EFAULT;

		spin_lock(&mm->page_table_lock);//给页表加锁
		/*在所有页上循环，对其中每个页进行吊页处理。调用follow_page检查当前页表中是否有到物理页的映射。
		 如果没有这样的页存在，就调用handle_mm_fault。这个函数分配一个页框并根据内存描述符的vm_flags字段设置它的页表项。
		 */
		do {
			struct page *map;
			//找到没有被映射的物理页并将其映射进去。
			while (!(map = follow_page(mm, start, write))) {
				spin_unlock(&mm->page_table_lock);
				switch (handle_mm_fault(mm, vma, start, write)) {//产生缺页异常后调用handle_mm_fault（）完成对第一个页面的映射
				case 1:
					tsk->min_flt++;
					break;
				case 2:
					tsk->maj_flt++;
					break;
				case 0:
					if (i) return i;
					return -EFAULT;
				default:
					if (i) return i;
					return -ENOMEM;
				}
				spin_lock(&mm->page_table_lock);
			}
			if (pages) {
				pages[i] = get_page_map(map);//判断得到的映射的页面是否合法
				/* FIXME: call the correct function,
				 * depending on the type of the found page
				 */
				if (!pages[i])
					goto bad_page;//映射得到的物理页面不存在，去到bad_page返回错误
				page_cache_get(pages[i]);//增加物理页面的访问次数
			}
			if (vmas)
				vmas[i] = vma;//得到当前页面的VMA
			i++;
			start += PAGE_SIZE;//得到下一个页面的初始地址
			len--;//要映射的页面-1
		} while(len && start < vma->vm_end);
		spin_unlock(&mm->page_table_lock);
	} while(len);
out:
	return i;

	/*
	 * We found an invalid page in the VMA.  Release all we have
	 * so far and fail.
	 */
bad_page:
	spin_unlock(&mm->page_table_lock);
	while (i--)
		page_cache_release(pages[i]);
	i = -EFAULT;
	goto out;
}

/*
 * Force in an entire range of pages from the current process's user VA,
 * and pin them in physical memory.  
 */
#define dprintk(x...)

int map_user_kiobuf(int rw, struct kiobuf *iobuf, unsigned long va, size_t len)
{
	if (iobuf->nr_pages)//如果iobuf已被映射，返回错误-EINVAL
		return -EINVAL;

	mm = current->mm;
	dprintk ("map_user_kiobuf: begin\n");//输出提示信息
	
	pgcount = (va + len + PAGE_SIZE - 1)/PAGE_SIZE - va/PAGE_SIZE;
	/* mapping 0 bytes is not permitted 不允许映射 0 字节*/
	if (!pgcount) BUG();//如果映射0字节，Oops
	err = expand_kiobuf(iobuf, pgcount);//拓展iobuf pgcount字节
	if (err)//err不为空，返回err
		return err;

	iobuf->locked = 0;//设置为未上锁
	iobuf->offset = va & (PAGE_SIZE-1);//设置抵消
	iobuf->length = len;//设置长度
	
	/* Try to fault in all of the necessary pages 尝试在所有必要的页面中出错*/
	down_read(&mm->mmap_sem);//得到读写信号量sem
	/* rw==READ means read from disk, write into memory area rw==READ 表示从磁盘读取，写入内存区域*/
	err = get_user_pages(current, mm, va, pgcount,
			(rw==READ), 0, iobuf->maplist, NULL);//调用get_user_pages，返回值赋值给err
	up_read(&mm->mmap_sem);//释放读写信号量sem
	if (err < 0) {//如果err小于0
		unmap_kiobuf(iobuf);//调用unmap_kiobuf，取消映射 kiobuf 引用的所有页面
		dprintk ("map_user_kiobuf: end %d\n", err);//输出提示信息（异常结束）
		return err;//返回err
	}
	iobuf->nr_pages = err;
	while (pgcount--) {//pgcount>0
		/* FIXME: flush superflous for rw==READ,probably wrong function for rw==WRITE
		 * rw==READ的刷新超浮，rw==WRITE可能是错误的函数
		 */
		flush_dcache_page(iobuf->maplist[pgcount]);//将page相关的data cache内容写回到内存
	}
	dprintk ("map_user_kiobuf: end OK\n");///输出提示信息（正常结束）
	return 0;
}

/*
 * Mark all of the pages in a kiobuf as dirty 
 *
 * We need to be able to deal with short reads from disk: if an IO error
 * occurs, the number of bytes read into memory may be less than the
 * size of the kiobuf, so we have to stop marking pages dirty once the
 * requested byte count has been reached.
 */

/*zyq:
 将kiobuf中的所有页面标记为脏页
 */
void mark_dirty_kiobuf(struct kiobuf *iobuf, int bytes)
{
	int index, offset, remaining;
	struct page *page;
	
	index = iobuf->offset >> PAGE_SHIFT;
	offset = iobuf->offset & ~PAGE_MASK;
	remaining = bytes;
	if (remaining > iobuf->length)//剩余大于iobuf长度
		remaining = iobuf->length;//剩余等于iobuf长度
	
	while (remaining > 0 && index < iobuf->nr_pages) {//如果剩余大于0且指数小于页面数
		page = iobuf->maplist[index];
		
		if (!PageReserved(page))//如果不为系统保留内存
			SetPageDirty(page);//设置为z脏页

		remaining -= (PAGE_SIZE - offset);//新剩余等于原剩余减去（页面大小减抵消）
		offset = 0;//抵消等于0
		index++;//指数加一
	}
}

/*
 * Unmap all of the pages referenced by a kiobuf.  We release the pages,
 * and unlock them if they were locked. 
 */

/*zyq:
 取消映射 kiobuf 引用的所有页面。 我们释放页面，如果它们被锁定，则解锁它们。
 */
void unmap_kiobuf (struct kiobuf *iobuf) 
{
	int i;
	struct page *map;
	
	for (i = 0; i < iobuf->nr_pages; i++) {
		map = iobuf->maplist[i];
		if (map) {
			if (iobuf->locked)//如果被锁定就解锁
				UnlockPage(map);
			/* FIXME: cache flush missing for rw==READ  缺少 rw==READ 的缓存刷新
			 * FIXME: call the correct reference counting function 调用正确的引用计数函数
			 */
			page_cache_release(map);//释放页面缓存
		}
	}
	
	iobuf->nr_pages = 0;
	iobuf->locked = 0;
}



/*
 * Lock down all of the pages of a kiovec for IO.
 *
 * If any page is mapped twice in the kiovec, we return the error -EINVAL.
 *
 * The optional wait parameter causes the lock call to block until all
 * pages can be locked if set.  If wait==0, the lock operation is
 * aborted if any locked pages are found and -EAGAIN is returned.
 */

/*zyq:
 锁定 kiovec for IO 的所有页面
 */
int lock_kiovec(int nr, struct kiobuf *iovec[], int wait)
{
	struct kiobuf *iobuf;
	int i, j;
	struct page *page, **ppage;
	int doublepage = 0;
	int repeat = 0;
	
 repeat:
	
	for (i = 0; i < nr; i++) {//所有页面均执行
		iobuf = iovec[i];

		if (iobuf->locked)//如果已经被锁，继续
			continue;

		ppage = iobuf->maplist;
		for (j = 0; j < iobuf->nr_pages; ppage++, j++) {//所有页面均执行
			page = *ppage;
			if (!page)//!page，继续
				continue;
			
			if (TryLockPage(page)) {//用来尝试获取锁：成功获取则返回true；获取失败则返回false，此处为成功返回
				while (j--) {//j>0
					struct page *tmp = *--ppage;//爬个指向ppage前一个
					if (tmp)
						UnlockPage(tmp);//tmp为真，解锁
				}
				goto retry;//跳转执行retry
			}
		}
		iobuf->locked = 1;//状态改为上锁
	}

	return 0;
	
 retry:
	
	/* 
	 * We couldn't lock one of the pages.  Undo the locking so far,
	 * wait on the page we got to, and try again.  
	 */
	
	unlock_kiovec(nr, iovec);
	if (!wait)
		return -EAGAIN;
	
	/* 
	 * Did the release also unlock the page we got stuck on?
	 */
	if (!PageLocked(page)) {
		/* 
		 * If so, we may well have the page mapped twice
		 * in the IO address range.  Bad news.  Of
		 * course, it _might_ just be a coincidence,
		 * but if it happens more than once, chances
		 * are we have a double-mapped page. 
		 */
		if (++doublepage >= 3) 
			return -EINVAL;
		
		/* Try again...  */
		wait_on_page(page);
	}
	
	if (++repeat < 16)
		goto repeat;
	return -EAGAIN;
}

/*
 * Unlock all of the pages of a kiovec after IO.
 */

/*zyq:
 解锁kiovec
 */
int unlock_kiovec(int nr, struct kiobuf *iovec[])
{
	struct kiobuf *iobuf;
	int i, j;
	struct page *page, **ppage;
	
	for (i = 0; i < nr; i++) {//所有页面均执行
		iobuf = iovec[i];

		if (!iobuf->locked)//如果有锁
			continue;//继续执行
		iobuf->locked = 0;//状态改为未上锁
		
		ppage = iobuf->maplist;
		for (j = 0; j < iobuf->nr_pages; ppage++, j++) {//所有页面均执行
			page = *ppage;
			if (!page)
				continue;//!page，继续执行
			UnlockPage(page);//解锁
		}
	}
	return 0;
}

/*zyq:
 重新设置address到address+size地址范围内的页表项的内容，释放旧的物理地址
 */
static inline void zeromap_pte_range(pte_t * pte, unsigned long address,
                                     unsigned long size, pgprot_t prot)
{
	address &= ~PMD_MASK;// 屏蔽高位  
	end = address + size;// 末地址
	if (end > PMD_SIZE)// 末地址是否超过了该页目录项管理的地址范围
		end = PMD_SIZE;
	do {
		pte_t zero_pte = pte_wrprotect(mk_pte(ZERO_PAGE(address), prot));// 设置页表项的新内容
		pte_t oldpage = ptep_get_and_clear(pte);//清除pte页表项并返回前一个值
		set_pte(pte, zero_pte);//将zero_pte写入pte所指的页表项中
		forget_pte(oldpage);// 释放旧的物理页
		address += PAGE_SIZE;// 下一个页表项
		pte++;
	} while (address && (address < end));//addres不为空且小于末地址
}

static inline int zeromap_pmd_range(struct mm_struct *mm, pmd_t * pmd, unsigned long address,
                                    unsigned long size, pgprot_t prot)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		pte_t * pte = pte_alloc(mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		zeromap_pte_range(pte, address, end - address, prot);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

/*zyq:
 重新设置address到address+size地址范围内的页目录项内容，释放旧的物理页
 */
int zeromap_page_range(unsigned long address, unsigned long size, pgprot_t prot)
{
	unsigned long end;

	address &= ~PGDIR_MASK;// 屏蔽高位  
	end = address + size;// 末地址
	if (end > PGDIR_SIZE)// 末地址是否超过了该页目录项管理的地址范围
		end = PGDIR_SIZE;
	do {
		pte_t * pte = pte_alloc(mm, pmd, address);
		if (!pte)//pte为空
			return -ENOMEM;//返回-ENOMEM
		zeromap_pte_range(pte, address, end - address, prot);// 重新设置一个页目录项的内容和释放物理页
		address = (address + PMD_SIZE) & PMD_MASK;//调整起始线性地址
		pmd++;
	} while (address && (address < end));//addres不为空且小于末地址
	return 0;//返回0
}

/*
 * maps a range of physical memory into the requested pages. the old
 * mappings are removed. any references to nonexistent pages results
 * in null mappings (currently treated as "copy-on-access")
 */
/*zyq:
 把物理地址phys_addr保存到页表项中，prot为属性，size是保存连续的多页物理地址到多个页表项中
 */
static inline void remap_pte_range(pte_t * pte, unsigned long address, unsigned long size,
	unsigned long phys_addr, pgprot_t prot)
{
	unsigned long end;

	address &= ~PMD_MASK;// 取得页目录项内的地址范围
	end = address + size;// 末虚拟地址
	if (end > PMD_SIZE)//如果末虚拟地址大于pmd大小
		end = PMD_SIZE;//末虚拟地址等于pmd大小
	do {
		struct page *page;
		pte_t oldpage; // 保存旧的数据
		oldpage = ptep_get_and_clear(pte);// 清空页表项内容
       
		page = virt_to_page(__va(phys_addr));
		if ((!VALID_PAGE(page)) || PageReserved(page))//
 			set_pte(pte, mk_pte_phys(phys_addr, prot)); // 把物理地址保存到页表项
		forget_pte(oldpage);// 释放老数据
		address += PAGE_SIZE;// 下一个虚拟地址
		phys_addr += PAGE_SIZE;// 下一个物理地址
		pte++;
	} while (address && (address < end));
}

static inline int remap_pmd_range(struct mm_struct *mm, pmd_t * pmd, unsigned long address, unsigned long size,
	unsigned long phys_addr, pgprot_t prot)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	phys_addr -= address;
	do {
		pte_t * pte = pte_alloc(mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		remap_pte_range(pte, address, end - address, address + phys_addr, prot);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

/*  Note: this is only safe if the mm semaphore is held when called. */
int remap_page_range(unsigned long from, unsigned long phys_addr, unsigned long size, pgprot_t prot)
{
	int error = 0;
	pgd_t * dir;
	unsigned long beg = from;
	unsigned long end = from + size;
	struct mm_struct *mm = current->mm;

	phys_addr -= from;
	dir = pgd_offset(mm, from);
	flush_cache_range(mm, beg, end);
	if (from >= end)
		BUG();

	spin_lock(&mm->page_table_lock);
	do {
		pmd_t *pmd = pmd_alloc(mm, dir, from);
		error = -ENOMEM;
		if (!pmd)
			break;
		error = remap_pmd_range(mm, pmd, from, end - from, phys_addr + from, prot);
		if (error)
			break;
		from = (from + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (from && (from < end));
	spin_unlock(&mm->page_table_lock);
	flush_tlb_range(mm, beg, end);
	return error;
}

/*
 * Establish a new mapping:
 *  - flush the old one
 *  - update the page tables
 *  - inform the TLB about the new one
 *
 * We hold the mm semaphore for reading and vma->vm_mm->page_table_lock
 */
/*
	作用为刷新页面在页表中的存储
	分为：释放旧页面、更新页表项、
*/
static inline void establish_pte(struct vm_area_struct * vma, unsigned long address, pte_t *page_table, pte_t entry)
{
	set_pte(page_table, entry);	// 将entry的页面置入页表项中
	flush_tlb_page(vma, address);	// 删除address处的一个页面
	update_mmu_cache(vma, address, entry);	// 在MMU中加入信息，包括虚拟地址address和页pte
}

/*
 * We hold the mm semaphore for reading and vma->vm_mm->page_table_lock
 */
static inline void break_cow(struct vm_area_struct * vma, struct page * new_page, unsigned long address, 
		pte_t *page_table)
{
	flush_page_to_ram(new_page);
	flush_cache_page(vma, address);
	establish_pte(vma, address, page_table, pte_mkwrite(pte_mkdirty(mk_pte(new_page, vma->vm_page_prot))));
}

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Goto-purists beware: the only reason for goto's here is that it results
 * in better assembly code.. The "default" path will see no jumps at all.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We hold the mm semaphore and the page_table_lock on entry and exit
 * with the page_table_lock released.
 */
// 写时复制
/*
	在之前，fork的子进程是完全复制了一份父进程的信息，二者相互独立
	但是发现子进程往往想执行自己的代码，并不需要父进程的信息
	这时就会导致多重的时间、空间浪费
	写时复制的思路是父子进程先同时共享一份物理地址(虚拟地址不同)
	且给共享的地方设置只读
	如果父子其一想要写入，便会引发缺页异常(进入do_page_fault())
	最终会把要写的页复制到新的页框并标记为可写，原来的页框仍然是只读的
*/
static int do_wp_page(struct mm_struct *mm, struct vm_area_struct * vma,
	unsigned long address, pte_t *page_table, pte_t pte)
{
	/*首先确定复制是否真正需要*/
	struct page *old_page, *new_page;
	
	old_page = pte_page(pte);	// 获取当前页
	/*
		VALID_PAGE定义如下，判断页面是否在索引范围内
		# define VALID_PAGE(page)  ((page - mem_map) < max_mapnr)
	*/
	if (!VALID_PAGE(old_page))	// 判断页是否可用
		goto bad_wp_page;

	/*
		TryLockPage():
		#define TryLockPage(page)	test_and_set_bit(PG_locked, &(page)->flags)
		用于设置页面锁，如果其他进程已经锁住了页面返回false
	*/
	if (!TryLockPage(old_page)) {	
		/*
			can_share_swap_page()判断是否只有一个进程占用
			如果是，则该页应被设置为可写
		*/
		int reuse = can_share_swap_page(old_page);	
		unlock_page(old_page);
		if (reuse) {
			flush_cache_page(vma, address);	// 删除一个PAGE_SIZE大小的区间
			establish_pte(vma, address, page_table, pte_mkyoung(pte_mkdirty(pte_mkwrite(pte))));	// 可写、脏页面、减小页龄
			spin_unlock(&mm->page_table_lock);
			return 1;	/* Minor fault */	//指没有堵塞当前进程
		}
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	// 如果真的需要，把旧页框的内容复制到新页框中
	// 然后用新页框的物理地址更新页表的页表项
	// 并标记新页框为可写和脏页框
	page_cache_get(old_page);
	spin_unlock(&mm->page_table_lock);

	new_page = alloc_page(GFP_HIGHUSER);	// 新建界面
	if (!new_page)
		goto no_mem;	// 如果内存不足新建失败
	copy_cow_page(old_page,new_page,address);	// 拷贝一下界面

	/*
	 * Re-check the pte - we dropped the lock
	 */
	//因为前面打开了锁，因此需要检查一下页有没有变化
	spin_lock(&mm->page_table_lock);
	if (pte_same(*page_table, pte)) {	// 判断二者是否一样，即判断这个页是否被交换出去了
		if (PageReserved(old_page))		// 判断是否没用过此页
			++mm->rss;
		break_cow(vma, new_page, address, page_table);
		lru_cache_add(new_page);

		/* Free the old page.. */
		new_page = old_page;
	}
	spin_unlock(&mm->page_table_lock);
	page_cache_release(new_page);
	page_cache_release(old_page);
	return 1;	/* Minor fault */

bad_wp_page:
	spin_unlock(&mm->page_table_lock);
	printk("do_wp_page: bogus page at address %08lx (page 0x%lx)\n",address,(unsigned long)old_page);
	return -1;
no_mem:
	page_cache_release(old_page);
	return -1;
}

/*zyq:
*/
static void vmtruncate_list(struct vm_area_struct *mpnt, unsigned long pgoff)
{
	do {
		struct mm_struct *mm = mpnt->vm_mm;
		unsigned long start = mpnt->vm_start;
		unsigned long end = mpnt->vm_end;
		unsigned long len = end - start;
		unsigned long diff;

		/* mapping wholly truncated? 映射完全截断？*/
		if (mpnt->vm_pgoff >= pgoff) {//文件偏移大于等于pgoff
			zap_page_range(mm, start, len);//删除给定范围内的用户页面
			continue;
		}

		/* mapping wholly unaffected? 映射完全不受影响？*/
		len = len >> PAGE_SHIFT;
		diff = pgoff - mpnt->vm_pgoff;
		if (diff >= len)
			continue;

		/* Ok, partially affected.. 好的，部分受影响..*/
		start += diff << PAGE_SHIFT;
		len = (len - diff) << PAGE_SHIFT;//更新边界
		zap_page_range(mm, start, len);//删除给定范围内的用户页面
	} while ((mpnt = mpnt->vm_next_share) != NULL);
}

/*
 * Handle all mappings that got truncated by a "truncate()"
 * system call.
 *
 * NOTE! We have to be ready to update the memory sharing
 * between the file and the memory map for a potential last
 * incomplete page.  Ugly, but necessary.
 */
 /*zyq:
 截断
 */
int vmtruncate(struct inode * inode, loff_t offset)
{
	unsigned long pgoff;
	struct address_space *mapping = inode->i_mapping;
	unsigned long limit;

	if (inode->i_size < offset)
		goto do_expand;//大小不够则扩大
	inode->i_size = offset;
	spin_lock(&mapping->i_shared_lock);//上锁
	if (!mapping->i_mmap && !mapping->i_mmap_shared)
		goto out_unlock;//解锁

	pgoff = (offset + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (mapping->i_mmap != NULL)
		vmtruncate_list(mapping->i_mmap, pgoff);
	if (mapping->i_mmap_shared != NULL)
		vmtruncate_list(mapping->i_mmap_shared, pgoff);//截断

out_unlock://解锁
	spin_unlock(&mapping->i_shared_lock);
	truncate_inode_pages(mapping, offset);
	goto out_truncate;

do_expand://扩大
	limit = current->rlim[RLIMIT_FSIZE].rlim_cur;
	if (limit != RLIM_INFINITY && offset > limit)
		goto out_sig;
	if (offset > inode->i_sb->s_maxbytes)
		goto out;
	inode->i_size = offset;

out_truncate:
	if (inode->i_op && inode->i_op->truncate) {
		lock_kernel();
		inode->i_op->truncate(inode);
		unlock_kernel();
	}
	return 0;
out_sig:
	send_sig(SIGXFSZ, current, 0);
out:
	return -EFBIG;
}

/* 
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...  
 */
void swapin_readahead(swp_entry_t entry)
{
	int i, num;
	struct page *new_page;
	unsigned long offset;

	/*
	 * Get the number of handles we should do readahead io to.
	 */
	num = valid_swaphandles(entry, &offset);	
	for (i = 0; i < num; offset++, i++) {	//循环调用read_swap_cache_async分配和读入若干个页面
		/* Ok, do the async read-ahead now */
		new_page = read_swap_cache_async(SWP_ENTRY(SWP_TYPE(entry), offset));
		if (!new_page)
			break;

		/*
			new_page计数值初始为2，减少new_page计数值
			因为预读进来的页面并没有进程在使用，因此他们在active_list中但计数为1
			以后，这些界面若是被某进程认领，技术就会变成2
			或者在一段时间后被refill_inactive_scan()移入不活跃队列
		*/
		page_cache_release(new_page);	
	}
	return;
}


/*
 * We hold the mm semaphore and the page_table_lock on entry and
 * should release the pagetable lock on exit..
 */
/*
	// 事后说明：emm这是当时我看的第一个函数，所以注释的比较基础
	函数参数说明：
	struct mm_struct *mm: mm_struct存储了当前进程的信息比如代码段、数据段的起始地址等，
	描述了一个进程的整个虚拟地址空间,每个进程只有一个mm_struct

	struct vm_area_struct *vma:内核每次为用户空间中分配一个空间使用时，都会生成一个vm_are_struct结构用于记录跟踪分配情况，
	一个vm_are_struct就代表一段虚拟内存空间。

	address:映射失败的线性地址

	page_table:映射失败的页面表项的地址.当物理页面在内存中使，页面表项是pte_t结构，指向一个内存页面；
	当物理页面不在内存中时，是swap_entry_t结构，指向一个盘上页面。

	orig_pte:映射address的页表项内容

	write_access:当映射失败时所进行的访问种类(读/写)
*/

static int do_swap_page(struct mm_struct * mm,
	struct vm_area_struct * vma, unsigned long address,
	pte_t * page_table, pte_t orig_pte, int write_access)
{
	struct page *page;
	swp_entry_t entry = pte_to_swp_entry(orig_pte); // 从orig_pte获得换出页的标识符
	pte_t pte;
	int ret = 1;
	spin_unlock(&mm->page_table_lock);	// 释放内存描述符page_table_lock的自旋锁
	page = lookup_swap_cache(entry);	// 检查交换区中是否有对应的页面
	/*
		如果没有找到，说明以前用于这个虚存页面的内存页面已经释放，现在其内容仅存在于盘上了
	*/
	if (!page) {
		/*
			由于每次寻道的时间比读取页面的时间长的多，因此每次都会多读几个页面，称为页面集群
			预读进来的页面都会暂时链入活跃页面队列以及swapper_space的换入/换出队列中，
			如果实际上确实不不需要，就会由kswapd和kreclaimd在一段时间后回收
			swapin_readahead()从对换区读取至多2^n个页的一组页，其中包括所请求的页。
			值n存放在page_cluster变量中，其中的每个页是通过调用read_swap_cache_async()函数读入的
		*/
		swapin_readahead(entry);	
		/*
			一般来说所需界面已经在活跃页面队列中，只需要把它找到就行了
			但是如果预读时因为内存不足而失败，就需要再读一次
			且这次只读取想要的那一个页面
		*/
		page = read_swap_cache_async(entry); //再次调用,使当前进程挂起直到该页从磁盘上读出为止
		if (!page) {
			/*
			 * Back out if somebody else faulted in this pte while
			 * we released the page table lock.
			 */
			/*
				如果请求的页还未加到对换高速缓存，那么另一个内核控制路径可能已经代表这个进程在一个子进程换入了所请求的页
				可以通过临时获取page_table_lock自旋锁，并把page_table所指向的表项与orig_pte进行比较
				如果二者有差异，说明这一页已经被某个其他内核线程换入，函数返回1，否则返回-1
			*/
			int retval;
			spin_lock(&mm->page_table_lock);
			retval = pte_same(*page_table, orig_pte) ? -1 : 1;
			spin_unlock(&mm->page_table_lock);
			return retval;
		}

		/* Had to read the page from swap area: Major fault */
		ret = 2;
	}
	/*
		mark_page_accessed()作用为修改PG_active和PG_referenced
		PG_active置1代表页面被认为是活跃的
		当页面被访问时，检查页面的PG_referenced位，若未被置位，则置位
		若已经置位，说明该页经常被访问，
		此时若该页在inactive链表上，则值位PG_active，将其移动到active上，并清除PG_referenced的设置
		如果PG_referenced置位一段时间之后没有被访问，则系统自动清除该位
		对于在active链表的页面来说，PG_active位被置位，PG_referenced位未被置位，过段时间后页面就会被清除PG_active，挪到inactive链表上去
	*/
	mark_page_accessed(page);

	lock_page(page);	// 对页加锁

	/*
	 * Back out if somebody else faulted in this pte while we
	 * released the page table lock.
	 */
	spin_lock(&mm->page_table_lock);
	if (!pte_same(*page_table, orig_pte)) {	//判断是否有变化
		spin_unlock(&mm->page_table_lock);
		unlock_page(page);
		page_cache_release(page);	// 减少页的引用计数
		return 1;
	}

	/* The page isn't present yet, go ahead with the fault. */
		
	swap_free(entry);	//减少entry对应页槽的引用计数器
	if (vm_swap_full())	// 如果交换区满了
		remove_exclusive_swap_page(page);	//把page从swap_cache中释放

	mm->rss++;
	pte = mk_pte(page, vma->vm_page_prot);	
	if (write_access && can_share_swap_page(page))	// 如果是写访问且只有一个进程占有该界面
		pte = pte_mkdirty(pte_mkwrite(pte));	// 设置该页面为可写且为脏页面
	unlock_page(page);

	// 后两个函数对于i386来说均为空操作
	flush_page_to_ram(page);
	flush_icache_page(vma, page);

	set_pte(page_table, pte);	// 将pte加入page_tabel中

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, address, pte);	// 空操作
	spin_unlock(&mm->page_table_lock);
	return ret;
}

/*
 * We are called with the MM semaphore and page_table_lock
 * spinlock held to protect against concurrent faults in
 * multithreaded programs. 
 */
static int do_anonymous_page(struct mm_struct * mm, struct vm_area_struct * vma, pte_t *page_table, int write_access, unsigned long addr)
{
	pte_t entry;

	/* Read-only mapping of ZERO_PAGE. */
	/*
		在pte_wrprotect()中，把_PAGE_RW标志位置0，表示该物理界面只允许读
		同时对于读操作，所映射的物理页面总是同一个物理内存界面empty_zero_page，这个页面的内容全为0
		目的是进一步推迟页框的分配，该页面不可写，当下次有进程要写，触发写时拷贝时，内核才为其分配页框
	*/
	entry = pte_wrprotect(mk_pte(ZERO_PAGE(addr), vma->vm_page_prot));

	/* ..except if it's a write access */
	if (write_access) {	// 如果是写请求
		struct page *page;

		/* Allocate our own private page. */
		spin_unlock(&mm->page_table_lock);
		// 只有可写的的页面才通过alloc_page()为其分配独立的物理内存
		// 在alloc_page中会把新页框填为0
		page = alloc_page(GFP_HIGHUSER);
		if (!page)	// 如果分配物理内存失败，跳转至no_mem返回-1，即没有空间了
			goto no_mem;
		clear_user_highpage(page, addr); //安全约定，清除遗留数据

		spin_lock(&mm->page_table_lock);
		if (!pte_none(*page_table)) {	// 如果该页面被访问过	
			page_cache_release(page);	// 减少page的引用次数
			spin_unlock(&mm->page_table_lock);
			return 1;
		}
		mm->rss++;	// 跟踪分配给进程的页框数目
		flush_page_to_ram(page);	// 对i386是空操作
		entry = pte_mkwrite(pte_mkdirty(mk_pte(page, vma->vm_page_prot))); // 设置entry可写、脏页面
		// 下面两个函数将新页框插入到与交换相关的数据结构中
		lru_cache_add(page);
		mark_page_accessed(page);
	}
	// 将分配到的物理界面entry连同所有的状态以及标志位写入page_table的页面表项
	set_pte(page_table, entry);	

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, addr, entry);	// 对于i386CPU来说无意义，因为i386的MMU是实现在CPU内部的
	spin_unlock(&mm->page_table_lock);
	return 1;	/* Minor fault */

no_mem:
	return -1;
}

/*
 * do_no_page() tries to create a new page mapping. It aggressively
 * tries to share with existing pages, but makes a separate copy if
 * the "write_access" parameter is true in order to avoid the next
 * page fault.
 *
 * As this is called only for pages that do not currently exist, we
 * do not need to flush old virtual caches or the TLB.
 *
 * This is called with the MM semaphore held and the page table
 * spinlock held. Exit with the spinlock released.
 */
//TODO do_no_page
// 对于从未被访问的页的处理,想要创建一个新的页映射
static int do_no_page(struct mm_struct * mm, struct vm_area_struct * vma,
	unsigned long address, int write_access, pte_t *page_table)
{
	struct page * new_page;
	pte_t entry;

	// 如果这个页被映射为一个磁盘文件，则vma->vm_ops->nopage指向装入这个页的函数
	// 由这个函数将所缺的页从磁盘装入到内存中
	if (!vma->vm_ops || !vma->vm_ops->nopage)	// 线性区没有映射磁盘文件，说明是一个匿名映射,需要调用下面这个函数获得一个新的页框
		return do_anonymous_page(mm, vma, page_table, write_access, address);	// 获得一个新的页框
	spin_unlock(&mm->page_table_lock);

	// 如果已经被映射为磁盘文件，则vma->vm_ops->nopage指向装入这个页的函数
	new_page = vma->vm_ops->nopage(vma, address & PAGE_MASK, 0);

	if (new_page == NULL)	/* no page was available -- SIGBUS */
		return 0;
	if (new_page == NOPAGE_OOM)	// OOM：out_of_memory
		return -1;

	/*
	 * Should we do an early C-O-W break?
	 */
	if (write_access && !(vma->vm_flags & VM_SHARED)) {		// 写访问且不是几个进程共享
		struct page * page = alloc_page(GFP_HIGHUSER);	//如果有高端内存，就从高端内存分配页
		if (!page) {
			page_cache_release(new_page);
			return -1;
		}
		copy_user_highpage(page, new_page, address);	//	把上述调入的页面拷贝到新页面
		page_cache_release(new_page);
		lru_cache_add(page);
		new_page = page;
	}

	spin_lock(&mm->page_table_lock);
	/*
	 * This silly early PAGE_DIRTY setting removes a race
	 * due to the bad i386 page protection. But it's valid
	 * for other architectures too.
	 *
	 * Note that if write_access is true, we either now have
	 * an exclusive copy of the page, or this is a shared mapping,
	 * so we can make it writable and dirty to avoid having to
	 * handle that later.
	 */
	/* Only go through if we didn't race with anybody else... */
	if (pte_none(*page_table)) {	//如果pte不存在
		++mm->rss;
		// 后两句在i386没用
		flush_page_to_ram(new_page);
		flush_icache_page(vma, new_page);
		entry = mk_pte(new_page, vma->vm_page_prot);
		if (write_access)
			entry = pte_mkwrite(pte_mkdirty(entry));	// 设置写允许、脏页面
		set_pte(page_table, entry);
	} else {
		/* One of our sibling threads was faster, back out. */
		page_cache_release(new_page);
		spin_unlock(&mm->page_table_lock);
		return 1;
	}

	/* no need to invalidate: a not-present page shouldn't be cached */
	update_mmu_cache(vma, address, entry);
	spin_unlock(&mm->page_table_lock);
	return 2;	/* Major fault */
}

/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * Note the "page_table_lock". It is to protect against kswapd removing
 * pages from under us. Note that kswapd only ever _removes_ pages, never
 * adds them. As such, once we have noticed that the page is not present,
 * we can drop the lock early.
 *
 * The adding of pages is protected by the MM semaphore (which we hold),
 * so we don't need to worry about a page being suddenly been added into
 * our VM.
 *
 * We enter with the pagetable spinlock held, we are supposed to
 * release it when done.
 */
/*
	在此区分是写时拷贝还是请求调页
	被寻址的页不在主存中的情况分为：
	（1）进程从未访问此页，此时页表相应的表项被填充为0，pte_none宏返回1
	（2）进程访问过这个页，但这个页的内容被临时保存在磁盘上，
		此时页表相应表项没有被填充为0，但由于页面不在物理内存中，Present为0
*/
static inline int handle_pte_fault(struct mm_struct *mm,
	struct vm_area_struct * vma, unsigned long address,
	int write_access, pte_t * pte)
{
	pte_t entry;

	entry = *pte;
	/*
		extern inline int pte_present(pte_t pte)
		{
			return pte_val(pte) & _PAGE_PRESENT;
		}
		_PAGE_PRESENT为0x001，pte值的第0位代表是否在内存中
	*/
	if (!pte_present(entry)) {	// 检测该页在不在内存中
		/*
		 * If it truly wasn't present, we know that kswapd
		 * and the PTE updates will not touch it later. So
		 * drop the lock.
		 */
		if (pte_none(entry))	// 确认该页从未被访问过
			//如果到达了这里，说明从来都没有访问过该页，应进行请求调页
			return do_no_page(mm, vma, address, write_access, pte);	
		// 如过页不在内存中但是之前访问过（页表项存在），说明这个页被保存在了磁盘交换区上（页换入）
		return do_swap_page(mm, vma, address, pte, entry, write_access);
	}

	if (write_access) {	// 如果是写访问
		if (!pte_write(entry))	//如果页面有写保护(没有写权限)
			return do_wp_page(mm, vma, address, pte, entry);	//写时复制

		entry = pte_mkdirty(entry);	// 标记脏页面，表示该页面被写过	
	}
	entry = pte_mkyoung(entry);	// 因为访问了，所以减小页龄
	establish_pte(vma, address, pte, entry);	// 将页写入页表中
	spin_unlock(&mm->page_table_lock);
	return 1;
}

/*
 * By the time we get here, we already hold the mm semaphore
 */
/*
	mm：指向异常发生时正在CPU上运行的内存描述符
	vma：指向引起异常的线性地址所在线性区的描述符
	address：引起异常的线性地址
	write_access：如果tsk试图向address写，则置为1，如果tsk试图在address读或者执行，则值为0
*/
int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct * vma,
	unsigned long address, int write_access)
{
	pgd_t *pgd;
	pmd_t *pmd;

	/*
		即使address属于进程的地址空间，相应的页表也可能还没有被分配
		因此在做别的事情之前要先执行分配页目录和页表的任务
	*/
	current->state = TASK_RUNNING;	// 该状态表示进程处于正在运行或就绪状态
	pgd = pgd_offset(mm, address);	// 宏操作，计算出指向该地址所属页面目录项的指针

	/*
	 * We need the page table lock to synchronize with kswapd
	 * and the SMP-safe atomic PTE updates.
	 */
	spin_lock(&mm->page_table_lock);	// 页表锁
	/*
		pmd_alloc()本来是分配一个中间目录项的，但由于i386只使用两层映射
		CPU把具体的目录项当成一个只含一个表项的中间目录
		因此此处不可能失败
	*/
	pmd = pmd_alloc(mm, pgd, address);

	if (pmd) {
		/*
			pte_alloc()作用为：
			若相应的目录项已经指向一个页面表，会根据给定的地址在表中找到相应的页面表项
			若目录项为空，则先分配一个页面表，再在页面表中找到相应的表项
			为下面分配物理内存界面并建立映射做好准备 
		*/
		pte_t * pte = pte_alloc(mm, pmd, address);
		if (pte)
			// 检查address地址所对应的页表项，并决定如何为进程分配一个页框
			// 把所需页面调入内存，成功返回1否则返回-1
			return handle_pte_fault(mm, vma, address, write_access, pte);
	}
	spin_unlock(&mm->page_table_lock);
	return -1;
}

/*
 * Allocate page middle directory.
 *
 * We've already handled the fast-path in-line, and we own the
 * page table lock.
 *
 * On a two-level page table, this ends up actually being entirely
 * optimized away.
 */
pmd_t *__pmd_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	// 该函数和pte_alloc()十分相似，在pte_alloc()中有更详细注释
	pmd_t *new;
	
	/* "fast" allocation can happen without dropping the lock.. */
	// 
	new = pmd_alloc_one_fast(mm, address);	//采用一种快速的方式分配pmd页表
	if (!new) {
		spin_unlock(&mm->page_table_lock);
		new = pmd_alloc_one(mm, address);// 如果上述快速分配的方式失败，则通过物理页分配器进行分配
		spin_lock(&mm->page_table_lock);
		if (!new)	// 如果还没有就返回NULL
			return NULL;
		/*
		 * Because we dropped the lock, we should re-check the
		 * entry, as somebody else could have populated it..
		 */
		if (!pgd_none(*pgd)) {		//如果pdg在锁打开的过程中没了就把新建的释放掉
			pmd_free(new);
			goto out;
		}
	}
	pgd_populate(mm, pgd, new); 	//将new中的物理基地址填充到pgd的entry中
out:
	return pmd_offset(pgd, address);	//根据address计算得到pmd中的某个entry并返回其虚拟地址
}

/*
 * Allocate the page table directory.
 *
 * We've already handled the fast-path in-line, and we own the
 * page table lock.
 */
pte_t *pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	//需要再次说明的是i386没有实际上的pmd，对pmd的操作等价于对pgd的操作
	/*
		extern inline int pmd_none(pmd_t pmd)
		{
			return pmd_val(pmd) == (unsigned long) invalid_pte_table;
		}
		pmd_none返回是否存在该pmd，0代表存在
	*/
	if (pmd_none(*pmd)) {	
		pte_t *new;
		/* "fast" allocation can happen without dropping the lock.. */
		new = pte_alloc_one_fast(mm, address);	// 以快速的方式申请创建一个pte（从之前用过但废弃的里面选一个）
		if (!new) {
			spin_unlock(&mm->page_table_lock);
			new = pte_alloc_one(mm, address);	//通过物理页分配器进行分配
			spin_lock(&mm->page_table_lock);
			if (!new)
				return NULL;
			/*
			 * Because we dropped the lock, we should re-check the
			 * entry, as somebody else could have populated it..
			 */
			if (!pmd_none(*pmd)) {	// 过程中如果pmd没了就释放掉刚创建的pte
				pte_free(new);
				goto out;
			}
		}
		/*
		pmd_populate (struct mm_struct *mm, pmd_t *pmd_entry, pte_t *pte)
		{
			pmd_val(*pmd_entry) = __pa(pte);
		}
		__pa()作用是把虚地址转化为物理地址,该函数作用便是把物理基地址填充到pmd中
		*/
		pmd_populate(mm, pmd, new); 
	}
out:
	return pte_offset(pmd, address);	//根据address计算得到pte的地址并返回
}

/*
zyq:
将线性地址转化为页并调入物理内存。
*/
int make_pages_present(unsigned long addr, unsigned long end)
{
	int ret, len, write;
	struct vm_area_struct * vma;

	vma = find_vma(current->mm, addr);//找到起始地址的邻近区
	write = (vma->vm_flags & VM_WRITE) != 0;
	if (addr >= end)//输入违法
		BUG();
	if (end > vma->vm_end)//VMA没有覆盖地址（找不到VMA去覆盖该地址）
		BUG();
	len = (end+PAGE_SIZE-1)/PAGE_SIZE-addr/PAGE_SIZE;//求算线性地址可以转化为几个页
	ret = get_user_pages(current, current->mm, addr,
			len, write, 0, NULL, NULL);//将线性地址转化成的页调入物理内存。
	return ret == len ? 0 : -1;
}


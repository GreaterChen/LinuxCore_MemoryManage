/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/smp_lock.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>

rwlock_t vmlist_lock = RW_LOCK_UNLOCKED;
struct vm_struct * vmlist;

static inline void free_area_pte(pmd_t * pmd, unsigned long address, unsigned long size)
{
	/*
		为页表中相应的表项释放页框
	*/
	pte_t * pte;
	unsigned long end;

	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}
	pte = pte_offset(pmd, address);
	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		pte_t page;
		page = ptep_get_and_clear(pte);
		address += PAGE_SIZE;
		pte++;
		if (pte_none(page))
			continue;
		if (pte_present(page)) {
			struct page *ptpage = pte_page(page);
			if (VALID_PAGE(ptpage) && (!PageReserved(ptpage)))
				__free_page(ptpage);	// 分配给非连续内存区的每个页框是通过伙伴系统的__free_page()函数来释放的
			continue;
		}
		printk(KERN_CRIT "Whee.. Swapped out page in kernel page table\n");
	} while (address < end);
}

static inline void free_area_pmd(pgd_t * dir, unsigned long address, unsigned long size)
{
	/*
		alloc_area_pmd的反操作
		为页中间目录释放页表
	*/
	pmd_t * pmd;
	unsigned long end;

	if (pgd_none(*dir))
		return;
	if (pgd_bad(*dir)) {
		pgd_ERROR(*dir);
		pgd_clear(dir);
		return;
	}
	pmd = pmd_offset(dir, address);
	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		// 释放
		free_area_pte(pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
}

void vmfree_area_pages(unsigned long address, unsigned long size)
{	
	/*
		从起始地址 address 开始，执行vmalloc_area_pages()的反向操作
	*/
	pgd_t * dir;
	unsigned long end = address + size;

	dir = pgd_offset_k(address);	// 宏
	flush_cache_all();
	do {
		// 对中间页表，开始free每一个页表项
		free_area_pmd(dir, address, end - address);
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	flush_tlb_all();
}

static inline int alloc_area_pte (pte_t * pte, unsigned long address,
			unsigned long size, int gfp_mask, pgprot_t prot)
{
	/*
		为页表中相应的表项分配页框
	*/
	unsigned long end;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		struct page * page;
		spin_unlock(&init_mm.page_table_lock);
		page = alloc_page(gfp_mask);			// 每个页框是通过 page_alloc() 进行分配的
		spin_lock(&init_mm.page_table_lock);
		if (!pte_none(*pte))
			printk(KERN_ERR "alloc_area_pte: page already exists\n");
		if (!page)
			return -ENOMEM;
		set_pte(pte, mk_pte(page, prot));		// 宏, 把新页框的物理地址写进页表
		address += PAGE_SIZE;					// 把常量 PAGE_SIZE=4096 (一个页框的长度) 加到 address 上之后，循环反复执行 
		pte++;
	} while (address < end);					// 直到完成
	return 0;
}

static inline int alloc_area_pmd(pmd_t * pmd, unsigned long address, unsigned long size, int gfp_mask, pgprot_t prot)
{
	/*
		功能：为新的页中间目录分配所有相关的页表
		
		针对页中间目录所指向的所有页表, 为所有页中间页表分配相关的表项
	*/
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		// 分配一个新的页表，并更新<页中间目录>中相应的目录项
		pte_t * pte = pte_alloc(&init_mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		// 为页表中相应的表项分配所有的页框
		if (alloc_area_pte(pte, address, end - address, gfp_mask, prot))
			return -ENOMEM;
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
	return 0;
}

inline int vmalloc_area_pages (unsigned long address, unsigned long size,
                               int gfp_mask, pgprot_t prot)
{
	/*
		vmalloc_area_pages()函数
		参数：
			address: 存储器区的起始线性地址
			size: 存储器区的大小
			gfp_mask: 传递给伙伴算法的分配标志。它总是被置为 GFP_KERNEL | __GFP_HIGHMEM
			prot: 已分配页框的保护位。 它总是被置为0x63 对应着Present、Accessed、Read/Write及Dirty
	*/

	pgd_t * dir;
	unsigned long end = address + size;	// 内存区的末尾线性地址赋给end局部变量
	int ret;

	dir = pgd_offset_k(address);	// 使用 pgd_offset_k宏 导出这个存储器区的起始线性地址在主内核页全局目录中的目录项
	spin_lock(&init_mm.page_table_lock);	// 然后获取内核页表自旋锁


	do {
		pmd_t *pmd;

		// 首先调用pmd_alloc()为新内存区创建一个<页中间目录>，并把它的物理地址写入内核页全局目录的合适表项	
		pmd = pmd_alloc(&init_mm, dir, address);
		ret = -ENOMEM;
		if (!pmd)
			break;

		ret = -ENOMEM;
		// 然后调用alloc_area_pmd()为新的<页中间目录>分配所有相关的页表
		if (alloc_area_pmd(pmd, address, end - address, gfp_mask, prot))
			break;

		// 更新address
		address = (address + PGDIR_SIZE) & PGDIR_MASK;

		// 增加指向页全局目录的指针dir
		dir++;

		ret = 0;
	} while (address && (address < end));	// 直到指向非连续区的页表项全被建立

	spin_unlock(&init_mm.page_table_lock);	// 释放锁
	flush_cache_all();
	return ret;
}

struct vm_struct * get_vm_area(unsigned long size, unsigned long flags)
{
	/*
		这个函数的作用是：
			创建类型为vm_struct的新描述符	
		
		为非连续内存区保留的线性地址空间的其实地址由VMALLOC_START宏定义， 末尾地址由VMALLOC_END宏定义
	*/
	unsigned long addr;
	struct vm_struct **p, *tmp, *area;

	// 这里首先调用 kmalloc()为新描述符获得一个存储器区
	area = (struct vm_struct *) kmalloc(sizeof(*area), GFP_KERNEL);

	if (!area)
		return NULL;
	
	size += PAGE_SIZE;
	addr = VMALLOC_START;	// 起始地址，加了8mb的
	/*
		将非连续存储区的描述符插入到一个链表里，链表的第一个元素的地址存放在vmlist变量中
		对这个链表的访问是通过vmlist_lock读/写自旋锁保护的
	*/
	write_lock(&vmlist_lock);	

	// 扫描描述符链表，查找可用的空间	p: 头地址	tmp: p地址对应的元素	p=&tmp->next: 不断的指向下一个元素
	for (p = &vmlist; (tmp = *p) ; p = &tmp->next) {
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long) tmp->addr)	// 如果找到了，直接break
			break;
		addr = tmp->size + (unsigned long) tmp->addr;	// 找到下一个空位置
		if (addr > VMALLOC_END-size)
			goto out;
	}
	/*
		找到了, 给新建的描述符的 各个字段 赋值
	*/
	area->flags = flags;	// 已分配内存块的标志（属于哪一类）
	area->addr = (void *)addr;	
	area->size = size;
	area->next = *p;
	*p = area;
	write_unlock(&vmlist_lock);
	return area;	// 返回新描述符

	/*
		没找到, 返回NULL
	*/
out:
	write_unlock(&vmlist_lock);
	kfree(area);
	return NULL;
}

void vfree(void * addr)
{
	/*
		功能：释放非连续存储器区
		参数：addr	要释放存储器区的起始地址
	*/
	struct vm_struct **p, *tmp;

	if (!addr)
		return;
	if ((PAGE_SIZE-1) & (unsigned long) addr) {
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		return;
	}

	/*
		扫描由 vmlist 指向的链表, 以查找要释放存储器区的描述符的地址
	*/
	write_lock(&vmlist_lock);
	for (p = &vmlist ; (tmp = *p) ; p = &tmp->next) {
		if (tmp->addr == addr) {
			*p = tmp->next;
			/*
				存储器区本身的释放是通过调用 vmfree_area_pages()完成的
				而描述符的释放是通过调用 kfree()完成的
			*/
			vmfree_area_pages(VMALLOC_VMADDR(tmp->addr), tmp->size);	// 释放存储区本身
			write_unlock(&vmlist_lock);
			kfree(tmp);	// 释放描述符
			return;
		}
	}
	write_unlock(&vmlist_lock);
	printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n", addr);
}

void * __vmalloc (unsigned long size, int gfp_mask, pgprot_t prot)
{ 
	void * addr;
	struct vm_struct *area;

	size = PAGE_ALIGN(size);	// 把size取整为4096（页框大小）的一个倍数
	if (!size || (size >> PAGE_SHIFT) > num_physpages) {
		BUG();
		return NULL;
	}
	// 新建一个描述符
	area = get_vm_area(size, VM_ALLOC);
	// 如果不是空， 就说明分配成功了
	if (!area)
		return NULL;
	// 从描述符获得 找到的 空闲的、满足条件的 地址空间的 首地址（线性地址） 
	addr = area->addr;
	// 请求非连续的页框，并通过返回非连续存储器区的起始地址而结束
	if (vmalloc_area_pages(VMALLOC_VMADDR(addr), size, gfp_mask, prot)) {
		vfree(addr);
		return NULL;
	}
	return addr;
}

long vread(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

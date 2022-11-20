/*
 *  linux/arch/i386/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/tty.h>
#include <linux/vt_kern.h>		/* For unblank_screen() */

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/hardirq.h>

extern void die(const char *,struct pt_regs *,long);

/*
 * Ugly, ugly, but the goto's result in better assembly..
 */
int __verify_write(const void * addr, unsigned long size)
{
	struct vm_area_struct * vma;
	unsigned long start = (unsigned long) addr;

	if (!size)
		return 1;

	vma = find_vma(current->mm, start);
	if (!vma)
		goto bad_area;
	if (vma->vm_start > start)
		goto check_stack;

good_area:
	if (!(vma->vm_flags & VM_WRITE))
		goto bad_area;
	size--;
	size += start & ~PAGE_MASK;
	size >>= PAGE_SHIFT;
	start &= PAGE_MASK;

	for (;;) {
	survive:
		{
			int fault = handle_mm_fault(current->mm, vma, start, 1);
			if (!fault)
				goto bad_area;
			if (fault < 0)
				goto out_of_memory;
		}
		if (!size)
			break;
		size--;
		start += PAGE_SIZE;
		if (start < vma->vm_end)
			continue;
		vma = vma->vm_next;
		if (!vma || vma->vm_start != start)
			goto bad_area;
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;;
	}
	return 1;

check_stack:
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, start) == 0)
		goto good_area;

bad_area:
	return 0;

out_of_memory:
	if (current->pid == 1) {
		current->policy |= SCHED_YIELD;
		schedule();
		goto survive;
	}
	goto bad_area;
}

extern spinlock_t timerlist_lock;

/*
 * Unlock any spinlocks which will prevent us from getting the
 * message out (timerlist_lock is acquired through the
 * console unblank code)
 */
void bust_spinlocks(int yes)
{
	spin_lock_init(&timerlist_lock);
	if (yes) {
		oops_in_progress = 1;
#ifdef CONFIG_SMP
		global_irq_lock = 0;	/* Many serial drivers do __global_cli() */
#endif
	} else {
		int loglevel_save = console_loglevel;
#ifdef CONFIG_VT
		unblank_screen();
#endif
		oops_in_progress = 0;
		/*
		 * OK, the message is on the console.  Now we call printk()
		 * without oops_in_progress set so that printk will give klogd
		 * a poke.  Hold onto your hats...
		 */
		console_loglevel = 15;		/* NMI oopser may have shut the console up */
		printk(" ");
		console_loglevel = loglevel_save;
	}
}

void do_BUG(const char *file, int line)
{
	bust_spinlocks(1);
	printk("kernel BUG at %s:%d!\n", file, line);
}

asmlinkage void do_invalid_op(struct pt_regs *, unsigned long);
extern unsigned long idt;

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 */


/*缺页异常！
	struct pt_regs *regs : 指向例外发生前CPU中各寄存器内容的一份副本，是由内核的中断响应机制保存下来的现场
	error_code:指明映射失败的具体原因
*/
//TODO do_page_fault
asmlinkage void do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long address;
	unsigned long page;
	unsigned long fixup;
	int write;
	siginfo_t info;

	/* get the address */
	// 当i386CPU产生“页面错”异常时，CPU会将导致映射失败的线性地址放在控制寄存器CR2中，此处即为取出该地址
	__asm__("movl %%cr2,%0":"=r" (address));

	/* It's safe to allow irq's after cr2 has been saved */
	if (regs->eflags & X86_EFLAGS_IF)
		local_irq_enable();

	/*
		current是一个宏操作，用来取得当前正在运行的进程的task_struct结构的地址
		在每个进程的task_struct中有一个指针，指向其mm_struct数据结构
		CPU实际进行的映射并不涉及mm_struct，而是通过页面目录和页面表进行，但是mm_struct描述了这种映射
	*/
	tsk = current;	

	// !(error_code & 101),当error_code为0x0时为真，代表缺页、在内核态
	// 如果产生缺页的地址>TASK_SIZE(即进入了内核的3-4G空间)且发生在内核态,跳转到vamlloc_fault
	if (address >= TASK_SIZE && !(error_code & 5)) 
		goto vmalloc_fault;

	mm = tsk->mm;
	info.si_code = SEGV_MAPERR;

	
	/*in_interrupt返回非0说明映射的失败发生在某个中断服务程序中，与当前进程毫无关系
	  mm指针为空代表映射尚未建立，自然与当前进程没有关系
	*/
	if (in_interrupt() || !mm) 
		goto no_context;

	
	//接下来的操作需要互斥，down_read()后便不会有别的进程打扰
	down_read(&mm->mmap_sem); 

	/*
	至此已经知道了发生映射失败的地址以及所属的进程，接下来需要清楚该地址落在哪个区间
	find_vma()试图在一个虚存空间中找出地址大于给定地址的第一个区间
	其返回struct vm_area_struct类型指针，该指针指向描述进程中虚拟地址addr所在虚拟区间的结构体
	如果找不到，此次页面异常就是因为越界访问引起的
	*/
	vma = find_vma(mm, address);
	if (!vma)	// 不存在，说明访问了非法虚地址
		goto bad_area;
	if (vma->vm_start <= address)	// 如果找到了区间，且起始地址不高于给定的地址，说明给定的地址恰好落在该区间
		goto good_area;
	/*
		用户虚存空间中未使用的'空洞'分为两种：未分配的堆栈区和两个区间之间的空洞	
		若VM_GROWSDOWN为0，说明空洞上方区间并非堆栈区，说明是因为一个映射区间被撤销而留下来的，或者在建立映射时跳过了一块地址
		显然该种情况是异常情况，转到bad_area
	*/
	if (!(vma->vm_flags & VM_GROWSDOWN))	// 若区间处于未分配的堆栈区
		goto bad_area;
	// 如果真的是挨着堆栈区，继续判断
	if (error_code & 4) {	// 如果是用户态
		/*
			假设当前进程已经用尽了为本进程分配的堆栈区间，CPU中的堆栈指针%esp已经指向堆栈区间的起始地址
			若现在需要调用某子程序，CPU需要将返回地址压入堆栈，即将返回地址写入(%esp-4)的地方，
			在i386中一次压入栈最多的是pusha指令，可以一次将32个字节压入堆栈
			因此检查的准则是%esp-32，当超出这个范围时就一定是错的了，转向bad_area
		*/
		if (address + 32 < regs->esp)
			goto bad_area;
	}

	// 到达此处说明有正常的扩展需求，进行拓展
	// 该函数只是改变了堆栈区的vm_area_struct结构，并未建立起新扩展页面对物理内存的映射
	if (expand_stack(vma, address))	// 扩展占空间的vma
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */

// 细分error_code种类
good_area:
	info.si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {
		default:	/* 3: write, present */
#ifdef TEST_VERIFY_AREA
			if (regs->cs == KERNEL_CS)
				printk("WP fault at %08lx\n", regs->eip);
#endif
			/* fall through */
		case 2:		//   010&011，内核态写操作
			if (!(vma->vm_flags & VM_WRITE))	// 若不允许写入
				goto bad_area;
			write++;
			break;
		case 1:		// 保护态
			goto bad_area;
		case 0:		/* read, not present */
			if (!(vma->vm_flags & (VM_READ | VM_EXEC)))	// 可读 | 可执行
				goto bad_area;
	}

 survive:
	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	switch (handle_mm_fault(mm, vma, address, write)) {
	case 1:	// 在没有堵塞当前进程的情况下处理了缺页，这种缺页称为次缺页（minor fault）
		tsk->min_flt++;
		break;
	case 2:	// 缺页迫使当前进程睡眠(可能是由于当用磁盘上的数据填充所分配的页框时花费时间)，阻塞当前进程的缺页叫做主缺页(major fault)
		tsk->maj_flt++;
		break;
	case 0:	// 其他错误跳转到do_sigbus
		goto do_sigbus;
	default:	// 没有足够的内存
		goto out_of_memory;
	}

	/*
	 * Did it hit the DOS screen memory VA from vm86 mode?
	 */
	// 处理与VM86模式以及VGA的图象存储区有关的特殊情况
	if (regs->eflags & VM_MASK) {
		unsigned long bit = (address - 0xA0000) >> PAGE_SHIFT;
		if (bit < 32)
			tsk->thread.screen_bitmap |= 1 << bit;
	}
	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);	// 释放mmap_sem信号量

	/* User mode accesses just cause a SIGSEGV */
	if (error_code & 4) {	// 若是在用户模式
		tsk->thread.cr2 = address;
		tsk->thread.error_code = error_code;
		tsk->thread.trap_no = 14;
		info.si_signo = SIGSEGV;	// 代表异常是由于一个不存在的页框引起
		info.si_errno = 0;
		/* info.si_code has been set above */
		info.si_addr = (void *)address;
		force_sig_info(SIGSEGV, &info, tsk);	//给当前进程发杀死信号
		return;
		//在用户态转向bad_area的处理到此为止
	}

	/*
	 * Pentium F0 0F C7 C8 bug workaround.
	 */
	if (boot_cpu_data.f00f_bug) {
		unsigned long nr;
		
		nr = (address - idt) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return;
		}
	}

no_context:
	/* Are we prepared to handle this kernel fault?  */
	if ((fixup = search_exception_table(regs->eip)) != 0) {
		regs->eip = fixup;
		return;
	}

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

	if (address < PAGE_SIZE)
		printk(KERN_ALERT "Unable to handle kernel NULL pointer dereference");
	else
		printk(KERN_ALERT "Unable to handle kernel paging request");
	printk(" at virtual address %08lx\n",address);
	printk(" printing eip:\n");
	printk("%08lx\n", regs->eip);
	asm("movl %%cr3,%0":"=r" (page));
	page = ((unsigned long *) __va(page))[address >> 22];
	printk(KERN_ALERT "*pde = %08lx\n", page);
	if (page & 1) {
		page &= PAGE_MASK;
		address &= 0x003ff000;
		page = ((unsigned long *) __va(page))[address >> PAGE_SHIFT];
		printk(KERN_ALERT "*pte = %08lx\n", page);
	}
	die("Oops", regs, error_code);
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (tsk->pid == 1) {	// 如果是最初始的init进程
		tsk->policy |= SCHED_YIELD;
		schedule();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", tsk->comm);	// 打印出提示信息
	if (error_code & 4)	//如果在用户模式
		do_exit(SIGKILL);	// 杀死进程
	goto no_context;

do_sigbus:
	up_read(&mm->mmap_sem);

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void *)address;
	force_sig_info(SIGBUS, &info, tsk);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;
	return;

vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk" here. We might be inside
		 * an interrupt in the middle of a task switch..
		 */
		int offset = __pgd_offset(address);
		pgd_t *pgd, *pgd_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		asm("movl %%cr3,%0":"=r" (pgd));
		pgd = offset + (pgd_t *)__va(pgd);
		pgd_k = init_mm.pgd + offset;

		if (!pgd_present(*pgd_k))
			goto no_context;
		set_pgd(pgd, *pgd_k);
		
		pmd = pmd_offset(pgd, address);
		pmd_k = pmd_offset(pgd_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);

		pte_k = pte_offset(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
}

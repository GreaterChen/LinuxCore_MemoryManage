/*
 *	linux/mm/mmap.c
 *
 * Written by obz.
 */
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>

/*
 * WARNING: the debugging will use recursive algorithms so never enable this
 * unless you know what you are doing.
 */
#undef DEBUG_MM_RB

/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *		
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 */

 /*
 线性区的访问权限有16种组合，每种组合所对应的页的保护位存放在protection_map数组中。
 P 代表私有（Private），S 代表共享（Shared），后面的 3 个数字分别表示可读、可写和可执行。
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111 
};

/*
overcommit针对的是内存申请，内存申请不等于内存分配，内存只在实际用到的时候才分配，
内核参数 vm.overcommit_memory 接受三种取值：
0 – Heuristic overcommit handling. 这是缺省值，它允许overcommit，但过于明目张胆的overcommit会被拒绝，比如malloc一次性申请的内存大小就超过了系统总内存。Heuristic的意思是“试探式的”，内核利用某种算法（对该算法的详细解释请看文末）猜测你的内存申请是否合理，它认为不合理就会拒绝overcommit。
1 – Always overcommit. 允许overcommit，对内存申请来者不拒。
2 – Don’t overcommit. 禁止overcommit。
*/
int sysctl_overcommit_memory;

/* Check that a process has enough memory to allocate a
 * new virtual mapping.
 */

 /*
 检查是否有足够的空闲页框把交换区上存放的所有页换入。
 a.当对内存申请无任何限制条件时直接返回1，表示有足够的空闲页
 b.计算当前空闲页的上限
 b.(1)计算有多少缓存中空闲的页面个数
 b.(3)加上swap file或者swap device上空闲的“page frame”数目。
 本质上，swap file或者swap device上的磁盘空间都是给anonymous page做腾挪之用，其实这里的“page frame”不是真的page frame，称之swap page好了
 这里把free swap page的数目也计入free主要是因为可以把使用中的page frame swap out到free swap page上，因此也算是free page
 c.根据计算的空闲页来判断是否有足够的空闲页，有返回1，没有返回0。
 */
int vm_enough_memory(long pages)
{
	/* Stupid algorithm to decide if we have enough memory: while
	 * simple, it hopefully works in most obvious cases.. Easy to
	 * fool it, but this should catch most mistakes.
	 */
	/* 23/11/98 NJC: Somewhat less stupid version of algorithm,
	 * which tries to do "TheRightThing".  Instead of using half of
	 * (buffers+cache), use the minimum values.  Allow an extra 2%
	 * of num_physpages for safety margin.
	 */

	unsigned long free;
	
    /* Sometimes we want to use more memory than we have. */
	/*a*/
	if (sysctl_overcommit_memory)
	    return 1;

	/* The page cache contains buffer pages these days.. */
	/*b*/
	free = atomic_read(&page_cache_size);//原子操作
	free += nr_free_pages();
	free += nr_swap_pages;

	/*
	 * This double-counts: the nrpages are both in the page-cache
	 * and in the swapper space. At the same time, this compensates
	 * for the swap-space over-allocation (ie "nr_swap_pages" being
	 * too small.
	 */
	free += swapper_space.nrpages;

	/*
	 * The code below doesn't account for free space in the inode
	 * and dentry slab cache, slab cache fragmentation, inodes and
	 * dentries which will become freeable under VM load, etc.
	 * Lets just hope all these (complex) factors balance out...
	 */
	free += (dentry_stat.nr_unused * sizeof(struct dentry)) >> PAGE_SHIFT;
	free += (inodes_stat.nr_unused * sizeof(struct inode)) >> PAGE_SHIFT;

	return free > pages;
}

/* Remove one vm structure from the inode's i_mapping address space. */
static inline void __remove_shared_vm_struct(struct vm_area_struct *vma)
{
	struct file * file = vma->vm_file;

	if (file) {
		struct inode *inode = file->f_dentry->d_inode;
		if (vma->vm_flags & VM_DENYWRITE)
			atomic_inc(&inode->i_writecount);
		if(vma->vm_next_share)
			vma->vm_next_share->vm_pprev_share = vma->vm_pprev_share;
		*vma->vm_pprev_share = vma->vm_next_share;
	}
}

static inline void remove_shared_vm_struct(struct vm_area_struct *vma)
{
	lock_vma_mappings(vma);
	__remove_shared_vm_struct(vma);
	unlock_vma_mappings(vma);
}

void lock_vma_mappings(struct vm_area_struct *vma)
{
	struct address_space *mapping;

	mapping = NULL;
	if (vma->vm_file)
		mapping = vma->vm_file->f_dentry->d_inode->i_mapping;
	if (mapping)
		spin_lock(&mapping->i_shared_lock);
}

void unlock_vma_mappings(struct vm_area_struct *vma)
{
	struct address_space *mapping;

	mapping = NULL;
	if (vma->vm_file)
		mapping = vma->vm_file->f_dentry->d_inode->i_mapping;
	if (mapping)
		spin_unlock(&mapping->i_shared_lock);
}

/*
 *  sys_brk() for the most part doesn't need the global kernel
 *  lock, except when an application is doing something nasty
 *  like trying to un-brk an area that has already been mapped
 *  to a regular file.  in this case, the unmapping will need
 *  to invoke file system routines that need the global lock.
 */

 /*
 brk系统调用的实现函数：brk(brk)用来直接实现堆栈大小改变
 brk指定current->mm->brk旧值（堆的当前最后地址），参数brk为新值（旧地），返回值是线性区新的结束地址，这是一个系统调用。
 当用户态的进程调用brk()系统调用时，内核执行sys_brk（brk）函数。
 a.否位于进程代码段所在的线性区，如果是直接返回，因为堆不能与进程代码段所在的线性区重合。
 b.由于brk系统调用作用于一个线性区，它分配和释放完整的页。
 因此，该函数把addr的值调整为PAGE_SIZE的倍数，然后把调整的结果和内存描述的brk进程比较。
 c.如果进程请求缩小堆，则sys_brk()调用do_munmap()完成这项任务，然后返回
 d.如果进程请求扩大堆，则sys_brk首先检查是否允许进程这么做。
 如果进程企图分配在其限制范围之外的内存，函数并不多分配内存，只简单返回mm->brk的原有值
 e.然后，函数检查扩大之后的堆是否和进程的其他线性区重叠，如果是，不做任何事情就返回
 f.如果一切都顺利，则调用do_brk()函数。如果返回brk，则分配成功且sys_brk返回的新值，否则返回旧的
 */
asmlinkage unsigned long sys_brk(unsigned long brk)
{
	unsigned long rlim, retval;
	unsigned long newbrk, oldbrk;
	struct mm_struct *mm = current->mm;//mm：进程所拥有的用户空间内存描述符(在进程的task_struct)。

	down_write(&mm->mmap_sem);//mmapsem:读写信号量；函数down_write()是写者用来得到读写信号量sem时调用的，如果该信号量被读者或写者所持有，则对该函数的调用会导致调用者的睡眠。
	//防止两个以上的进程以上的进程操作同一个堆并修改它的大小

	if (brk < mm->end_code)//堆的最后地址小于代码段最后地址-说明在线性区。
		goto out;
	newbrk = PAGE_ALIGN(brk);//PAGE_ALIGN(修改后的堆值);将物理地址addr修整为页边界地址(页的上边界,向上取整)
	oldbrk = PAGE_ALIGN(mm->brk);//旧堆值
	if (oldbrk == newbrk)
		goto set_brk;//如果页数相同则不需要分配新页，直接跳转至set_brk，设置mm->brk为新的brk即可。

	/* Always allow shrinking brk. */
	if (brk <= mm->brk) {
		if (!do_munmap(mm, newbrk, oldbrk-newbrk))//删除mm的内存映射（使得堆的大小变小）详细见936
			goto set_brk;//修改内存记录的地址信息（改小）
		goto out;
	}

	/* Check against rlimit.. */
	rlim = current->rlim[RLIMIT_DATA].rlim_cur;//RLIMIT_DATA：数据段大小的最大值；rlim_cur：一个进程可以获取到的系统资源
	if (rlim < RLIM_INFINITY && brk - mm->start_data > rlim)//修改后进程申请分配的资源超过了可以获取到的系统资源（rlim）
		goto out;//修改失败

	/* Check against existing mmap mappings. */
	if (find_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))//PAGE_SIZE：计算扩大后的堆是否和线性区重合
		goto out;//修改失败

	/* Check if we have enough memory.. */
	if (!vm_enough_memory((newbrk-oldbrk) >> PAGE_SHIFT))//vm_enough_memory：判断是否有足够的内存
		goto out;//修改失败

	/* Ok, looks good - let it rip. */
	if (do_brk(oldbrk, newbrk-oldbrk) != oldbrk)//do_brk：执行扩充堆栈地址操作，成功返回旧地址
		goto out;//修改失败
set_brk:
	mm->brk = brk;//修改内存记录的地址信息
out:
	retval = mm->brk;
	up_write(&mm->mmap_sem);//放开阻塞
	return retval;
}

/* Combine the mmap "prot" and "flags" argument into one "vm_flags" used
 * internally. Essentially, translate the "PROT_xxx" and "MAP_xxx" bits
 * into "VM_xxx".
 */
static inline unsigned long calc_vm_flags(unsigned long prot, unsigned long flags)
{
#define _trans(x,bit1,bit2) \
((bit1==bit2)?(x&bit1):(x&bit1)?bit2:0)

	unsigned long prot_bits, flag_bits;
	prot_bits =
		_trans(prot, PROT_READ, VM_READ) |
		_trans(prot, PROT_WRITE, VM_WRITE) |
		_trans(prot, PROT_EXEC, VM_EXEC);
	flag_bits =
		_trans(flags, MAP_GROWSDOWN, VM_GROWSDOWN) |
		_trans(flags, MAP_DENYWRITE, VM_DENYWRITE) |
		_trans(flags, MAP_EXECUTABLE, VM_EXECUTABLE);
	return prot_bits | flag_bits;
#undef _trans
}

#ifdef DEBUG_MM_RB//只有在调用BUG模块的时候才会编译（条件编译）
/*
对红黑树的遍历后得到红黑树的节点个数（VMA个数）
*/
static int browse_rb(rb_node_t * rb_node) {
	int i = 0;
	if (rb_node) {
		i++;
		i += browse_rb(rb_node->rb_left);//（前序遍历，先根，再左子树，最后右子树）
		i += browse_rb(rb_node->rb_right);
	}
	return i;
}
/*
验证进程的VMA个数是否与内存记录值一样，（对先行列表和红黑树都进行分别的检查）
a.对线性列表个数进行验证。
b.对红黑树节点个数进行验证。
*/
static void validate_mm(struct mm_struct * mm) {
	int bug = 0;
	int i = 0;
	struct vm_area_struct * tmp = mm->mmap;
	while (tmp) {
		tmp = tmp->vm_next;//对进程所拥有的用户空间的线性空间（内存）进行遍历，并得到VMA个数
		i++;
	}
	if (i != mm->map_count)//验证线性列表的个数是否与内存记录值相同
		printk("map_count %d vm_next %d\n", mm->map_count, i), bug = 1;
	i = browse_rb(mm->mm_rb.rb_node);//验证红黑树的个数是否与内存记录值相同
	if (i != mm->map_count)
		printk("map_count %d rb %d\n", mm->map_count, i), bug = 1;
	if (bug)//任何一个验证个数仍然不对，进入BUG（）模块。
		BUG();
}
#else
#define validate_mm(mm) do { } while (0)
#endif

/*
 找需要插入的红黑树的位置，以及要插入链表的位置，并返回前一个线性区的地址和要插入的叶子节点的父节点的地址
 a.插入位置已存在，直接返回包含插入位置addr的VMA块
 b.插入位置不存在VAM返回的是他插入位的前一个节点对应的VAM
 */
static struct vm_area_struct * find_vma_prepare(struct mm_struct * mm, unsigned long addr,
						struct vm_area_struct ** pprev,
						rb_node_t *** rb_link, rb_node_t ** rb_parent)
{
	struct vm_area_struct * vma;
	rb_node_t ** __rb_link, * __rb_parent, * rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;
	vma = NULL;

	/*
	找到要插入的VAM（红黑表位置）
	*/
	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);//获得红黑树节点结构

		if (vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if (vma_tmp->vm_start <= addr)
				return vma;//插入位置已存在
			__rb_link = &__rb_parent->rb_left;//插入的线性地址小于该红黑树节点地址（起始）去左支更小的地址寻找
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;//插入的线性地址大于该红黑树节点地址（结束）去右支更大的地址寻找
		}
	}
	//插入位置不存在VAM（得到的是他插入位的前一个节点）
	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return vma;
}

/*
将新增的VAM插入线性列表中
*/
static inline void __vma_link_list(struct mm_struct * mm, struct vm_area_struct * vma, struct vm_area_struct * prev,
				   rb_node_t * rb_parent)
{
	if (prev) {
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent, struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

/*
将新增的VAM插入红黑树中
*/
static inline void __vma_link_rb(struct mm_struct * mm, struct vm_area_struct * vma,
				 rb_node_t ** rb_link, rb_node_t * rb_parent)
{
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);//用于在插入红黑树之前，将节点初始化后插入红黑树，此时插入节点， 红黑树并未平衡。（默认颜色为红色）
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);//函数用于将一个 rb_node 插入到红黑树里，并对红黑树进行调整， 使红黑树再次达到平衡。
}

/*
将新增的VAM插入映射文件中
*/ 
static inline void __vma_link_file(struct vm_area_struct * vma)
{
	struct file * file;

	file = vma->vm_file;
	if (file) {
		struct inode * inode = file->f_dentry->d_inode;
		struct address_space *mapping = inode->i_mapping;
		struct vm_area_struct **head;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&inode->i_writecount);

		head = &mapping->i_mmap;
		if (vma->vm_flags & VM_SHARED)
			head = &mapping->i_mmap_shared;
      
		/* insert vma into inode's share list */
		if((vma->vm_next_share = *head) != NULL)
			(*head)->vm_pprev_share = &vma->vm_next_share;
		*head = vma;
		vma->vm_pprev_share = head;
	}
}

/*
插入VAM
a.插入到线性表中
b.插入到红黑树里
c.插入到映射文件中
*/
static void __vma_link(struct mm_struct * mm, struct vm_area_struct * vma,  struct vm_area_struct * prev,
		       rb_node_t ** rb_link, rb_node_t * rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__vma_link_file(vma);
}

/*
插入VAM
a.对新增线性空间上锁（避免重复添加节点）
b.对VAM的页面上锁
c.执行插入操作
d.对页面解锁
e.对VAM块解锁
*/
static inline void vma_link(struct mm_struct * mm, struct vm_area_struct * vma, struct vm_area_struct * prev,
			    rb_node_t ** rb_link, rb_node_t * rb_parent)
{
	lock_vma_mappings(vma);//上锁，避免重复添加VMA
	spin_lock(&mm->page_table_lock);//上锁，针对页面
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	spin_unlock(&mm->page_table_lock);
	unlock_vma_mappings(vma);

	mm->map_count++;//更改进程内存中记录的VAM个数
	validate_mm(mm);//对VAM个数进行验证
}

/*
实现将一个新的VMA和附近的VMA合并功能
struct mm_struct *mm 进程内存描述符；
struct vm_area_struct *prev 新VMA的前一个节点；
unsigned long addr 新VMA起始地址vma->vm_start；
unsigned long end 新VMA结束地址 vma->vm_end；
unsigned long vm_flags 新VMA标志；
合并操作成功返回1；失败返回0；
a.对红黑树进行合并操作
b.对线性表进行合并操作
c.先将前一个快和新增块合并，如果存在后一个块且后一个块能合并继续合并。
*/
static int vma_merge(struct mm_struct * mm, struct vm_area_struct * prev,
		     rb_node_t * rb_parent, unsigned long addr, unsigned long end, unsigned long vm_flags)
{
	spinlock_t * lock = &mm->page_table_lock;//定义页面信号变量
	if (!prev) {
		prev = rb_entry(rb_parent, struct vm_area_struct, vm_rb);//线性表中没有前一个结点时时取红黑表的父节点代替（对红黑树进行合并操作）
		goto merge_next;
	}
	if (prev->vm_end == addr && can_vma_merge(prev, vm_flags)) {//对线性表进行合并操作（合并的条件）
		struct vm_area_struct * next;
		spin_lock(lock);//上锁
		prev->vm_end = end;//前一个块和新增的VAM合并（前一个块的结束地址改为新增块的结束地址）
		next = prev->vm_next;
		if (next && prev->vm_end == next->vm_start && can_vma_merge(next, vm_flags)) {
			prev->vm_end = next->vm_end;
			__vma_unlink(mm, next, prev);//再合并后一个块，再把原有的后一块删除
			spin_unlock(lock);

			mm->map_count--;//更新内存中记录的VMA总块个数
			kmem_cache_free(vm_area_cachep, next);
			return 1;
		}
		spin_unlock(lock);//解锁
		return 1;
	}

	prev = prev->vm_next;
	if (prev) {
 merge_next:
		if (!can_vma_merge(prev, vm_flags))
			return 0;//不可以合并返回0
		if (end == prev->vm_start) {
			spin_lock(lock);
			prev->vm_start = addr;//可以合并且合并成功后修改VMA起始的地址
			spin_unlock(lock);
			return 1;
		}
	}//可以合并但合并未成功返回0

	return 0;
}

/*
负责把磁盘文件的逻辑地址映射到虚拟地址，以及把虚拟址映射到物理地址。
do_mmap在mm.h中do_mmap()为当前进程创建并初始化一个新的虚拟区，
如果分配成功，就把这个新的虚拟区与进程已有的其他虚拟区进行合并
file：指向需要建立虚拟映射的文件，
addr：指定从何处开始查找一个空闲区域（起始地址），
len：给出vma段的地址空间长度，
off：是vma段相对于文件file的起始地址的偏移量，
prot：为vma段所包含页的访问权限
pgoff：页内偏移
*/
unsigned long do_mmap_pgoff(struct file * file, unsigned long addr, unsigned long len,
	unsigned long prot, unsigned long flags, unsigned long pgoff)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	unsigned int vm_flags;
	int correct_wcount = 0;
	int error;
	rb_node_t ** rb_link, * rb_parent;

	if (file && (!file->f_op || !file->f_op->mmap))
		return -ENODEV;//检查是否为要映射的文件定义了mmap文件操作。如果没有，就返回一个错误码。如果文件操作表的mmap为NULL说明相应的文件不能被映射(例如，这是一个目录).


	if ((len = PAGE_ALIGN(len)) == 0)//如果给出的VAM地址空间长度小于页的大小
		return addr;

	if (len > TASK_SIZE)//检查包含的地址大于TASK_SIZE
		return -EINVAL;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)//检查是否越界
		return -EINVAL;

	/* Too many mappings? */
	if (mm->map_count > MAX_MAP_COUNT)//进程映射了过多的线性区。
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);//get_unmapped_area获得新线性区的线性地址区间。
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags = calc_vm_flags(prot,flags) | mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;//通过prot和flag计算新线性区描述符的标志。
	//mm->def_flags是线性区的默认标志。它只能由mlockall系统调用修改。这个调用可以设置VM_LOCKED标志。由此锁住以后申请的RAM中的有页

	/* mlock MCL_FUTURE? */
	if (vm_flags & VM_LOCKED) {//或者进程加锁页的总数超过了保存在进程描述符的rlim[RLIMIT_MEMLOCK].rlim_cur字段中的值。也直接返回错误
		unsigned long locked = mm->locked_vm << PAGE_SHIFT;
		locked += len;
		if (locked > current->rlim[RLIMIT_MEMLOCK].rlim_cur)
			return -EAGAIN;
	}

	if (file) {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if ((prot & PROT_WRITE) && !(file->f_mode & FMODE_WRITE))//就检查文件是否为写入而打开的。
				return -EACCES;

			/* Make sure we don't allow writing to an append-only file.. */
			//如果节点仅仅允许追加写，但是文件以写方式打开，则返回错误。
			if (IS_APPEND(file->f_dentry->d_inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/* make sure there are no mandatory locks on the file. */
			//
			if (locks_verify_locked(file->f_dentry->d_inode))//如果请求一个共享内存映射，就检查文件上没有强制锁。
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);//如果文件没有写权限，那么相应的线性区也不会有写权限。

			/* fall through */
		case MAP_PRIVATE://即便是共享映射，也要进行下面的映射。
			if (!(file->f_mode & FMODE_READ))//不论是共享映射还是私有映射，都要检查文件的读权限
				return -EACCES;
			break;

		default:
			return -EINVAL;
		}
	} else {
		vm_flags |= VM_SHARED | VM_MAYSHARE;
		switch (flags & MAP_TYPE) {
		default:
			return -EINVAL;
		case MAP_PRIVATE:
			vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
			/* fall through */
		case MAP_SHARED:
			break;
		}
	}

	/* Clear old maps */
	error = -ENOMEM;
munmap_back:
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);////find_vma_prepare确定处于新区间前的线性区对象的位置，以及在红黑树中新线性区的位置
	if (vma && vma->vm_start < addr + len) {//检查是否还存在与新区间重叠的线性区。
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;////重叠了，就调用do_munmap删除新的线性区，然后重复整个步骤。
	}

	/* Check against address space limit. */
	/*
	检查进程地址空间的大小mm->total_vm << PAGE_SHIFT) + len是否超过允许的值。
	此检查不能被提前，因为上一步分配的线性区可能和已有线性区重叠，不能被加入线性区链表。
	*/
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	/* Private writable mapping? Check memory availability.. */
	if ((vm_flags & (VM_SHARED | VM_WRITE)) == VM_WRITE &&
	    !(flags & MAP_NORESERVE)				 &&
	    !vm_enough_memory(len >> PAGE_SHIFT))//没有MAP_NORESERVE表示需要检查空闲页框的数目
		return -ENOMEM;

	/* Can we just expand an old anonymous mapping? */
	/*
	不是文件映射，并且新区间是私有的，那么就调用vma_merge
	 它会检查前一个线性区是否可扩展，以包含新区间。
	 当新区间正好是两个区间之间的空洞时，它会将三个区间合并起来。
	 */
	if (!file && !(vm_flags & VM_SHARED) && rb_parent)
		if (vma_merge(mm, prev, rb_parent, addr, addr + len, vm_flags))
			goto out;

	/* Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);//首先调用kmem_cache_alloc为新的线性区分配一个vm_area_struct（说明没有发生线性区合并）
	if (!vma)
		return -ENOMEM;

	//初始化新vma对象。
	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = protection_map[vm_flags & 0x0f];
	vma->vm_ops = NULL;
	vma->vm_pgoff = pgoff;
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;
	vma->vm_raend = 0;

	if (file) {
		error = -EINVAL;
		if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
			goto free_vma;
		if (vm_flags & VM_DENYWRITE) {
			error = deny_write_access(file);
			if (error)
				goto free_vma;
			correct_wcount = 1;
		}
		vma->vm_file = file;
		get_file(file);//用文件对象的地址初始化线性区描述符的vm_file字段，并增加文件的引用计数
		/*
		 对映射的文件调用mmap方法，对于大多数文件系统，该方法由generic_file_mmap实现。它执行以下步骤:
		 将当前时间赋给文件索引节点对象的i_atime字段，并将该索引节点标记为脏。
		 用generic_file_vm_ops表的地址初始化线性区描述符的vm_ops字段，在这个表中的方法，除了nopage和populate方法外，其他所有都为空。
		 其中nopage方法由filemap_nopage实现，而populate方法由filemap_populate实现。
		 */
		error = file->f_op->mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;
	} else if (flags & MAP_SHARED) {//新线性区有VM_SHARED标志，又不是映射磁盘上的文件。则该线性区是一个共享匿名区。
		error = shmem_zero_setup(vma);//shmem_zero_setup对它进行初始化。共享匿名区主要用于进程间通信。
		if (error)
			goto free_vma;
	}

	/* Can addr have changed??
	 *
	 * Answer: Yes, several device drivers can do it in their
	 *         f_op->mmap method. -DaveM
	 */
	addr = vma->vm_start;

	vma_link(mm, vma, prev, rb_link, rb_parent);//vma_link将新线性区插入到线性区链表和红黑树中
	if (correct_wcount)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);

out:	
	mm->total_vm += len >> PAGE_SHIFT;
	if (vm_flags & VM_LOCKED) {//VM_LOCKED标志被设置，就调用make_pages_present连续分配线性区的所有页，并将所有页锁在RAM中。
		mm->locked_vm += len >> PAGE_SHIFT;
		/*
		 make_pages_present在所有页上循环，对其中每个页，调用follow_page检查当前页表中是否有到物理页的映射。
		 如果没有这样的页存在，就调用handle_mm_fault。这个函数分配一个页框并根据内存描述符的vm_flags字段设置它的页表项。
		 */
		make_pages_present(addr, addr + len);
	}
	return addr;

unmap_and_free_vma:
	if (correct_wcount)
		atomic_inc(&file->f_dentry->d_inode->i_writecount);
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
	zap_page_range(mm, vma->vm_start, vma->vm_end - vma->vm_start);
free_vma:
	kmem_cache_free(vm_area_cachep, vma);
	return error;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA
/*
 分配从低端地址向高端地址移动的线性区(xie.baoyou注：如堆而不是栈)
 */
static inline unsigned long arch_get_unmapped_area(struct file *filp, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct vm_area_struct *vma;

	if (len > TASK_SIZE)//进程地址不能超过TASK_SIZE
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(current->mm, addr);//给addr分配VAM（如果地址不是0，就从addr处开始分配，当然，需要将addr按4K取整）
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;//没有被映射，这块区间可以使用
	}
	addr = PAGE_ALIGN(TASK_UNMAPPED_BASE);//如果addr==0或者前面的搜索失败，从TASK_UNMAPPED_BASE开始搜索，这个值初始为用户态空间的1/3处（即1G处），它也是为正文段、数据段、BSS段保留的

	for (vma = find_vma(current->mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr)//没有找到
			return -ENOMEM;
		if (!vma || addr + len <= vma->vm_start)
			return addr;//找到了，记下本次找到的地方，下次从addr+len处开始找
		addr = vma->vm_end;
	}
}
#else
extern unsigned long arch_get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
#endif	

unsigned long get_unmapped_area(struct file *file, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)
{
	if (flags & MAP_FIXED) {
		if (addr > TASK_SIZE - len)//如果addr不等于0,就检查指定的地址是否在用户态空间。（这是为了避免用户态程序绕过安全检查而影响内核地址空间）
			return -ENOMEM;
		if (addr & ~PAGE_MASK)//检查是否与页边界对齐
			return -EINVAL;
		return addr;
	}

	if (file && file->f_op && file->f_op->get_unmapped_area)
		return file->f_op->get_unmapped_area(file, addr, len, pgoff, flags);//检查线性地址区间是否应该用于文件内存映射或匿名内存映射。分别调用文件和内存的get_unmapped_area操作

	return arch_get_unmapped_area(file, addr, len, pgoff, flags);
}

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
/*
 查找给定地址的最邻近区。
 它查找线性区的vm_end字段大于addr的第一个线性区的位置。并返回这个线性区描述符的地址。
 如果没有这样的线性区存在，就返回NULL。
 由find_vma函数所选择的线性区并不一定要包含addr，因为addr可能位于任何线性区之外。
 mm-进程内存描述符地址
 addr-线性地址。
 */
struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct *vma = NULL;

	if (mm) {
		/* Check the cache first. */
		/* (Cache hit rate is typically around 35%.) */
		/*
		mmap_cache指向最后一个引用的线性区对象。
		引入这个附加的字段是为了减少查找一个给定线性地址所在线性区而花费的时间。
		程序中引用地址的局部性使这种情况出现的可能性非常大:
		如果检查的最后一个线性地址属于某一给定的线性区。那么下一个要检查的线性地址也属于这一个线性区
		*/
		vma = mm->mmap_cache;
		if (!(vma && vma->vm_end > addr && vma->vm_start <= addr)) {//首先检查mmap_cache指定的线性区是否包含addr，如果是就返回这个线性区描述符的指针。
			rb_node_t * rb_node;

			rb_node = mm->mm_rb.rb_node;//mmap_cache中没有包含addr。就扫描进程的线性区。并在红黑树中查找线性区
			vma = NULL;

			while (rb_node) {
				struct vm_area_struct * vma_tmp;

				vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);//rb_entry从指向红黑树中一个节点的指针导出相应线性区描述符的指针。

				if (vma_tmp->vm_end > addr) {
					vma = vma_tmp;
					if (vma_tmp->vm_start <= addr)
						break;//当前线性区包含addr,退出循环，返回VMA
					rb_node = rb_node->rb_left;//否则在左子树中继续
				} else
					rb_node = rb_node->rb_right;//否则在右子树中继续
			}
			if (vma)
				mm->mmap_cache = vma;
		}
	}
	return vma;
}

/* Same as find_vma, but also return a pointer to the previous VMA in *pprev. */
/*
与find_vma类似，不同的是它把函数选中的前一个线性区描述符的指针赋给附加参数ppre。
 */
struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
				      struct vm_area_struct **pprev)
{
	if (mm) {
		/* Go through the RB tree quickly. */
		struct vm_area_struct * vma;
		rb_node_t * rb_node, * rb_last_right, * rb_prev;
		
		rb_node = mm->mm_rb.rb_node;
		rb_last_right = rb_prev = NULL;
		vma = NULL;

		while (rb_node) {
			struct vm_area_struct * vma_tmp;

			vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

			if (vma_tmp->vm_end > addr) {
				vma = vma_tmp;
				rb_prev = rb_last_right;
				if (vma_tmp->vm_start <= addr)
					break;
				rb_node = rb_node->rb_left;
			} else {
				rb_last_right = rb_node;
				rb_node = rb_node->rb_right;
			}
		}
		if (vma) {
			if (vma->vm_rb.rb_left) {
				rb_prev = vma->vm_rb.rb_left;
				while (rb_prev->rb_right)
					rb_prev = rb_prev->rb_right;
			}
			*pprev = NULL;
			if (rb_prev)
				*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
			if ((rb_prev ? (*pprev)->vm_next : mm->mmap) != vma)
				BUG();
			return vma;
		}
	}
	*pprev = NULL;
	return NULL;
}

struct vm_area_struct * find_extend_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct * vma;
	unsigned long start;

	addr &= PAGE_MASK; //页号数
	vma = find_vma(mm,addr);//找到位于该地址之后并且离该地址最近的vma
	if (!vma)
		return NULL;//没找到
	if (vma->vm_start <= addr)
		return vma;//起始小于该地址，说明该地址在该vma中
	if (!(vma->vm_flags & VM_GROWSDOWN))//如果不能向下增长，则不能覆盖到addr
		return NULL;//
	start = vma->vm_start;
	//向下增长
	if (expand_stack(vma, addr))//调用expand_stack()进行扩充，成功时返回0
		return NULL;
	if (vma->vm_flags & VM_LOCKED) {//表示需要马上为这块进程地址空间VMA的分配物理页面并建立映射关系
		make_pages_present(addr, start);//调用memory.c中的make_pages_present（）
	}
	return vma;
}

/* Normal function to fix up a mapping
 * This function is the default for when an area has no specific
 * function.  This may be used as part of a more specific routine.
 * This function works out what part of an area is affected and
 * adjusts the mapping information.  Since the actual page
 * manipulation is done in do_mmap(), none need be done here,
 * though it would probably be more appropriate.
 *
 * By the time this function is called, the area struct has been
 * removed from the process mapping list, so it needs to be
 * reinserted if necessary.
 *
 * The 4 main cases are:
 *    Unmapping the whole area
 *    Unmapping from the start of the segment to a point in it
 *    Unmapping from an intermediate point to the end
 *    Unmapping between to intermediate points, making a hole.
 *
 * Case 4 involves the creation of 2 new areas, for each side of
 * the hole.  If possible, we reuse the existing area rather than
 * allocate a new one, and the return indicates whether the old
 * area was reused.
 * 
 * 用于修复映射的普通函数
 * 当一个区域没有特定的
 *功能。 这可以用作更具体的例程的一部分。
 *此功能计算出区域的哪个部分受到影响，并且
 * 调整映射信息。 由于实际页面
 * 操作是在 do_mmap（） 中完成的，这里不需要做，
 * 虽然它可能更合适。
 *
 * 调用此函数时，区域结构
 * 从流程映射列表中删除，因此需要
 * 必要时重新插入。
 *
 * 4个主要案例是：
 *取消映射整个区域
 * 从段的开头到其中的点取消映射
 * 从中间点到终点的取消映射
 *取消中间点之间的映射，打一个洞。
 *
 * 案例 4 涉及为 2 个新区域创建 2 个新区域，用于
 * 洞。 如果可能，我们会重复使用现有区域，而不是
 * 分配一个新的，返回表明旧的是否面积被重复使用。
 */
static struct vm_area_struct * unmap_fixup(struct mm_struct *mm, 
	struct vm_area_struct *area, unsigned long addr, size_t len, 
	struct vm_area_struct *extra)
{
	struct vm_area_struct *mpnt;
	unsigned long end = addr + len;

	area->vm_mm->total_vm -= len >> PAGE_SHIFT;//减去要释放的页
	if (area->vm_flags & VM_LOCKED)//如果是锁定的页
		area->vm_mm->locked_vm -= len >> PAGE_SHIFT;//减去所锁定的页

	/* Unmapping the whole area. */
	/*取消整个vma的映射*/
	if (addr == area->vm_start && end == area->vm_end) {
		if (area->vm_ops && area->vm_ops->close)
			area->vm_ops->close(area);/*关闭该VMA*/
		if (area->vm_file)
			fput(area->vm_file);/*写回文件*/
		kmem_cache_free(vm_area_cachep, area);/*清除缓存*/
		return extra;
	}

	/* Work out to one of the ends. */
	if (end == area->vm_end) {
		//移除一部分
		/*
		 * here area isn't visible to the semaphore-less readers
		 * so we don't need to update it under the spinlock.
		 */
		area->vm_end = addr;
		lock_vma_mappings(area);//给vma上锁
		spin_lock(&mm->page_table_lock);//给页表上锁
	} else if (addr == area->vm_start) {
		area->vm_pgoff += (end - area->vm_start) >> PAGE_SHIFT;
		/* same locking considerations of the above case */
		area->vm_start = end;
		lock_vma_mappings(area);
		spin_lock(&mm->page_table_lock);
	} else {
		/*从中间去，即空洞*/
	/* Unmapping a hole: area->vm_start < addr <= end < area->vm_end */
		/* Add end mapping -- leave beginning for below */
		mpnt = extra;
		extra = NULL;
		/*把extra附加到映射*/
		mpnt->vm_mm = area->vm_mm;
		mpnt->vm_start = end;
		mpnt->vm_end = area->vm_end;
		mpnt->vm_page_prot = area->vm_page_prot;
		mpnt->vm_flags = area->vm_flags;
		mpnt->vm_raend = 0;
		mpnt->vm_ops = area->vm_ops;
		mpnt->vm_pgoff = area->vm_pgoff + ((end - area->vm_start) >> PAGE_SHIFT);
		mpnt->vm_file = area->vm_file;
		mpnt->vm_private_data = area->vm_private_data;
		//文件映射
		if (mpnt->vm_file)
			get_file(mpnt->vm_file);
		if (mpnt->vm_ops && mpnt->vm_ops->open)
			mpnt->vm_ops->open(mpnt);
		area->vm_end = addr;	/* Truncate area */

		/* Because mpnt->vm_file == area->vm_file this locks
		 * things correctly.
		 */
		lock_vma_mappings(area);
		spin_lock(&mm->page_table_lock);//解锁
		__insert_vm_struct(mm, mpnt);//插入vm中
	}

	__insert_vm_struct(mm, area);//插入VM中
	spin_unlock(&mm->page_table_lock);
	unlock_vma_mappings(area);
	return extra;//返回新增的VMA
}

/*
 * Try to free as many page directory entries as we can,
 * without having to work very hard at actually scanning
 * the page tables themselves.
 *
 * Right now we try to free page tables if we have a nice
 * PGDIR-aligned area that got free'd up. We could be more
 * granular if we want to, but this is fast and simple,
 * and covers the bad cases.
 *
 * "prev", if it exists, points to a vma before the one
 * we just free'd - but there's no telling how much before.
 */
/*
 * 释放页
*/
static void free_pgtables(struct mm_struct * mm, struct vm_area_struct *prev,
	unsigned long start, unsigned long end)
{
	unsigned long first = start & PGDIR_MASK; //起始页
	unsigned long last = end + PGDIR_SIZE - 1; //末页
	unsigned long start_index, end_index;

	if (!prev) {
		prev = mm->mmap;
		if (!prev)
			goto no_mmaps;
		if (prev->vm_end > start) {
			if (last > prev->vm_start)
				last = prev->vm_start;//从开头删
			goto no_mmaps;
		}
	}
	for (;;) {
		struct vm_area_struct *next = prev->vm_next;

		if (next) {
			if (next->vm_start < start) {
				prev = next;
				continue;
			}
			if (last > next->vm_start)
				last = next->vm_start;
		}
		if (prev->vm_end > first)
			first = prev->vm_end + PGDIR_SIZE - 1;
		break;
	}
no_mmaps:
	/*
	 * If the PGD bits are not consecutive in the virtual address, the
	 * old method of shifting the VA >> by PGDIR_SHIFT doesn't work.
	 */
	//获得各个物理页
	start_index = pgd_index(first);
	end_index = pgd_index(last);
	if (end_index > start_index) {
		clear_page_tables(mm, start_index, end_index - start_index);//从页表清除
		flush_tlb_pgtables(mm, first & PGDIR_MASK, last & PGDIR_MASK);//从缓存清除
	}
}

/* Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 * Jeremy Fitzhardine <jeremy@sw.oz.au>
 */
 /**
  * 从当前进程的地址空间中删除一个线性地址区间。
  * 要删除的区间并不总是对应一个线性区。它或者是一个线性区的一部分，或者是多个线性区。
  * mm-进程内存描述符。
  * start-要删除的地址区间的起始地址。
  * len-要删除的长度。
  */
int do_munmap(struct mm_struct *mm, unsigned long addr, size_t len)
{
	struct vm_area_struct *mpnt, *prev, **npp, *free, *extra;
	//初步检查：线性区地址不能大于TASK_SIZE，start必须是4096的整数倍。
	if ((addr & ~PAGE_MASK) || addr > TASK_SIZE || len > TASK_SIZE-addr)
		return -EINVAL;
	//len也不能为0
	if ((len = PAGE_ALIGN(len)) == 0)
		return -EINVAL;

	/* Check if this memory area is ok - put it on the temporary
	 * list if so..  The checks here are pretty simple --
	 * every area affected in some way (by any overlap) is put
	 * on the list.  If nothing is put on, nothing is affected.
	 */
	//mpnt是要删除的线性地址区间之后第一个线性区的位置。mpnt->end>start
	mpnt = find_vma_prev(mm, addr, &prev);
	if (!mpnt)
		return 0;//没有这样的线性区
	/* we have  addr < mpnt->vm_end  */

	if (mpnt->vm_start >= addr+len)
		//没有与线性地址区间重叠的线性区
		return 0;

	/* If we'll make "hole", check the vm areas limit */
	/*数量超过范围*/
	if ((mpnt->vm_start < addr && mpnt->vm_end > addr+len)
	    && mm->map_count >= MAX_MAP_COUNT)
		return -ENOMEM;

	/*
	 * We may need one additional vma to fix up the mappings ... 
	 * and this is the last chance for an easy error exit.
	 */
	extra = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);//分配一个缓存
	if (!extra)
		return -ENOMEM;

	npp = (prev ? &prev->vm_next : &mm->mmap);
	free = NULL;
	spin_lock(&mm->page_table_lock);
	for ( ; mpnt && mpnt->vm_start < addr+len; mpnt = *npp) {
		*npp = mpnt->vm_next;
		mpnt->vm_next = free;
		free = mpnt;
		rb_erase(&mpnt->vm_rb, &mm->mm_rb);
	}
	mm->mmap_cache = NULL;	/* Kill the cache. */
	spin_unlock(&mm->page_table_lock);

	/* Ok - we have the memory areas we should free on the 'free' list,
	 * so release them, and unmap the page range..
	 * If the one of the segments is only being partially unmapped,
	 * it will put new vm_area_struct(s) into the address space.
	 * In that case we have to be careful with VM_DENYWRITE.
	 */
	while ((mpnt = free) != NULL) {
		unsigned long st, end, size;
		struct file *file = NULL;

		free = free->vm_next;

		st = addr < mpnt->vm_start ? mpnt->vm_start : addr;
		end = addr+len;
		end = end > mpnt->vm_end ? mpnt->vm_end : end;
		size = end - st;

		if (mpnt->vm_flags & VM_DENYWRITE &&
		    (st != mpnt->vm_start || end != mpnt->vm_end) &&
		    (file = mpnt->vm_file) != NULL) {
			atomic_dec(&file->f_dentry->d_inode->i_writecount);
		}
		remove_shared_vm_struct(mpnt);
		mm->map_count--;

		zap_page_range(mm, st, size);

		/*
		 * Fix the mapping, and free the old area if it wasn't reused.
		 */
		extra = unmap_fixup(mm, mpnt, st, size, extra);
		if (file)
			atomic_inc(&file->f_dentry->d_inode->i_writecount);
	}
	validate_mm(mm);

	/* Release the extra vma struct if it wasn't used */
	if (extra)
		kmem_cache_free(vm_area_cachep, extra);

	free_pgtables(mm, prev, addr, addr+len);

	return 0;
}

asmlinkage long sys_munmap(unsigned long addr, size_t len)
{
	int ret;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);//读写锁
	ret = do_munmap(mm, addr, len);//删除映射
	up_write(&mm->mmap_sem);
	return ret;
}

/*
 *  this is really a simplified "do_mmap".  it only handles
 *  anonymous maps.  eventually we may be able to do some
 *  brk-specific accounting here.
 */
/*
	执行动态分配
*/
unsigned long do_brk(unsigned long addr, unsigned long len)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	unsigned long flags;
	rb_node_t ** rb_link, * rb_parent;

	len = PAGE_ALIGN(len);//页面对齐
	if (!len)
		return addr;

	/*
	 * mlock MCL_FUTURE?
	 */
	if (mm->def_flags & VM_LOCKED) {
		unsigned long locked = mm->locked_vm << PAGE_SHIFT;//锁住的页的数量
		locked += len;
		//如果超出限制，报错
		if (locked > current->rlim[RLIMIT_MEMLOCK].rlim_cur)
			return -EAGAIN;
	}

	/*
	 * Clear old maps.  this also does some error checking for us
	 */
	/*
	调用find_vma_prepare()查找是不是已经存在某个vma覆盖了地址addr，
	如果是的话，这个已经存在的vma可能只是覆盖了部分[addr, addr len)区域，
	也可能覆盖了整个区域。这时就需要调用do_munmap()来把被覆盖地部分清除。
	*/
 munmap_back:
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);//在当前进程所有线性区组成的红黑树中依次遍历每个vma，以确定上一步找到的新区间之前的线性区对象的位置
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))//执行删除操作
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limits *after* clearing old maps... */
	if ((mm->total_vm << PAGE_SHIFT) + len
	    > current->rlim[RLIMIT_AS].rlim_cur)
		return -ENOMEM;

	if (mm->map_count > MAX_MAP_COUNT)
		return -ENOMEM;

	if (!vm_enough_memory(len >> PAGE_SHIFT))
		return -ENOMEM;

	flags = calc_vm_flags(PROT_READ|PROT_WRITE|PROT_EXEC,
				MAP_FIXED|MAP_PRIVATE) | mm->def_flags;

	flags |= VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	/* Can we just expand an old anonymous mapping? */
	if (rb_parent && vma_merge(mm, prev, rb_parent, addr, addr + len, flags))
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */

	/*
	如果没有成功的话，那么就只能新建一个vma，并把它连接到所有vma的链表和红黑树中去：
	*/
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma)
		return -ENOMEM;

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = flags;
	vma->vm_page_prot = protection_map[flags & 0x0f];
	vma->vm_ops = NULL;
	vma->vm_pgoff = 0;
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;

	vma_link(mm, vma, prev, rb_link, rb_parent);

out:
	mm->total_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED) {
		mm->locked_vm += len >> PAGE_SHIFT;
		make_pages_present(addr, addr + len);
	}
	return addr;
}

/* Build the RB tree corresponding to the VMA list. */
/*红黑树*/
void build_mmap_rb(struct mm_struct * mm)
{
	struct vm_area_struct * vma;
	rb_node_t ** rb_link, * rb_parent;

	mm->mm_rb = RB_ROOT;//头结点
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		__vma_link_rb(mm, vma, rb_link, rb_parent);//插入到红黑树
		rb_parent = &vma->vm_rb;
		rb_link = &rb_parent->rb_right;
	}
}

/* Release all mmaps. */
/*
	释放mm
*/
void exit_mmap(struct mm_struct * mm)
{
	struct vm_area_struct * mpnt;

	release_segments(mm);//释放mm的段
	spin_lock(&mm->page_table_lock);
	mpnt = mm->mmap;
	mm->mmap = mm->mmap_cache = NULL;
	mm->mm_rb = RB_ROOT;
	mm->rss = 0;
	spin_unlock(&mm->page_table_lock);
	mm->total_vm = 0;
	mm->locked_vm = 0;

	flush_cache_mm(mm);//刷新缓存
	while (mpnt) {//释放vam
		struct vm_area_struct * next = mpnt->vm_next;
		unsigned long start = mpnt->vm_start;
		unsigned long end = mpnt->vm_end;
		unsigned long size = end - start;

		if (mpnt->vm_ops) {
			if (mpnt->vm_ops->close)
				mpnt->vm_ops->close(mpnt);//执行close来释放
		}
		mm->map_count--;
		remove_shared_vm_struct(mpnt);//移除vam
		zap_page_range(mm, start, size);
		if (mpnt->vm_file)
			fput(mpnt->vm_file);//更新文件
		kmem_cache_free(vm_area_cachep, mpnt);
		mpnt = next;
	}
	flush_tlb_mm(mm);

	/* This is just debugging */
	if (mm->map_count)
		BUG();

	clear_page_tables(mm, FIRST_USER_PGD_NR, USER_PTRS_PER_PGD);
}

/*
 在线性区对象链表和内存描述符的红黑树中插入一个vm_area_struct结构。
 mm-指定进程内存描述符的地址。
 vmp-指定要插入的vm_area_struct对象的地址。要求线性区对象的vm_start和vm_end字段必须被初始化。
 */
void insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	rb_node_t ** rb_link, * rb_parent;

	__vma = find_vma_prepare(mm, vma->vm_start, &prev, &rb_link, &rb_parent);//调用find_vma_prepare确定在红黑树中vma应该位于何处。
	if (__vma && __vma->vm_start < vma->vm_end)
		BUG();
	/**
	 调用vma_link执行以下操作:
	 在mm->mmap所指向的链表中插入线性区。
	 在红黑树中插入线性区。
	 如果线性区是匿名的，就把它插入相应的anon_vma数据结构作为头节点的链表中。
	 递增mm->map_count计数器。
	 如果线性区包含一个内存映射文件，则vma_link执行其他与内存映射文件相关的任务。
	 */
	vma_link(mm, vma, prev, rb_link, rb_parent);
	validate_mm(mm);
}
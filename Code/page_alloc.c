/*
 *  linux/mm/page_alloc.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 */

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/compiler.h>

int nr_swap_pages;
int nr_active_pages;
int nr_inactive_pages;
struct list_head inactive_list;
struct list_head active_list;
pg_data_t *pgdat_list;

static char *zone_names[MAX_NR_ZONES] = { "DMA", "Normal", "HighMem" };
static int zone_balance_ratio[MAX_NR_ZONES] __initdata = { 128, 128, 128, };
static int zone_balance_min[MAX_NR_ZONES] __initdata = { 20 , 20, 20, };
static int zone_balance_max[MAX_NR_ZONES] __initdata = { 255 , 255, 255, };

/*
 * Free_page() adds the page to the free lists. This is optimized for
 * fast normal cases (no error jumps taken normally).
 *
 * The way to optimize jumps for gcc-2.2.2 is to:
 *  - select the "normal" case and put it inside the if () { XXX }
 *  - no else-statements if you can avoid them
 *
 * With the above two rules, you get a straight-line execution path
 * for the normal case, giving better asm-code.
 */

#define memlist_init(x) INIT_LIST_HEAD(x)
#define memlist_add_head list_add
#define memlist_add_tail list_add_tail
#define memlist_del list_del
#define memlist_entry list_entry
#define memlist_next(x) ((x)->next)
#define memlist_prev(x) ((x)->prev)

/*
 * Temporary debugging check.
 */
#define BAD_RANGE(zone,x) (((zone) != (x)->zone) || (((x)-mem_map) < (zone)->zone_start_mapnr) || (((x)-mem_map) >= (zone)->zone_start_mapnr+(zone)->size))

/*
 * Buddy system. Hairy. You really aren't expected to understand this
 *
 * Hint: -mask = 1+~mask
 */

static void FASTCALL(__free_pages_ok (struct page *page, unsigned int order));

// 这才是对页面块进行释放的实际函数！
static void __free_pages_ok (struct page *page, unsigned int order)
{
	/*
		函数说明：
			函数把释放的页面块链入空闲链表，并对伙伴系统的位图进行管理，必要时合并伙伴块。
			实际上是expand()函数的反操作。
	*/
	unsigned long index, page_idx, mask, flags;

	/*
		free_area_t 就是 free_area_struct 数据结构
		typedef struct free_area_struct {
	
			struct list_head {
				struct list_head *next, *prev;
			};
	
			struct list_head	free_list;
			unsigned long		*map;

		} free_area_t;
	
	*/
	free_area_t *area;
	struct page *base;
	zone_t *zone;

	/* Yes, think what happens when other parts of the kernel take 
	 * a reference to a page in order to pin it for io. -ben
	 */
	if (PageLRU(page))
		lru_cache_del(page);

	if (page->buffers)
		BUG();
	if (page->mapping)
		BUG();
	if (!VALID_PAGE(page))
		BUG();
	if (PageSwapCache(page))
		BUG();
	if (PageLocked(page))
		BUG();
	if (PageLRU(page))
		BUG();
	if (PageActive(page))
		BUG();
	page->flags &= ~((1<<PG_referenced) | (1<<PG_dirty));

	// 需要释放1个页面到进程的local_pages中
	if (current->flags & PF_FREE_PAGES)
		goto local_freelist;
 back_local_freelist:

	zone = page->zone;

	mask = (~0UL) << order;

	// 该管理zone所有4k页面的起始mem_map虚拟地址
	base = zone->zone_mem_map;
	page_idx = page - base;
	if (page_idx & ~mask)
		BUG();
	
	// 使用buddy算法,求得该page对应的map管理位图值索引(page_idx >> order)/2
	index = page_idx >> (1 + order);

	//获取该zone对应的free_area[order]
	area = zone->free_area + order;

	spin_lock_irqsave(&zone->lock, flags);

	// 将释放的空闲页数目,加到该zone的free_pages中去
	zone->free_pages -= mask;

	// 升级的最多次数为10次
	while (mask + (1 << (MAX_ORDER-1))) {
		struct page *buddy1, *buddy2;

		if (area >= zone->free_area + MAX_ORDER)
			BUG();
		
		/*
			__test_and_change_bit()函数
			
			功能：对index进行(^)异或运算,返回0,表示伙伴不在当前area内,或序伙伴忙,或许伙伴被拆到了其他area空闲着

			这个函数实现异或并返回原来的值：
				0 表示原来处于相同的状态，现在处于不同的状态；
				1 表示原来处于不同的状态，现在处于相同的状态；
		*/
		if (!__test_and_change_bit(index, area->map))
			/*
			 * the buddy page is still allocated.
			 */
			break;
		/*
		 * Move the buddy up one level.
		 */

		// 如果现在处于相同状态则找到buddy并进行合并，将合并后的块升级到下一个free_area中。
		// 求得它的伙伴对应的struct page单元,对边界位(1<<order)进行异或操作
		buddy1 = base + (page_idx ^ -mask);
		buddy2 = base + page_idx;
		if (BAD_RANGE(zone,buddy1))
			BUG();
		if (BAD_RANGE(zone,buddy2))
			BUG();

		memlist_del(&buddy1->list);		// 将合并后的块从目前层级的free_area中删除
		mask <<= 1;						//计算升级后的mask
		area++;							//指向升级后的area
		index >>= 1;
		page_idx &= mask;				//调整page_idx成(1<<order)页对齐,即:调整page_idx成伙伴中"比较小的那个小伙伴"对应的地址
	}
	memlist_add_head(&(base + page_idx)->list, &area->free_list);	//将经过Buddy伙伴合并后的页,添加到相应order对应的area对应的free_list中

	spin_unlock_irqrestore(&zone->lock, flags);
	return;

 local_freelist:
	if (current->nr_local_pages)
		goto back_local_freelist;
	if (in_interrupt())
		goto back_local_freelist;		

	list_add(&page->list, &current->local_pages);
	page->index = order;
	current->nr_local_pages++;
}

// 位图操作宏定义
#define MARK_USED(index, order, area) \
	__change_bit((index) >> (1+(order)), (area)->map)

static inline struct page * expand (zone_t *zone, struct page *page,
	 unsigned long index, int low, int high, free_area_t * area)
{
	/*
		参数：
			zone	指向已分配页块所在的管理区
			page	指向已分配的页块
			index	已分配的页块在mem_map中的下标
			low		所需物理块大小的order 即 2^low
			high	当前空闲区队列（也就是从中得到能满足要求的物理块的队列）的 curr_order
			area	指向实际分配的页块
	*/
	unsigned long size = 1 << high;		// 得到大小 幂次

	// high不可能小于low;  如果high等于low, 就跳过这个循环了; 否则进入循环
	// 当 high == low, 循环结束
	while (high > low) {
		if (BAD_RANGE(zone,page))
			BUG();
		
		// 将物理块链入低一档（也就是物理块大小减半）的空闲队列中去
		area--;
		high--;
		size >>= 1;		// ➗2 大小减半
		memlist_add_head(&(page)->list, &(area)->free_list);	// 头插
		MARK_USED(index, high, area);	// 设置位图

		// 以后半部分作为新的物理块，开始下一轮循环，也就是处理更低一档的空闲块队列
		index += size;
		page += size;
	}

	if (BAD_RANGE(zone,page))
		BUG();

	return page;
}

static FASTCALL(struct page * rmqueue(zone_t *zone, unsigned int order));
static struct page * rmqueue(zone_t *zone, unsigned int order)
{
	/*
		参数：
			zone 管理区
			order 需要分配的页面大小，表示分配页面数为 2^order 
	*/

	// zone->free_area是个结构数组，代表不同大小的空闲区的头，使用zone->free_area + order获取数组的下标，指向链接所需大小的物理内存块的队列头
	free_area_t * area = zone->free_area + order;
	unsigned int curr_order = order;
	struct list_head *head, *curr;
	unsigned long flags;
	struct page *page;

	// 分配页面时候，把page从双向链中摘除，这个过程是不能允许其他的进程、处理器来打扰的，所以要给相应的分区加上锁。
	spin_lock_irqsave(&zone->lock, flags);

	// 主要操作在 do-while 结构中进行
	/*
		大体流程：
			1、首先在恰好满足要求的队列里分配，不行就试试更大的内存块的队列
			2、如果大的成功了，就把分配到的大块 的剩余部分 分解成小块，链入相应的队列中 (expand函数)
	*/
	do {
		head = &area->free_list;	// head指向当前order大小区域的链表头
		curr = memlist_next(head);	// 指向head下一个 <宏定义>

		if (curr != head) {
			unsigned int index;

			// memlist_entry() 实际上用的是 list_entry()
			//  -> 这里将一个list_head指针curr换算成宿主结构的起始地址，也就是取得指向其宿主page结构的指针
			//     -> curr是一个page结构内部的成分list的地址，想要获得宿主地址，也就是用当前地址减去list在page内部的偏移量
			page = memlist_entry(curr, struct page, list);

			if (BAD_RANGE(zone,page))
				BUG();

			// memlist_del() 实际上用的是 list_del(), 作用是把这个page元素从队列中摘除
			memlist_del(curr);
			// 如果某个页面块被分配出去，就要在 frea_area 的位图中进行标记，这是通过调用 MARK_USED（）宏来完成的。
			index = page - zone->zone_mem_map;
			if (curr_order != MAX_ORDER-1)
				MARK_USED(index, curr_order, area);
			// 更新一下free_pages大小
			zone->free_pages -= 1UL << order;

			// 如果分配出去后还有剩余块，就通过 expand（）获得所分配的页块，而把剩余块链入适当的空闲队列中。
			page = expand(zone, page, index, order, curr_order, area);
			spin_unlock_irqrestore(&zone->lock, flags);

			set_page_count(page, 1);
			if (BAD_RANGE(zone,page))
				BUG();
			if (PageLRU(page))
				BUG();
			if (PageActive(page))
				BUG();
			return page;	
		}
		// 不断向上扫描，直到成功或者最终失败
		curr_order++;
		area++;
	} while (curr_order < MAX_ORDER);	// 不断向上扫描，直到成功或者最终失败
	spin_unlock_irqrestore(&zone->lock, flags);

	return NULL;
}

/*
这个函数只在CONFIG_DISCONTIGMEM无定义的时候才得到编译（与NUMA结构的alloc_pages相反）
*/

#ifndef CONFIG_DISCONTIGMEM
struct page *_alloc_pages(unsigned int gfp_mask, unsigned int order)
{
	// 下面这个是具体的页面分配函数
	return __alloc_pages(gfp_mask, order,
		contig_page_data.node_zonelists+(gfp_mask & GFP_ZONEMASK));
}
#endif

static struct page * FASTCALL(balance_classzone(zone_t *, unsigned int, unsigned int, int *));
static struct page * balance_classzone(zone_t * classzone, unsigned int gfp_mask, unsigned int order, int * freed)
{
	struct page * page = NULL;
	int __freed = 0;

	if (!(gfp_mask & __GFP_WAIT))
		goto out;
	if (in_interrupt())
		BUG();

	current->allocation_order = order;
	current->flags |= PF_MEMALLOC | PF_FREE_PAGES;

	__freed = try_to_free_pages(classzone, gfp_mask, order);

	current->flags &= ~(PF_MEMALLOC | PF_FREE_PAGES);

	if (current->nr_local_pages) {
		struct list_head * entry, * local_pages;
		struct page * tmp;
		int nr_pages;

		local_pages = &current->local_pages;

		if (likely(__freed)) {
			/* pick from the last inserted so we're lifo */
			entry = local_pages->next;
			do {
				tmp = list_entry(entry, struct page, list);
				if (tmp->index == order && memclass(tmp->zone, classzone)) {
					list_del(entry);
					current->nr_local_pages--;
					set_page_count(tmp, 1);
					page = tmp;

					if (page->buffers)
						BUG();
					if (page->mapping)
						BUG();
					if (!VALID_PAGE(page))
						BUG();
					if (PageSwapCache(page))
						BUG();
					if (PageLocked(page))
						BUG();
					if (PageLRU(page))
						BUG();
					if (PageActive(page))
						BUG();
					if (PageDirty(page))
						BUG();

					break;
				}
			} while ((entry = entry->next) != local_pages);
		}

		nr_pages = current->nr_local_pages;
		/* free in reverse order so that the global order will be lifo */
		while ((entry = local_pages->prev) != local_pages) {
			list_del(entry);
			tmp = list_entry(entry, struct page, list);
			__free_pages_ok(tmp, tmp->index);
			if (!nr_pages--)
				BUG();
		}
		current->nr_local_pages = 0;
	}
 out:
	*freed = __freed;
	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator:
 */
struct page * __alloc_pages(unsigned int gfp_mask, unsigned int order, zonelist_t *zonelist)
{
	/*
		参数：
			gfp_mask 分配策略
			order 分配大小，可以是1, 2, 4, 8, ...., 2^max_order
			zonelist 所有区
	*/
	unsigned long min;
	zone_t **zone, * classzone;
	struct page * page;
	int freed;

	// 这里获取了所有的管理区
	zone = zonelist->zones;
	classzone = *zone;
	// “低水位”初始化, UL = unsigned long  幂次操作<<  这里也就是需要的空间大小 2^order
	min = 1UL << order;
	/*
		循环遍历管理区，如果 没了/成功 就退出；
		条件是： 如果rmqueue()失败，那就继续到 分配策略规定的 下一个管理区找
	*/
	for (;;) {
		zone_t *z = *(zone++);
		if (!z)
			break;

		// 更新“水位线”
		min += z->pages_low;
		// 如果这个区 有可用空间，就调用rmqueue()函数，试图从该管理区中分配
		if (z->free_pages > min) {
			// rmqueue函数：试图从一个页面管理区分配若干连续的内存页面
			page = rmqueue(z, order);
			if (page)
				return page;
		}
	}


	/*
		如果发现管理区中的空闲页面总量已经降到最低点，则把 zone_t 结构中需要重新平衡
		的标志（need_balance）置 1，而且如果内核线程 kswapd 在一个等待队列中睡眠，就唤醒它，
		让它收回一些页面以备使用
		
		<need_balance 是和 kswapd 配合使用的>
	*/
	classzone->need_balance = 1;
	mb();
	if (waitqueue_active(&kswapd_wait))
		wake_up_interruptible(&kswapd_wait);


	/*
		再次尝试！
		如果给定分配策略中所有页面管理区都分配失败,那就把原来的最低水位除以4下调.看能否满足要求,可以满足调用rmqueue分配并返回
	*/
	zone = zonelist->zones;
	min = 1UL << order;
	for (;;) {
		unsigned long local_min;
		zone_t *z = *(zone++);
		if (!z)
			break;

		local_min = z->pages_min;
		if (!(gfp_mask & __GFP_WAIT))
			local_min >>= 2;		// ➗4
		min += local_min;
		if (z->free_pages > min) {
			page = rmqueue(z, order);
			if (page)
				return page;
		}
	}

	/* here we're in the low on memory slow path */

rebalance:
	/*
		PF_MEMALLOC		allocating memory
		PF_MEMDIE		killed out of memory
		看是哪类进程在请求分配页面， 如果是上述两类， 那么必须给进程分配页面！
		继续尝试分配！
	*/
	if (current->flags & (PF_MEMALLOC | PF_MEMDIE)) {
		zone = zonelist->zones;
		for (;;) {
			zone_t *z = *(zone++);
			if (!z)
				break;

			page = rmqueue(z, order);
			if (page)
				return page;
		}
		return NULL;
	}

	/* Atomic allocations - we can't balance anything */
	// 如果请求分配页面的进程不能等待，也不能被重新调度，只好在没有分配到页面的情况下“空手”返回。
	if (!(gfp_mask & __GFP_WAIT))
		return NULL;

	/*
		如果必须要得到页面的进程还还是没分配到页面,就要调用
		balance_classzone（）函数把当前进程所占有的局部页面释放出来。如果释放成功，则返回
		一个 page 结构指针，指向页面块中第一个页面的起始地址。
	*/
	page = balance_classzone(classzone, gfp_mask, order, &freed);
	if (page)
		return page;

	// 然后继续分配页面！
	zone = zonelist->zones;
	min = 1UL << order;
	for (;;) {
		zone_t *z = *(zone++);
		if (!z)
			break;

		min += z->pages_min;
		if (z->free_pages > min) {
			page = rmqueue(z, order);
			if (page)
				return page;
		}
	}

	/* Don't let big-order allocations loop */
	if (order > 3)
		return NULL;

	/* Yield for kswapd, and try again */
	current->policy |= SCHED_YIELD;
	__set_current_state(TASK_RUNNING);
	schedule();
	goto rebalance;
}

/*
 * Common helper functions.
 */
unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order)
{
	struct page * page;

	page = alloc_pages(gfp_mask, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}

unsigned long get_zeroed_page(unsigned int gfp_mask)
{
	struct page * page;

	page = alloc_pages(gfp_mask, 0);
	if (page) {
		void *address = page_address(page);
		clear_page(address);
		return (unsigned long) address;
	}
	return 0;
}

void __free_pages(struct page *page, unsigned int order)
{
	if (!PageReserved(page) && put_page_testzero(page))
		__free_pages_ok(page, order);	// 连续页框的释放
}

void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0)
		__free_pages(virt_to_page(addr), order);
}

/*
 * Total amount of free (allocatable) RAM:
 */
unsigned int nr_free_pages (void)
{
	unsigned int sum;
	zone_t *zone;
	pg_data_t *pgdat = pgdat_list;

	sum = 0;
	while (pgdat) {
		for (zone = pgdat->node_zones; zone < pgdat->node_zones + MAX_NR_ZONES; zone++)
			sum += zone->free_pages;
		pgdat = pgdat->node_next;
	}
	return sum;
}

/*
 * Amount of free RAM allocatable as buffer memory:
 */
unsigned int nr_free_buffer_pages (void)
{
	pg_data_t *pgdat = pgdat_list;
	unsigned int sum = 0;

	do {
		zonelist_t *zonelist = pgdat->node_zonelists + (GFP_USER & GFP_ZONEMASK);
		zone_t **zonep = zonelist->zones;
		zone_t *zone;

		for (zone = *zonep++; zone; zone = *zonep++) {
			unsigned long size = zone->size;
			unsigned long high = zone->pages_high;
			if (size > high)
				sum += size - high;
		}

		pgdat = pgdat->node_next;
	} while (pgdat);

	return sum;
}

#if CONFIG_HIGHMEM
unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat = pgdat_list;
	unsigned int pages = 0;

	while (pgdat) {
		pages += pgdat->node_zones[ZONE_HIGHMEM].free_pages;
		pgdat = pgdat->node_next;
	}
	return pages;
}
#endif

#define K(x) ((x) << (PAGE_SHIFT-10))

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 */
void show_free_areas_core(pg_data_t *pgdat)
{
 	unsigned int order;
	unsigned type;
	pg_data_t *tmpdat = pgdat;

	printk("Free pages:      %6dkB (%6dkB HighMem)\n",
		K(nr_free_pages()),
		K(nr_free_highpages()));

	while (tmpdat) {
		zone_t *zone;
		for (zone = tmpdat->node_zones;
			       	zone < tmpdat->node_zones + MAX_NR_ZONES; zone++)
			printk("Zone:%s freepages:%6lukB min:%6lukB low:%6lukB " 
				       "high:%6lukB\n", 
					zone->name,
					K(zone->free_pages),
					K(zone->pages_min),
					K(zone->pages_low),
					K(zone->pages_high));
			
		tmpdat = tmpdat->node_next;
	}

	printk("( Active: %d, inactive: %d, free: %d )\n",
	       nr_active_pages,
	       nr_inactive_pages,
	       nr_free_pages());

	for (type = 0; type < MAX_NR_ZONES; type++) {
		struct list_head *head, *curr;
		zone_t *zone = pgdat->node_zones + type;
 		unsigned long nr, total, flags;

		total = 0;
		if (zone->size) {
			spin_lock_irqsave(&zone->lock, flags);
		 	for (order = 0; order < MAX_ORDER; order++) {
				head = &(zone->free_area + order)->free_list;
				curr = head;
				nr = 0;
				for (;;) {
					curr = memlist_next(curr);
					if (curr == head)
						break;
					nr++;
				}
				total += nr * (1 << order);
				printk("%lu*%lukB ", nr, K(1UL) << order);
			}
			spin_unlock_irqrestore(&zone->lock, flags);
		}
		printk("= %lukB)\n", K(total));
	}

#ifdef SWAP_CACHE_INFO
	show_swap_cache_info();
#endif	
}

void show_free_areas(void)
{
	show_free_areas_core(pgdat_list);
}

/*
 * Builds allocation fallback zone lists.
 */
static inline void build_zonelists(pg_data_t *pgdat)
{
	int i, j, k;

	for (i = 0; i <= GFP_ZONEMASK; i++) {
		zonelist_t *zonelist;
		zone_t *zone;

		zonelist = pgdat->node_zonelists + i;
		memset(zonelist, 0, sizeof(*zonelist));

		j = 0;
		k = ZONE_NORMAL;
		if (i & __GFP_HIGHMEM)
			k = ZONE_HIGHMEM;
		if (i & __GFP_DMA)
			k = ZONE_DMA;

		switch (k) {
			default:
				BUG();
			/*
			 * fallthrough:
			 */
			case ZONE_HIGHMEM:
				zone = pgdat->node_zones + ZONE_HIGHMEM;
				if (zone->size) {
#ifndef CONFIG_HIGHMEM
					BUG();
#endif
					zonelist->zones[j++] = zone;
				}
			case ZONE_NORMAL:
				zone = pgdat->node_zones + ZONE_NORMAL;
				if (zone->size)
					zonelist->zones[j++] = zone;
			case ZONE_DMA:
				zone = pgdat->node_zones + ZONE_DMA;
				if (zone->size)
					zonelist->zones[j++] = zone;
		}
		zonelist->zones[j++] = NULL;
	} 
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 */
void __init free_area_init_core(int nid, pg_data_t *pgdat, struct page **gmap,
	unsigned long *zones_size, unsigned long zone_start_paddr, 
	unsigned long *zholes_size, struct page *lmem_map)
{
	struct page *p;
	unsigned long i, j;
	unsigned long map_size;
	unsigned long totalpages, offset, realtotalpages;
	const unsigned long zone_required_alignment = 1UL << (MAX_ORDER-1);

	if (zone_start_paddr & ~PAGE_MASK)
		BUG();

	totalpages = 0;
	for (i = 0; i < MAX_NR_ZONES; i++) {
		unsigned long size = zones_size[i];
		totalpages += size;
	}
	realtotalpages = totalpages;
	if (zholes_size)
		for (i = 0; i < MAX_NR_ZONES; i++)
			realtotalpages -= zholes_size[i];
			
	printk("On node %d totalpages: %lu\n", nid, realtotalpages);

	INIT_LIST_HEAD(&active_list);
	INIT_LIST_HEAD(&inactive_list);

	/*
	 * Some architectures (with lots of mem and discontinous memory
	 * maps) have to search for a good mem_map area:
	 * For discontigmem, the conceptual mem map array starts from 
	 * PAGE_OFFSET, we need to align the actual array onto a mem map 
	 * boundary, so that MAP_NR works.
	 */
	map_size = (totalpages + 1)*sizeof(struct page);
	if (lmem_map == (struct page *)0) {
		lmem_map = (struct page *) alloc_bootmem_node(pgdat, map_size);
		lmem_map = (struct page *)(PAGE_OFFSET + 
			MAP_ALIGN((unsigned long)lmem_map - PAGE_OFFSET));
	}
	*gmap = pgdat->node_mem_map = lmem_map;
	pgdat->node_size = totalpages;
	pgdat->node_start_paddr = zone_start_paddr;
	pgdat->node_start_mapnr = (lmem_map - mem_map);
	pgdat->nr_zones = 0;

	/*
	 * Initially all pages are reserved - free ones are freed
	 * up by free_all_bootmem() once the early boot process is
	 * done.
	 */
	for (p = lmem_map; p < lmem_map + totalpages; p++) {
		set_page_count(p, 0);
		SetPageReserved(p);
		init_waitqueue_head(&p->wait);
		memlist_init(&p->list);
	}

	offset = lmem_map - mem_map;	
	for (j = 0; j < MAX_NR_ZONES; j++) {
		zone_t *zone = pgdat->node_zones + j;
		unsigned long mask;
		unsigned long size, realsize;

		realsize = size = zones_size[j];
		if (zholes_size)
			realsize -= zholes_size[j];

		printk("zone(%lu): %lu pages.\n", j, size);
		zone->size = size;
		zone->name = zone_names[j];
		zone->lock = SPIN_LOCK_UNLOCKED;
		zone->zone_pgdat = pgdat;
		zone->free_pages = 0;
		zone->need_balance = 0;
		if (!size)
			continue;

		pgdat->nr_zones = j+1;

		mask = (realsize / zone_balance_ratio[j]);
		if (mask < zone_balance_min[j])
			mask = zone_balance_min[j];
		else if (mask > zone_balance_max[j])
			mask = zone_balance_max[j];
		zone->pages_min = mask;
		zone->pages_low = mask*2;
		zone->pages_high = mask*3;

		zone->zone_mem_map = mem_map + offset;
		zone->zone_start_mapnr = offset;
		zone->zone_start_paddr = zone_start_paddr;

		if ((zone_start_paddr >> PAGE_SHIFT) & (zone_required_alignment-1))
			printk("BUG: wrong zone alignment, it will crash\n");

		for (i = 0; i < size; i++) {
			struct page *page = mem_map + offset + i;
			page->zone = zone;
			if (j != ZONE_HIGHMEM)
				page->virtual = __va(zone_start_paddr);
			zone_start_paddr += PAGE_SIZE;
		}

		offset += size;
		for (i = 0; ; i++) {
			unsigned long bitmap_size;

			memlist_init(&zone->free_area[i].free_list);
			if (i == MAX_ORDER-1) {
				zone->free_area[i].map = NULL;
				break;
			}

			/*
			 * Page buddy system uses "index >> (i+1)",
			 * where "index" is at most "size-1".
			 *
			 * The extra "+3" is to round down to byte
			 * size (8 bits per byte assumption). Thus
			 * we get "(size-1) >> (i+4)" as the last byte
			 * we can access.
			 *
			 * The "+1" is because we want to round the
			 * byte allocation up rather than down. So
			 * we should have had a "+7" before we shifted
			 * down by three. Also, we have to add one as
			 * we actually _use_ the last bit (it's [0,n]
			 * inclusive, not [0,n[).
			 *
			 * So we actually had +7+1 before we shift
			 * down by 3. But (n+8) >> 3 == (n >> 3) + 1
			 * (modulo overflows, which we do not have).
			 *
			 * Finally, we LONG_ALIGN because all bitmap
			 * operations are on longs.
			 */
			bitmap_size = (size-1) >> (i+4);
			bitmap_size = LONG_ALIGN(bitmap_size+1);
			zone->free_area[i].map = 
			  (unsigned long *) alloc_bootmem_node(pgdat, bitmap_size);
		}
	}
	build_zonelists(pgdat);
}

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_core(0, &contig_page_data, &mem_map, zones_size, 0, 0, 0);
}

static int __init setup_mem_frac(char *str)
{
	int j = 0;

	while (get_option(&str, &zone_balance_ratio[j++]) == 2);
	printk("setup_mem_frac: ");
	for (j = 0; j < MAX_NR_ZONES; j++) printk("%d  ", zone_balance_ratio[j]);
	printk("\n");
	return 1;
}

__setup("memfrac=", setup_mem_frac);

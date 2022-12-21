/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the opereation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * linux/Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/pagemap.h>
#include <linux/init.h>

#include <asm/dma.h>
#include <asm/uaccess.h> /* for copy_to/from_user */
#include <asm/pgtable.h>

/* How many pages do we try to swap or page in/out together? */
/*页面集群的数量，在__init swap_setup(void)函数中介绍*/
int page_cluster;

pager_daemon_t pager_daemon = {
	512,	/* base number for calculating the number of tries */
	SWAP_CLUSTER_MAX,	/* minimum number of tries */
	8,	/* do swap I/O in clusters of this size */
};


//将页面从不活跃列表移动到活跃列表中
static inline void activate_page_nolock(struct page * page)
{
	if (PageLRU(page) && !PageActive(page)) {	// 确保该页面在LRU中，且不在active_list中
		del_page_from_inactive_list(page);	//从不活跃列表中删除
		add_page_to_active_list(page);		//加入活跃列表
	}
}

void activate_page(struct page * page)
{
	spin_lock(&pagemap_lru_lock);	// 加锁
	activate_page_nolock(page);		// 真正干活的函数
	spin_unlock(&pagemap_lru_lock);	// 解锁
}

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
void lru_cache_add(struct page * page)
{
	if (!TestSetPageLRU(page)) {
		spin_lock(&pagemap_lru_lock);
		add_page_to_inactive_list(page);	//加入不活跃列表
		spin_unlock(&pagemap_lru_lock);
	}
}

/**
 * __lru_cache_del: remove a page from the page lists
 * @page: the page to add
 *
 * This function is for when the caller already holds
 * the pagemap_lru_lock.
 */
void __lru_cache_del(struct page * page)
{
	if (TestClearPageLRU(page)) {//测试并清除表示该页在LRU中的标志
		if (PageActive(page)) {
			del_page_from_active_list(page);	//如果该页面在活跃页面列表中，
		} else {
			del_page_from_inactive_list(page);	//如果在不活跃页面列表中
		}
	}
}

/**
 * lru_cache_del: remove a page from the page lists
 * @page: the page to remove
 */
void lru_cache_del(struct page * page)
{
	spin_lock(&pagemap_lru_lock);	//获取LRU锁
	__lru_cache_del(page);	//实际的从LRU列表删除页面的工作
	spin_unlock(&pagemap_lru_lock);	//解锁
}

/*
 * Perform any setup for the swap system
 */
//TODO swap_setup
void __init swap_setup(void)
{
	/* 由于读磁盘时先要经过寻道，且寻道是较为费时间的，因此若每次只读指定一个页面并不经济
		Linux采用一次多读几个界面，称为"预读"，但预读需要更大的内存空间，为了确定一个适当的数量，
		此函数通过物理内存本身的大小来确定page_cluster参数大小。
	*/
	unsigned long megs = num_physpages >> (20 - PAGE_SHIFT);
	/*
		PAGE_SHIFT定义于include/asm-ia64/page.h,代表右移多少位能够得到页帧号
	*/

	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}

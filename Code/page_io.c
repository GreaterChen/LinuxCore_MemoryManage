/*
 *  linux/mm/page_io.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, 
 *  Asynchronous swapping added 30.12.95. Stephen Tweedie
 *  Removed race in async swapping. 14.4.1996. Bruno Haible
 *  Add swap of shared pages through the page cache. 20.2.1998. Stephen Tweedie
 *  Always use brw_page, life becomes simpler. 12 May 1998 Eric Biederman
 */

#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/locks.h>
#include <linux/swapctl.h>

#include <asm/pgtable.h>

/*
 * Reads or writes a swap page.
 * wait=1: start I/O and wait for completion. wait=0: start asynchronous I/O.
 *
 * Important prevention of race condition: the caller *must* atomically 
 * create a unique swap cache entry for this swap page before calling
 * rw_swap_page, and must lock that page.  By ensuring that there is a
 * single page of memory reserved for the swap entry, the normal VM page
 * lock on that page also doubles as a lock on swap entries.  Having only
 * one lock to deal with per swap entry (rather than locking swap and memory
 * independently) also makes it easier to make certain swapping operations
 * atomic, which is particularly important when we are trying to ensure 
 * that shared pages stay shared while being swapped.
 */

/*
	rw:是换入（READ）还是换出（WRITE）
	entry:当物理页面在内存中使，页面表项是pte_t结构，指向一个内存页面；当物理页面不在内存中时，是swap_entry_t结构，指向一个盘上页面。
	page:欲读写的页面
*/
static int rw_swap_page_base(int rw, swp_entry_t entry, struct page *page)
{
	unsigned long offset;
	int zones[PAGE_SIZE/512];
	int zones_used;
	kdev_t dev = 0;
	int block_size;
	struct inode *swapf = 0;


	if (rw == READ) {
	/*
		如果数据是进行换入操作（READ），清除页框的PG_uptodate标志
		因为如果从磁盘读信息，该页面显然不是最新的
		只有在换入操作成功完成时该标志才会被再次设置
	*/
		ClearPageUptodate(page);
		kstat.pswpin++;	// 增加换入的页面的统计数字
	} else
		kstat.pswpout++;

	get_swaphandle_info(entry, &offset, &dev, &swapf); //请求该swap file的iNode结构
	if (dev) {
		/*
			如果存储区域是一个分区，那么只有一个块要被写入，即一个页的大小
			因此zones只有一个，代表要写入的分区的偏移量
		*/
		zones[0] = offset;
		zones_used = 1;
		block_size = PAGE_SIZE;
	} else if (swapf) {
		/*	
			如果是一个交换文件，那么在调用brw_page()之前，
			必须先用bmap()对文件中构成页面的每个块进行映射
		*/
		int i, j;
		unsigned int block = offset	//计算最开始的block
			<< (PAGE_SHIFT - swapf->i_sb->s_blocksize_bits);

		// 单个块的大小存储字文件所在的文件系统的超级块信息中
		block_size = swapf->i_sb->s_blocksize;
		/*
			对构成整个页面的每个区块调用bmap()，每个区块都存储在zone数组中，
			以便传递给brw_page()。如果任何区块不能被映射，返回0
		*/
		for (i=0, j=0; j< PAGE_SIZE ; i++, j += block_size)
			if (!(zones[i] = bmap(swapf,block++))) {
				printk("rw_swap_page: bad swap file\n");
				return 0;
			}
		zones_used = i;	//记录多少块组成的页面
		dev = swapf->i_dev;	//记录那个设备在被写入
	} else {
		return 0;
	}

 	/* block_size == PAGE_SIZE/zones_used */
	/*
		调用brw_page()进行I/O，当I/O完成后，将解锁该页，
		在页面上等待的进程都会在此时被唤醒
	*/
 	brw_page(rw, page, dev, zones, block_size);

 	/* Note! For consistency we do all of the logic,
 	 * decrementing the page count, and unlocking the page in the
 	 * swap lock map - in the IO completion handler.
 	 */
	return 1;
}

/*
 * A simple wrapper so the base function doesn't need to enforce
 * that all swap pages go through the swap cache! We verify that:
 *  - the page is locked
 *  - it's marked as being swap-cache
 *  - it's associated with the swap inode
 */
/*
	用来换入换出页
	rw:指定数据传输方向的标志：READ表示换入，WRITE表示换出
	page:对换高速缓存中页描述符的地址
*/
void rw_swap_page(int rw, struct page *page)
{
	swp_entry_t entry;

	entry.val = page->index;

	if (!PageLocked(page))	//如果页面未上锁，报错
		PAGE_BUG(page);
	if (!PageSwapCache(page))//如果页面不在对换区，报错
		PAGE_BUG(page);
	if (page->mapping != &swapper_space)	//如果映射不到该交换区，报错
		PAGE_BUG(page);
	if (!rw_swap_page_base(rw, entry, page))	//如果返回false，则解锁该页
		UnlockPage(page);
}

/*
 * The swap lock map insists that pages be in the page cache!
 * Therefore we can't use it.  Later when we can remove the need for the
 * lock map and we can reduce the number of functions exported.
 */
void rw_swap_page_nolock(int rw, swp_entry_t entry, char *buf)
{
	struct page *page = virt_to_page(buf);	// 获得页描述符
	
	if (!PageLocked(page))	//未上锁
		PAGE_BUG(page);
	if (PageSwapCache(page))//在交换区
		PAGE_BUG(page);
	if (page->mapping)	//有映射
		PAGE_BUG(page);
	/* needs sync_page to wait I/O completation */
	page->mapping = &swapper_space;
	if (!rw_swap_page_base(rw, entry, page))	//开始I/O对换操作
		UnlockPage(page);
	wait_on_page(page);	//等待I/O数据传送完成
	page->mapping = NULL;
}

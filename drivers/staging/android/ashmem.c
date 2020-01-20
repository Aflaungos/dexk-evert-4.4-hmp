// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008 Google, Inc.
 * Robert Love <rlove@google.com>
 * Copyright (C) 2021 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#define pr_fmt(fmt) "ashmem: " fmt

#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include "ashmem.h"
#include <uapi/linux/personality.h>

/**
 * struct ashmem_area - The anonymous shared memory area
<<<<<<< HEAD
 * @mmap_lock:		The mmap mutex lock
=======
 * @name:		The optional name in /proc/pid/maps
 * @name_lock:		Protects name
 * @unpinned_list:	The list of all ashmem areas
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
 * @file:		The shmem-based backing file
 * @file_is_setup:	Boolean indicating the file is setup
 * @size:		The size of the mapping, in bytes
 * @prot_mask:		The allowed protection bits, as vm_flags
 *
 * The lifecycle of this structure is from our parent file's open() until
 * its release().
 *
 * Warning: Mappings do NOT pin this structure; It dies on close()
 */
struct ashmem_area {
<<<<<<< HEAD
	struct mutex mmap_lock;
=======
	char name[ASHMEM_FULL_NAME_LEN];
	spinlock_t name_lock;
	struct list_head unpinned_list;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	struct file *file;
	bool file_is_setup;
	size_t size;
	unsigned long prot_mask;
};

<<<<<<< HEAD
=======
/**
 * struct ashmem_range - A range of unpinned/evictable pages
 * @lru:	         The entry in the LRU list
 * @unpinned:	         The entry in its area's unpinned list
 * @asma:	         The associated anonymous shared memory area.
 * @pgstart:	         The starting page (inclusive)
 * @pgend:	         The ending page (inclusive)
 * @purged:	         The purge status (ASHMEM_NOT or ASHMEM_WAS_PURGED)
 *
 * The lifecycle of this structure is from unpin to pin.
 */
struct ashmem_range {
	struct list_head lru;
	struct list_head unpinned;
	struct ashmem_area *asma;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};

/* LRU list of unpinned pages, protected by list_lock */
static LIST_HEAD(ashmem_lru_list);
static DEFINE_MUTEX(list_lock);

/* long lru_count - The count of pages on our LRU list. */
static atomic_long_t lru_count;

/* mmap_lock - protects mmap operations */
static DEFINE_MUTEX(mmap_lock);

>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
static struct kmem_cache *ashmem_area_cachep __read_mostly;

#define PROT_MASK		(PROT_EXEC | PROT_READ | PROT_WRITE)

/**
<<<<<<< HEAD
=======
 * lru_add() - Adds a range of memory to the LRU list
 * @range:     The memory range being added.
 *
 * The range is first added to the end (tail) of the LRU list.
 * After this, the size of the range is added to @lru_count
 */
static inline void lru_add(struct ashmem_range *range)
{
	list_add_tail(&range->lru, &ashmem_lru_list);
	atomic_long_add(range_size(range), &lru_count);
}

/**
 * lru_del() - Removes a range of memory from the LRU list
 * @range:     The memory range being removed
 *
 * The range is first deleted from the LRU list.
 * After this, the size of the range is removed from @lru_count
 */
static inline void lru_del(struct ashmem_range *range)
{
	list_del(&range->lru);
	atomic_long_sub(range_size(range), &lru_count);
}

/**
 * range_alloc() - Allocates and initializes a new ashmem_range structure
 * @asma:	   The associated ashmem_area
 * @prev_range:	   The previous ashmem_range in the sorted asma->unpinned list
 * @purged:	   Initial purge status (ASMEM_NOT_PURGED or ASHMEM_WAS_PURGED)
 * @start:	   The starting page (inclusive)
 * @end:	   The ending page (inclusive)
 *
 * This function is protected by list_lock.
 *
 * Return: 0 if successful, or -ENOMEM if there is an error
 */
static int range_alloc(struct ashmem_area *asma,
		       struct ashmem_range *prev_range, unsigned int purged,
		       size_t start, size_t end)
{
	struct ashmem_range *range;

	range = kmem_cache_zalloc(ashmem_range_cachep, GFP_KERNEL);
	if (unlikely(!range))
		return -ENOMEM;

	range->asma = asma;
	range->pgstart = start;
	range->pgend = end;
	range->purged = purged;

	list_add_tail(&range->unpinned, &prev_range->unpinned);

	if (range_on_lru(range))
		lru_add(range);

	return 0;
}

/**
 * range_del() - Deletes and dealloctes an ashmem_range structure
 * @range:	 The associated ashmem_range that has previously been allocated
 */
static void range_del(struct ashmem_range *range)
{
	list_del(&range->unpinned);
	if (range_on_lru(range))
		lru_del(range);
	kmem_cache_free(ashmem_range_cachep, range);
}

/**
 * range_shrink() - Shrinks an ashmem_range
 * @range:	    The associated ashmem_range being shrunk
 * @start:	    The starting byte of the new range
 * @end:	    The ending byte of the new range
 *
 * This does not modify the data inside the existing range in any way - It
 * simply shrinks the boundaries of the range.
 *
 * Theoretically, with a little tweaking, this could eventually be changed
 * to range_resize, and expand the lru_count if the new range is larger.
 */
static inline void range_shrink(struct ashmem_range *range,
				size_t start, size_t end)
{
	size_t pre = range_size(range);

	range->pgstart = start;
	range->pgend = end;

	if (range_on_lru(range))
		atomic_long_sub(pre - range_size(range), &lru_count);
}

/**
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
 * ashmem_open() - Opens an Anonymous Shared Memory structure
 * @inode:	   The backing file's index node(?)
 * @file:	   The backing file
 *
 * Please note that the ashmem_area is not returned by this function - It is
 * instead written to "file->private_data".
 *
 * Return: 0 if successful, or another code if unsuccessful.
 */
static int ashmem_open(struct inode *inode, struct file *file)
{
	struct ashmem_area *asma;
	int ret;

	ret = generic_file_open(inode, file);
	if (unlikely(ret))
		return ret;

	asma = kmem_cache_alloc(ashmem_area_cachep, GFP_KERNEL);
	if (unlikely(!asma))
		return -ENOMEM;

<<<<<<< HEAD
	*asma = (typeof(*asma)){
		.mmap_lock = __MUTEX_INITIALIZER(asma->mmap_lock),
		.prot_mask = PROT_MASK
	};

=======
	spin_lock_init(&asma->name_lock);
	INIT_LIST_HEAD(&asma->unpinned_list);
	memcpy(asma->name, ASHMEM_NAME_PREFIX, ASHMEM_NAME_PREFIX_LEN);
	asma->prot_mask = PROT_MASK;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	file->private_data = asma;

	return 0;
}

/**
 * ashmem_release() - Releases an Anonymous Shared Memory structure
 * @ignored:	      The backing file's Index Node(?) - It is ignored here.
 * @file:	      The backing file
 *
 * Return: 0 if successful. If it is anything else, go have a coffee and
 * try again.
 */
static int ashmem_release(struct inode *ignored, struct file *file)
{
	struct ashmem_area *asma = file->private_data;
<<<<<<< HEAD
=======
	struct ashmem_range *range, *next;

	mutex_lock(&list_lock);
	list_for_each_entry_safe(range, next, &asma->unpinned_list, unpinned)
		range_del(range);
	mutex_unlock(&list_lock);
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)

	if (asma->file)
		fput(asma->file);
	kmem_cache_free(ashmem_area_cachep, asma);

	return 0;
}

static ssize_t ashmem_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
<<<<<<< HEAD
	struct ashmem_area *asma = iocb->ki_filp->private_data;
	struct file *vmfile;
	ssize_t ret;

	/* If size is not set, or set to 0, always return EOF. */
	if (!READ_ONCE(asma->size))
		return 0;

	vmfile = READ_ONCE(asma->file);
	if (!vmfile)
=======
	struct ashmem_area *asma = file->private_data;
	int ret = 0;

	/* If size is not set, or set to 0, always return EOF. */
	if (asma->size == 0)
		return 0;

	if (!asma->file)
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
		return -EBADF;

	/*
	 * asma and asma->file are used outside the lock here.  We assume
	 * once asma->file is set it will never be changed, and will not
	 * be destroyed until all references to the file are dropped and
	 * ashmem_release is called.
	 */
<<<<<<< HEAD
	ret = vfs_iter_read(vmfile, iter, &iocb->ki_pos);
	if (ret > 0)
		vmfile->f_pos = iocb->ki_pos;
=======
	ret = __vfs_read(asma->file, buf, len, pos);
	if (ret >= 0)
		/** Update backing file pos, since f_ops->read() doesn't */
		asma->file->f_pos = *pos;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	return ret;
}

static loff_t ashmem_llseek(struct file *file, loff_t offset, int origin)
{
	struct ashmem_area *asma = file->private_data;
<<<<<<< HEAD
	struct file *vmfile;
	loff_t ret;

	if (!READ_ONCE(asma->size))
		return -EINVAL;

	vmfile = READ_ONCE(asma->file);
	if (!vmfile)
		return -EBADF;

	ret = vfs_llseek(vmfile, offset, origin);
=======
	int ret;

	if (asma->size == 0)
		return -EINVAL;

	if (!asma->file)
		return -EBADF;

	ret = vfs_llseek(asma->file, offset, origin);
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	if (ret < 0)
		return ret;

	/** Copy f_pos from backing file, since f_ops->llseek() sets it */
	file->f_pos = vmfile->f_pos;
	return ret;
}

static inline vm_flags_t calc_vm_may_flags(unsigned long prot)
{
	return _calc_vm_trans(prot, PROT_READ,  VM_MAYREAD) |
	       _calc_vm_trans(prot, PROT_WRITE, VM_MAYWRITE) |
	       _calc_vm_trans(prot, PROT_EXEC,  VM_MAYEXEC);
}

static int ashmem_vmfile_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* do not allow to mmap ashmem backing shmem file directly */
	return -EPERM;
}

static unsigned long
ashmem_vmfile_get_unmapped_area(struct file *file, unsigned long addr,
				unsigned long len, unsigned long pgoff,
				unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

<<<<<<< HEAD
static int ashmem_file_setup(struct ashmem_area *asma, size_t size,
=======
static int ashmem_file_setup(struct ashmem_area *asma,
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
			     struct vm_area_struct *vma)
{
	char name[ASHMEM_FULL_NAME_LEN] = ASHMEM_NAME_DEF;
	static struct file_operations vmfile_fops;
<<<<<<< HEAD
	static DEFINE_SPINLOCK(vmfile_fops_lock);
	struct file *vmfile;

	vmfile = shmem_file_setup(ASHMEM_NAME_DEF, size, vma->vm_flags);
	if (IS_ERR(vmfile))
		return PTR_ERR(vmfile);

	/*
	 * override mmap operation of the vmfile so that it can't be
	 * remapped which would lead to creation of a new vma with no
	 * asma permission checks. Have to override get_unmapped_area
	 * as well to prevent VM_BUG_ON check for f_ops modification.
	 */
	if (!READ_ONCE(vmfile_fops.mmap)) {
		spin_lock(&vmfile_fops_lock);
		if (!vmfile_fops.mmap) {
			vmfile_fops = *vmfile->f_op;
			vmfile_fops.get_unmapped_area =
				ashmem_vmfile_get_unmapped_area;
			WRITE_ONCE(vmfile_fops.mmap, ashmem_vmfile_mmap);
		}
		spin_unlock(&vmfile_fops_lock);
=======
	struct file *vmfile;

	spin_lock(&asma->name_lock);
	if (asma->name[ASHMEM_NAME_PREFIX_LEN] != '\0')
		strcpy(name, asma->name);
	spin_unlock(&asma->name_lock);

	/* ... and allocate the backing shmem file */
	vmfile = shmem_file_setup(name, asma->size, vma->vm_flags);
	if (IS_ERR(vmfile))
		return PTR_ERR(vmfile);
	vmfile->f_mode |= FMODE_LSEEK;
	/*
	 * override mmap operation of the vmfile so that it can't be
	 * remapped which would lead to creation of a new vma with no
	 * asma permission checks. Have to override get_unmapped_area
	 * as well to prevent VM_BUG_ON check for f_ops modification.
	 */
	if (!vmfile_fops.mmap) {
		vmfile_fops = *vmfile->f_op;
		vmfile_fops.mmap = ashmem_vmfile_mmap;
		vmfile_fops.get_unmapped_area =
				ashmem_vmfile_get_unmapped_area;
	}
	vmfile->f_op = &vmfile_fops;
	WRITE_ONCE(asma->file, vmfile);
	return 0;
}

static int ashmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct ashmem_area *asma = file->private_data;
	unsigned long prot_mask;
	size_t size;
	int ret;

	size = READ_ONCE(asma->size);

	/* user needs to SET_SIZE before mapping */
	if (unlikely(!size))
		return -EINVAL;

	/* requested mapping size larger than object size */
	if (vma->vm_end - vma->vm_start > PAGE_ALIGN(size))
		return -EINVAL;

	prot_mask = READ_ONCE(asma->prot_mask);

	/* requested protection bits must match our allowed protection mask */
	if (unlikely((vma->vm_flags & ~calc_vm_prot_bits(prot_mask)) &
		     calc_vm_prot_bits(PROT_MASK)))
		return -EPERM;
	vma->vm_flags &= ~calc_vm_may_flags(~prot_mask);

	if (!READ_ONCE(asma->file)) {
		bool do_setup;

		mutex_lock(&mmap_lock);
		if ((do_setup = !asma->file_is_setup)) {
			ret = ashmem_file_setup(asma, vma);
			if (!ret)
				asma->file_is_setup = true;
		}
		mutex_unlock(&mmap_lock);

		if (do_setup && ret)
			return ret;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	}
	vmfile->f_op = &vmfile_fops;
	vmfile->f_mode |= FMODE_LSEEK;

<<<<<<< HEAD
	WRITE_ONCE(asma->file, vmfile);
=======
	if (vma->vm_flags & VM_SHARED)
		shmem_set_file(vma, asma->file);
	else {
		if (vma->vm_file)
			fput(vma->vm_file);
		vma->vm_file = asma->file;
	}

>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	return 0;
}

static int ashmem_mmap(struct file *file, struct vm_area_struct *vma)
{
<<<<<<< HEAD
	struct ashmem_area *asma = file->private_data;
	unsigned long prot_mask;
	size_t size;
=======
	struct ashmem_range *range, *next;
	unsigned long freed = 0;

	/* We might recurse into filesystem code, so bail out if necessary */
	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;

	if (!mutex_trylock(&list_lock))
		return -1;

	list_for_each_entry_safe(range, next, &ashmem_lru_list, lru) {
		loff_t start = range->pgstart * PAGE_SIZE;
		loff_t end = (range->pgend + 1) * PAGE_SIZE;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)

	/* user needs to SET_SIZE before mapping */
	size = READ_ONCE(asma->size);
	if (unlikely(!size))
		return -EINVAL;

<<<<<<< HEAD
	/* requested mapping size larger than object size */
	if (vma->vm_end - vma->vm_start > PAGE_ALIGN(size))
		return -EINVAL;

	/* requested protection bits must match our allowed protection mask */
	prot_mask = READ_ONCE(asma->prot_mask);
	if (unlikely((vma->vm_flags & ~calc_vm_prot_bits(prot_mask)) &
		     calc_vm_prot_bits(PROT_MASK)))
		return -EPERM;
=======
		freed += range_size(range);
		if (--sc->nr_to_scan <= 0)
			break;
	}
	mutex_unlock(&list_lock);
	return freed;
}

static unsigned long
ashmem_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	/*
	 * note that lru_count is count of pages on the lru, not a count of
	 * objects on the list. This means the scan function needs to return the
	 * number of pages freed, not the number of objects scanned.
	 */
	return atomic_long_read(&lru_count);
}
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)

	vma->vm_flags &= ~calc_vm_may_flags(~prot_mask);

<<<<<<< HEAD
	if (!READ_ONCE(asma->file)) {
		int ret = 0;

		mutex_lock(&asma->mmap_lock);
		if (!asma->file)
			ret = ashmem_file_setup(asma, size, vma);
		mutex_unlock(&asma->mmap_lock);

		if (ret)
			return ret;
	}

	get_file(asma->file);

	if (vma->vm_flags & VM_SHARED) {
		shmem_set_file(vma, asma->file);
	} else {
		if (vma->vm_file)
			fput(vma->vm_file);
		vma->vm_file = asma->file;
=======
static int set_prot_mask(struct ashmem_area *asma, unsigned long prot)
{
	/* the user can only remove, not add, protection bits */
	if (unlikely((READ_ONCE(asma->prot_mask) & prot) != prot))
		return -EINVAL;

	/* does the application expect PROT_READ to imply PROT_EXEC? */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		prot |= PROT_EXEC;

	WRITE_ONCE(asma->prot_mask, prot);
	return 0;
}

static int set_name(struct ashmem_area *asma, void __user *name)
{
	int len;
	int ret = 0;
	char local_name[ASHMEM_NAME_LEN];

	len = strncpy_from_user(local_name, name, ASHMEM_NAME_LEN);
	if (len < 0)
		return len;
	if (len == ASHMEM_NAME_LEN)
		local_name[ASHMEM_NAME_LEN - 1] = '\0';
	/* cannot change an existing mapping's name */
	if (unlikely(asma->file)) {
		ret = -EINVAL;
	} else {
		spin_lock(&asma->name_lock);
		strcpy(asma->name + ASHMEM_NAME_PREFIX_LEN, local_name);
		spin_unlock(&asma->name_lock);
	}

	return ret;
}

static int get_name(struct ashmem_area *asma, void __user *name)
{
	int ret = 0;
	size_t len;
	/*
	 * Have a local variable to which we'll copy the content
	 * from asma with the lock held. Later we can copy this to the user
	 * space safely without holding any locks. So even if we proceed to
	 * wait for mmap_sem, it won't lead to deadlock.
	 */
	char local_name[ASHMEM_NAME_LEN];

	if (asma->name[ASHMEM_NAME_PREFIX_LEN] != '\0') {
		/*
		 * Copying only `len', instead of ASHMEM_NAME_LEN, bytes
		 * prevents us from revealing one user's stack to another.
		 */
		len = strlen(asma->name + ASHMEM_NAME_PREFIX_LEN) + 1;
		memcpy(local_name, asma->name + ASHMEM_NAME_PREFIX_LEN, len);
	} else {
		len = sizeof(ASHMEM_NAME_DEF);
		memcpy(local_name, ASHMEM_NAME_DEF, len);
	}

	/*
	 * Now we are just copying from the stack variable to userland
	 * No lock held
	 */
	if (unlikely(copy_to_user(name, local_name, len)))
		ret = -EFAULT;
	return ret;
}

/*
 * ashmem_pin - pin the given ashmem region, returning whether it was
 * previously purged (ASHMEM_WAS_PURGED) or not (ASHMEM_NOT_PURGED).
 *
 * Caller must hold list_lock.
 */
static int ashmem_pin(struct ashmem_area *asma, size_t pgstart, size_t pgend)
{
	struct ashmem_range *range, *next;
	int ret = ASHMEM_NOT_PURGED;

	list_for_each_entry_safe(range, next, &asma->unpinned_list, unpinned) {
		/* moved past last applicable page; we can short circuit */
		if (range_before_page(range, pgstart))
			break;

		/*
		 * The user can ask us to pin pages that span multiple ranges,
		 * or to pin pages that aren't even unpinned, so this is messy.
		 *
		 * Four cases:
		 * 1. The requested range subsumes an existing range, so we
		 *    just remove the entire matching range.
		 * 2. The requested range overlaps the start of an existing
		 *    range, so we just update that range.
		 * 3. The requested range overlaps the end of an existing
		 *    range, so we just update that range.
		 * 4. The requested range punches a hole in an existing range,
		 *    so we have to update one side of the range and then
		 *    create a new range for the other side.
		 */
		if (page_range_in_range(range, pgstart, pgend)) {
			ret |= range->purged;

			/* Case #1: Easy. Just nuke the whole thing. */
			if (page_range_subsumes_range(range, pgstart, pgend)) {
				range_del(range);
				continue;
			}

			/* Case #2: We overlap from the start, so adjust it */
			if (range->pgstart >= pgstart) {
				range_shrink(range, pgend + 1, range->pgend);
				continue;
			}

			/* Case #3: We overlap from the rear, so adjust it */
			if (range->pgend <= pgend) {
				range_shrink(range, range->pgstart,
					     pgstart - 1);
				continue;
			}

			/*
			 * Case #4: We eat a chunk out of the middle. A bit
			 * more complicated, we allocate a new range for the
			 * second half and adjust the first chunk's endpoint.
			 */
			range_alloc(asma, range, range->purged,
				    pgend + 1, range->pgend);
			range_shrink(range, range->pgstart, pgstart - 1);
			break;
		}
	}

	return ret;
}

/*
 * ashmem_unpin - unpin the given range of pages. Returns zero on success.
 *
 * Caller must hold list_lock.
 */
static int ashmem_unpin(struct ashmem_area *asma, size_t pgstart, size_t pgend)
{
	struct ashmem_range *range, *next;
	unsigned int purged = ASHMEM_NOT_PURGED;

restart:
	list_for_each_entry_safe(range, next, &asma->unpinned_list, unpinned) {
		/* short circuit: this is our insertion point */
		if (range_before_page(range, pgstart))
			break;

		/*
		 * The user can ask us to unpin pages that are already entirely
		 * or partially pinned. We handle those two cases here.
		 */
		if (page_range_subsumed_by_range(range, pgstart, pgend))
			return 0;
		if (page_range_in_range(range, pgstart, pgend)) {
			pgstart = min_t(size_t, range->pgstart, pgstart);
			pgend = max_t(size_t, range->pgend, pgend);
			purged |= range->purged;
			range_del(range);
			goto restart;
		}
	}

	return range_alloc(asma, range, purged, pgstart, pgend);
}

/*
 * ashmem_get_pin_status - Returns ASHMEM_IS_UNPINNED if _any_ pages in the
 * given interval are unpinned and ASHMEM_IS_PINNED otherwise.
 *
 * Caller must hold list_lock.
 */
static int ashmem_get_pin_status(struct ashmem_area *asma, size_t pgstart,
				 size_t pgend)
{
	struct ashmem_range *range;
	int ret = ASHMEM_IS_PINNED;

	list_for_each_entry(range, &asma->unpinned_list, unpinned) {
		if (range_before_page(range, pgstart))
			break;
		if (page_range_in_range(range, pgstart, pgend)) {
			ret = ASHMEM_IS_UNPINNED;
			break;
		}
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	}

	return 0;
}

static int set_prot_mask(struct ashmem_area *asma, unsigned long prot)
{
<<<<<<< HEAD
	/* the user can only remove, not add, protection bits */
	if (unlikely((READ_ONCE(asma->prot_mask) & prot) != prot))
		return -EINVAL;

	/* does the application expect PROT_READ to imply PROT_EXEC? */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		prot |= PROT_EXEC;
=======
	struct ashmem_pin pin;
	size_t pgstart, pgend;
	int ret;

	if (unlikely(copy_from_user(&pin, p, sizeof(pin))))
		return -EFAULT;

	if (unlikely(!asma->file))
		return -EINVAL;

	/* per custom, you can pass zero for len to mean "everything onward" */
	if (!pin.len)
		pin.len = PAGE_ALIGN(asma->size) - pin.offset;

	if (unlikely((pin.offset | pin.len) & ~PAGE_MASK))
		return -EINVAL;

	if (unlikely(((__u32)-1) - pin.offset < pin.len))
		return -EINVAL;

	if (unlikely(PAGE_ALIGN(asma->size) < pin.offset + pin.len))
		return -EINVAL;

	pgstart = pin.offset / PAGE_SIZE;
	pgend = pgstart + (pin.len / PAGE_SIZE) - 1;

	mutex_lock(&list_lock);
	switch (cmd) {
	case ASHMEM_PIN:
		ret = ashmem_pin(asma, pgstart, pgend);
		break;
	case ASHMEM_UNPIN:
		ret = ashmem_unpin(asma, pgstart, pgend);
		break;
	case ASHMEM_GET_PIN_STATUS:
		ret = ashmem_get_pin_status(asma, pgstart, pgend);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&list_lock);
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)

	WRITE_ONCE(asma->prot_mask, prot);
	return 0;
}

static long ashmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ashmem_area *asma = file->private_data;
<<<<<<< HEAD
=======
	long ret;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)

	switch (cmd) {
	case ASHMEM_SET_NAME:
		return 0;
	case ASHMEM_GET_NAME:
		return 0;
	case ASHMEM_SET_SIZE:
<<<<<<< HEAD
		if (READ_ONCE(asma->file))
			return -EINVAL;

		WRITE_ONCE(asma->size, (size_t)arg);
		return 0;
=======
		if (READ_ONCE(asma->file)) {
			ret = -EINVAL;
		} else {
			WRITE_ONCE(asma->size, (size_t)arg);
			ret = 0;
		}
		break;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	case ASHMEM_GET_SIZE:
		return READ_ONCE(asma->size);
	case ASHMEM_SET_PROT_MASK:
		return set_prot_mask(asma, arg);
	case ASHMEM_GET_PROT_MASK:
		return READ_ONCE(asma->prot_mask);
	case ASHMEM_PIN:
		return 0;
	case ASHMEM_UNPIN:
		return 0;
	case ASHMEM_GET_PIN_STATUS:
		return ASHMEM_IS_PINNED;
	case ASHMEM_PURGE_ALL_CACHES:
<<<<<<< HEAD
		return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
=======
		ret = -EPERM;
		if (capable(CAP_SYS_ADMIN)) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
				.nr_to_scan = LONG_MAX,
			};
			ret = ashmem_shrink_count(&ashmem_shrinker, &sc);
			ashmem_shrink_scan(&ashmem_shrinker, &sc);
		}
		break;
	default:
		return -ENOTTY;
>>>>>>> 88a2083c40fe (staging: android: ashmem: Get rid of the big mutex lock)
	}

	return -ENOTTY;
}

/* support of 32bit userspace on 64bit platforms */
#ifdef CONFIG_COMPAT
static long compat_ashmem_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	switch (cmd) {
	case COMPAT_ASHMEM_SET_SIZE:
		cmd = ASHMEM_SET_SIZE;
		break;
	case COMPAT_ASHMEM_SET_PROT_MASK:
		cmd = ASHMEM_SET_PROT_MASK;
		break;
	}
	return ashmem_ioctl(file, cmd, arg);
}
#endif

static const struct file_operations ashmem_fops = {
	.owner = THIS_MODULE,
	.open = ashmem_open,
	.release = ashmem_release,
	.read_iter = ashmem_read_iter,
	.llseek = ashmem_llseek,
	.mmap = ashmem_mmap,
	.unlocked_ioctl = ashmem_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ashmem_ioctl,
#endif
};

static struct miscdevice ashmem_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ashmem",
	.fops = &ashmem_fops,
};

static int __init ashmem_init(void)
{
	int ret;

	ashmem_area_cachep = kmem_cache_create("ashmem_area_cache",
					       sizeof(struct ashmem_area),
					       0, 0, NULL);
	if (unlikely(!ashmem_area_cachep)) {
		pr_err("failed to create slab cache\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = misc_register(&ashmem_misc);
	if (unlikely(ret)) {
		pr_err("failed to register misc device!\n");
		goto out_free1;
	}

	pr_info("initialized\n");

	return 0;

out_free1:
	kmem_cache_destroy(ashmem_area_cachep);
out:
	return ret;
}
device_initcall(ashmem_init);
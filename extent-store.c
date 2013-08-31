#include "bcache.h"
#include "btree.h"
#include "request.h"

#include <linux/bcache-ioctl.h>
#include <linux/bio.h>
#include <linux/device.h>
#include <linux/hash.h>
#include <linux/idr.h>
#include <linux/ioctl.h>
#include <linux/module.h>

static struct class *bch_extent_class;
static int bch_extent_major;
static DEFINE_IDR(bch_extent_minor);

struct bch_ioctl_read_op {
	struct bch_ioctl_read	i;
	struct closure		cl;
	struct btree_op		op;
	struct cache_set	*c;
	struct bio		*bio;

	size_t			extent_buf_done;
	int			io_error;
	ssize_t			result;
};

static void bch_cache_read_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct bch_ioctl_read_op *op = container_of(cl,
				struct bch_ioctl_read_op, cl);

	if (error)
		op->io_error = error;

	bch_bbio_endio(op->c, bio, error, "reading from cache");
}

static int bch_ioctl_read_fn(struct btree_op *b_op, struct btree *b,
			     struct bkey *k)
{
	struct bch_ioctl_read_op *op = container_of(b_op,
			struct bch_ioctl_read_op, op);
	struct bio *n, *bio = op->bio;
	struct bkey *bio_key, user_key;
	unsigned ptr = 0;

	if (bkey_cmp(k, &KEY(op->i.inode, bio->bi_iter.bi_sector, 0)) <= 0)
		return MAP_CONTINUE;

	/*
	 * Holes return 0s to userspace (from the zero_fill_bio(), and userspace
	 * can detect the hole by noticing the missing key.
	 */
	if (KEY_INODE(k) != op->i.inode ||
	    KEY_START(k) >= bio_end_sector(bio)) {
		/* Completely missed */
		op->result += bio->bi_iter.bi_size;
		bio_endio(bio, 0);
		return MAP_DONE;
	}

	if (KEY_START(k) > bio->bi_iter.bi_sector) {
		op->result += KEY_START(k) - bio->bi_iter.bi_sector;
		bio_advance(bio, KEY_START(k) - bio->bi_iter.bi_sector);
	}

	if (!KEY_SIZE(k))
		return MAP_CONTINUE;

	n = bio_next_split(bio, min_t(uint64_t, INT_MAX,
				      KEY_OFFSET(k) - bio->bi_iter.bi_sector),
			   GFP_NOIO, b->c->bio_split);

	bio_key = &container_of(n, struct bbio, bio)->key;
	bch_bkey_copy_single_ptr(bio_key, k, ptr);

	/*
	 * Trim the key to match what we're actually reading; then we copy the
	 * key out to userspace:
	 */
	bch_cut_front(&KEY(op->i.inode, n->bi_iter.bi_sector, 0), bio_key);
	bch_cut_back(&KEY(op->i.inode, bio_end_sector(n), 0), bio_key);

	BUG_ON(KEY_START(bio_key) < op->i.offset);
	BUG_ON(KEY_OFFSET(bio_key) > op->i.offset + op->i.sectors);

	user_key = *bio_key;
	SET_KEY_PTRS(&user_key, 0);

	if (op->extent_buf_done + bkey_bytes(&user_key) > op->i.extent_buf_size) {
		bio_put(n);
		bio_endio(bio, 0);
		return -ENOSPC;
	}

	if (copy_to_user((void * __user) op->i.extent_buf + op->extent_buf_done,
			 &user_key, bkey_bytes(&user_key))) {
		bio_put(n);
		bio_endio(bio, 0);
		return -EFAULT;
	}

	op->extent_buf_done += bkey_bytes(&user_key);
	op->result += n->bi_iter.bi_size;

	n->bi_end_io	= bch_cache_read_endio;
	n->bi_private	= &op->cl;

	__bch_submit_bbio(n, b->c);
	return n == bio ? MAP_DONE : MAP_CONTINUE;
}

static long bch_ioctl_read(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_read *user_read = (void __user *) arg;
	struct bch_ioctl_read_op op;
	size_t done = 0;
	int ret = 0;

	memset(&op, 0, sizeof(op));
	closure_init_stack(&op.cl);
	bch_btree_op_init(&op.op, -1);
	op.c = c;

	if (copy_from_user(&op.i, user_read, sizeof(op.i)))
		return -EFAULT;

	while (!ret && done < op.i.sectors) {
		unsigned long uaddr = (unsigned long) op.i.buf + (done << 9);
		size_t bytes_left = (op.i.sectors - done) << 9;

		op.bio = bio_alloc_bioset(GFP_KERNEL,
				min_t(size_t, BIO_MAX_PAGES,
				      DIV_ROUND_UP(bytes_left, PAGE_SIZE)),
				c->bio_split);

		ret = bio_get_user_pages(op.bio, uaddr, bytes_left, 1);
		if (ret < 0) {
			bio_put(op.bio);
			ret = -ENOMEM;
			break;
		}

		op.bio->bi_iter.bi_sector = op.i.offset + done;
		done += bio_sectors(op.bio);

		zero_fill_bio(op.bio);

		ret = bch_btree_map_keys(&op.op, c, BTREE_ID_EXTENTS,
					 &KEY(op.i.inode, op.i.offset, 0),
					 bch_ioctl_read_fn, MAP_END_KEY);
		BUG_ON(ret == MAP_CONTINUE);
	}

	closure_sync(&op.cl); /* wait for io */

	if (put_user(op.extent_buf_done / sizeof(u64),
		     &user_read->extents_found))
		return -EFAULT;

	if (op.io_error)
		return op.io_error;

	if (op.result)
		return op.result;

	if (ret < 0)
		return ret;

	return 0;
}

static long bch_ioctl_write(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_write *user_write = (void __user *) arg;
	struct bch_ioctl_write i;
	struct closure cl;
	size_t done = 0;
	int ret = 0;

	if (copy_from_user(&i, user_write, sizeof(i)))
		return -EFAULT;

	closure_init_stack(&cl);

	while (!ret && done < KEY_SIZE(&i.extent)) {
		unsigned long uaddr = (unsigned long) i.buf + (done << 9);
		size_t bytes_left = (KEY_SIZE(&i.extent) - done) << 9;
		struct data_insert_op op;

		memset(&op, 0, offsetof(struct data_insert_op, insert_keys));
		op.c		= c;
		op.inode	= KEY_INODE(&i.extent);
		op.version	= KEY_VERSION(&i.extent);
		op.write_point	= hash_long((unsigned long) current, 16);

		op.bio = bio_alloc_bioset(GFP_KERNEL,
				min_t(size_t, BIO_MAX_PAGES,
				      DIV_ROUND_UP(bytes_left, PAGE_SIZE)),
				c->bio_split);

		ret = bio_get_user_pages(op.bio, uaddr, bytes_left, 0);
		if (ret < 0) {
			bio_put(op.bio);
			ret = -ENOMEM;
			break;
		}

		op.bio->bi_iter.bi_sector = KEY_START(&i.extent) + done;
		done += bio_sectors(op.bio);

		closure_call(&op.cl, bch_data_insert, NULL, &cl);
		closure_sync(&cl);
		bio_put(op.bio);

		if (op.error)
			return op.error;
	}

	return done;
}

struct bch_ioctl_list_extents_op {
	struct bch_ioctl_list_extents	i;
	struct btree_op		op;

	size_t			buf_done;
	ssize_t			result;
};

static int bch_ioctl_list_extents_fn(struct btree_op *b_op, struct btree *b,
				     struct bkey *k)
{
	struct bch_ioctl_list_extents_op *op = container_of(b_op,
				struct bch_ioctl_list_extents_op, op);
	struct bkey user_key;

	if (bkey_cmp(k, &op->i.end) >= 0) {
		op->result = 0;
		return MAP_DONE;
	}

	if (!KEY_SIZE(k))
		return MAP_CONTINUE;

	user_key = *k;
	SET_KEY_PTRS(&user_key, 0);

	if (op->buf_done + bkey_bytes(&user_key) > op->i.buf_size)
		return MAP_DONE;

	if (copy_to_user((void * __user) op->i.buf + op->buf_done,
			 &user_key, bkey_bytes(&user_key)))
		return -EFAULT;

	op->buf_done += bkey_bytes(&user_key);
	return MAP_CONTINUE;
}

static long bch_ioctl_list_extents(struct cache_set *c, unsigned long arg)
{
	struct bch_ioctl_list_extents *user_i = (void __user *) arg;
	struct bch_ioctl_list_extents_op op;
	int ret;

	memset(&op, 0, sizeof(op));
	bch_btree_op_init(&op.op, -1);
	op.result = 1;

	if (copy_from_user(&op.i, user_i, sizeof(op.i)))
		return -EFAULT;

	ret = bch_btree_map_keys(&op.op, c, BTREE_ID_EXTENTS,
				 PRECEDING_KEY(&op.i.start),
				 bch_ioctl_list_extents_fn, MAP_END_KEY);
	BUG_ON(ret == MAP_CONTINUE);

	if (ret)
		return ret;

	if (put_user(op.buf_done / sizeof(u64), &user_i->extents_found))
		return -EFAULT;

	return op.result;
}

static long bch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cache_set *c = file->private_data;

	switch (cmd) {
	case BCH_IOCTL_READ:
		return bch_ioctl_read(c, arg);
	case BCH_IOCTL_WRITE:
		return bch_ioctl_write(c, arg);
	case BCH_IOCTL_LIST_EXTENTS:
		return bch_ioctl_list_extents(c, arg);
	}

	return -ENOSYS;
}

static int bch_extent_open(struct inode *inode, struct file *file)
{
	struct cache_set *c;
	int ret = 0;

	mutex_lock(&bch_register_lock);

	c = idr_find(&bch_extent_minor, iminor(inode));
	WARN_ON(!c);

	if (!c || test_bit(CACHE_SET_UNREGISTERING, &c->flags)) {
		ret = -ENXIO;
		goto out;
	}

	closure_get(&c->cl);
	file->private_data = c;
out:
	mutex_unlock(&bch_register_lock);

	return ret;
}

static int bch_extent_release(struct inode *inode, struct file *file)
{
	struct cache_set *c = file->private_data;
	closure_put(&c->cl);
	return 0;
}

static struct file_operations bch_extent_store = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch_ioctl,
	.open		= bch_extent_open,
	.release	= bch_extent_release,
};

int bch_extent_store_init_cache_set(struct cache_set *c)
{
	c->minor = idr_alloc(&bch_extent_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	pr_info("creating dev %u", c->minor);

	device_create(bch_extent_class, NULL,
		      MKDEV(bch_extent_major, c->minor), NULL,
		      "bcache_extent%d", c->minor);
	return 0;
}

void bch_extent_store_exit(void)
{
	if (bch_extent_major)
		unregister_chrdev(bch_extent_major, "bcache_extent_store");
}

int bch_extent_store_init(void)
{
	bch_extent_major = register_chrdev(0, "bcache_extent_store",
					      &bch_extent_store);
	if (bch_extent_major < 0)
		return bch_extent_major;

	bch_extent_class = class_create(THIS_MODULE, "bcache_extent_store");
	if (IS_ERR(bch_extent_class)) {
		unregister_chrdev(bch_extent_major, "bcache_extent_store");
		return PTR_ERR(bch_extent_class);
	}

	return 0;
}

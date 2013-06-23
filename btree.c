/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 *
 * Uses a block device as cache for other block devices; optimized for SSDs.
 * All allocation is done in buckets, which should match the erase block size
 * of the device.
 *
 * Buckets containing cached data are kept on a heap sorted by priority;
 * bucket priority is increased on cache hit, and periodically all the buckets
 * on the heap have their priority scaled down. This currently is just used as
 * an LRU but in the future should allow for more intelligent heuristics.
 *
 * Buckets have an 8 bit counter; freeing is accomplished by incrementing the
 * counter. Garbage collection is used to remove stale pointers.
 *
 * Indexing is done via a btree; nodes are not necessarily fully sorted, rather
 * as keys are inserted we only sort the pages that have not yet been written.
 * When garbage collection is run, we resort the entire node.
 *
 * All configuration is done via sysfs; see Documentation/bcache.txt.
 */

#include "bcache.h"
#include "btree.h"
#include "debug.h"
#include "request.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <trace/events/bcache.h>

/*
 * Todo:
 * register_bcache: Return errors out to userspace correctly
 *
 * Writeback: don't undirty key until after a cache flush
 *
 * Create an iterator for key pointers
 *
 * On btree write error, mark bucket such that it won't be freed from the cache
 *
 * Journalling:
 *   Check for bad keys in replay
 *   Propagate barriers
 *   Refcount journal entries in journal_replay
 *
 * Garbage collection:
 *   Finish incremental gc
 *   Gc should free old UUIDs, data for invalid UUIDs
 *
 * Provide a way to list backing device UUIDs we have data cached for, and
 * probably how long it's been since we've seen them, and a way to invalidate
 * dirty data for devices that will never be attached again
 *
 * Keep 1 min/5 min/15 min statistics of how busy a block device has been, so
 * that based on that and how much dirty data we have we can keep writeback
 * from being starved
 *
 * Add a tracepoint or somesuch to watch for writeback starvation
 *
 * When btree depth > 1 and splitting an interior node, we have to make sure
 * alloc_bucket() cannot fail. This should be true but is not completely
 * obvious.
 *
 * Make sure all allocations get charged to the root cgroup
 *
 * Plugging?
 *
 * If data write is less than hard sector size of ssd, round up offset in open
 * bucket to the next whole sector
 *
 * Also lookup by cgroup in get_open_bucket()
 *
 * Superblock needs to be fleshed out for multiple cache devices
 *
 * Add a sysfs tunable for the number of writeback IOs in flight
 *
 * Add a sysfs tunable for the number of open data buckets
 *
 * IO tracking: Can we track when one process is doing io on behalf of another?
 * IO tracking: Don't use just an average, weigh more recent stuff higher
 *
 * Test module load/unload
 */

static const char * const op_types[] = {
	"insert", "replace"
};

static const char *op_type(struct btree_op *op)
{
	return op_types[op->type];
}

#define MAX_NEED_GC		64
#define MAX_SAVE_PRIO		72

#define PTR_HASH(c, k)							\
	(((k)->ptr[0] >> c->bucket_bits) | PTR_GEN(k, 0))

struct workqueue_struct *bch_gc_wq;
static struct workqueue_struct *btree_io_wq;

void bch_btree_op_init_stack(struct btree_op *op)
{
	memset(op, 0, sizeof(struct btree_op));
	op->lock = -1;
}

#define insert_lock(s, b)	((b)->level <= (s)->lock)

/*
 * These macros are for recursing down the btree - they handle the details of
 * locking and looking up nodes in the cache for you. They're best treated as
 * mere syntax when reading code that uses them.
 *
 * op->lock determines whether we take a read or a write lock at a given depth.
 * If you've got a read lock and find that you need a write lock (i.e. you're
 * going to have to split), set op->lock and return -EINTR; btree_root() will
 * call you again and you'll have the correct lock.
 */

/**
 * btree - recurse down the btree on a specified key
 * @fn:		function to call, which will be passed the child node
 * @key:	key to recurse on
 * @b:		parent btree node
 * @op:		pointer to struct btree_op
 */
#define btree(fn, key, b, op, ...)					\
({									\
	int _r, l = (b)->level - 1;					\
	bool _w = l <= (op)->lock;					\
	struct btree *_child = bch_btree_node_get((b)->c, key, l,	\
						  b->btree_id, _w);	\
	if (!IS_ERR(_child)) {						\
		_child->parent = (b);					\
		_r = bch_btree_ ## fn(_child, op, ##__VA_ARGS__);	\
		rw_unlock(_w, _child);					\
	} else								\
		_r = PTR_ERR(_child);					\
	_r;								\
})

/**
 * btree_root - call a function on the root of the btree
 * @fn:		function to call, which will be passed the child node
 * @c:		cache set
 * @op:		pointer to struct btree_op
 */
#define btree_root(fn, c, id, op, ...)					\
({									\
	int _r = -EINTR;						\
	do {								\
		struct btree *_b = (c)->btree_roots[id];		\
		bool _w = insert_lock(op, _b);				\
		rw_lock(_w, _b, _b->level);				\
		if (_b == (c)->btree_roots[id] &&			\
		    _w == insert_lock(op, _b)) {			\
			_b->parent = NULL;				\
			_r = bch_btree_ ## fn(_b, op, ##__VA_ARGS__);	\
		}							\
		rw_unlock(_w, _b);					\
		bch_cannibalize_unlock(c);				\
		if (_r == -ENOSPC) {					\
			wait_event((c)->try_wait,			\
				   !(c)->try_harder);			\
			_r = -EINTR;					\
		}							\
	} while (_r == -EINTR);						\
									\
	_r;								\
})

/* Btree key manipulation */

void __bkey_put(struct cache_set *c, struct bkey *k)
{
	unsigned i;

	for (i = 0; i < KEY_PTRS(k); i++)
		if (ptr_available(c, k, i))
			atomic_dec_bug(&PTR_BUCKET(c, k, i)->pin);
}

static void bkey_put(struct cache_set *c, struct bkey *k, int level)
{
	if ((level && KEY_OFFSET(k)) || !level)
		__bkey_put(c, k);
}

/* Btree IO */

KEY_FIELD(KEY0_PTRS,		high, 60, 3)
KEY_FIELD(KEY0_CSUM,		high, 56, 2)
KEY_FIELD(KEY0_PINNED,		high, 55, 1)
KEY_FIELD(KEY0_DIRTY,		high, 36, 1)

KEY_FIELD(KEY0_SIZE,		high, 20, 16)
KEY_FIELD(KEY0_INODE,		high, 0,  20)

static void convert_v0_keys(struct btree *b, struct bset *i)
{
	struct bkey *k;

	for (k = i->start;
	     k < end(i);
	     k = bkey_next(k)) {
		struct bkey t;
		bkey_init(&t);

		SET_KEY_PTRS(&t,	KEY0_PTRS(k));
		SET_KEY_CSUM(&t,	KEY0_CSUM(k));
		SET_KEY_PINNED(&t,	KEY0_PINNED(k));
		SET_KEY_DIRTY(&t,	KEY0_DIRTY(k));
		SET_KEY_SIZE(&t,	KEY0_SIZE(k));
		SET_KEY_INODE(&t,	KEY0_INODE(k));
		SET_KEY_OFFSET(&t,	k->low);

		*k = t;
	}
}

static uint64_t btree_csum_set(struct btree *b, struct bset *i)
{
	if (i->version < BCACHE_BSET_CSUM) {
		return csum_set(i);
	} else {
		uint64_t crc = b->key.ptr[0];
		void *data = (void *) i + 8, *end = end(i);

		crc = bch_crc64_update(crc, data, end - data);
		return crc ^ 0xffffffffffffffffULL;
	}
}

static void bch_btree_node_read_done(struct btree *b)
{
	const char *err = "bad btree header";
	struct bset *i = b->sets[0].data;
	struct btree_iter *iter;

	iter = mempool_alloc(b->c->fill_iter, GFP_NOWAIT);
	iter->size = b->c->sb.bucket_size / b->c->sb.block_size;
	iter->used = 0;

	if (!i->seq)
		goto err;

	for (;
	     b->written < btree_blocks(b) && i->seq == b->sets[0].data->seq;
	     i = write_block(b)) {
		err = "unsupported bset version";
		if (i->version > BCACHE_BSET_VERSION)
			goto err;

		err = "bad btree header";
		if (b->written + set_blocks(i, b->c) > btree_blocks(b))
			goto err;

		err = "bad magic";
		if (i->magic != bset_magic(b->c))
			goto err;

		err = "bad checksum";
		if (i->csum != btree_csum_set(b, i))
			goto err;

		err = "empty set";
		if (i != b->sets[0].data && !i->keys)
			goto err;

		if (i->version < BCACHE_BSET_KEY_v1)
			convert_v0_keys(b, i);

		bch_btree_iter_push(iter, i->start, end(i));

		b->written += set_blocks(i, b->c);
	}

	err = "corrupted btree";
	for (i = write_block(b);
	     index(i, b) < btree_blocks(b);
	     i = ((void *) i) + block_bytes(b->c))
		if (i->seq == b->sets[0].data->seq)
			goto err;

	bch_btree_sort_and_fix_extents(b, iter);

	i = b->sets[0].data;
	err = "short btree key";
	if (b->sets[0].size &&
	    bkey_cmp(&b->key, &b->sets[0].end) < 0)
		goto err;

	if (b->written < btree_blocks(b))
		bch_bset_init_next(b);
out:
	mempool_free(iter, b->c->fill_iter);
	return;
err:
	set_btree_node_io_error(b);
	bch_cache_set_error(b->c, "%s at bucket %zu, block %zu, %u keys",
			    err, PTR_BUCKET_NR(b->c, &b->key, 0),
			    index(i, b), i->keys);
	goto out;
}

static void btree_node_read_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

void bch_btree_node_read(struct btree *b)
{
	uint64_t start_time = local_clock();
	struct closure cl;
	struct bio *bio;

	trace_bcache_btree_read(b);

	closure_init_stack(&cl);

	bio = bch_bbio_alloc(b->c);
	bio->bi_rw	= REQ_META|READ_SYNC;
	bio->bi_size	= KEY_SIZE(&b->key) << 9;
	bio->bi_end_io	= btree_node_read_endio;
	bio->bi_private	= &cl;

	bch_bio_map(bio, b->sets[0].data);

	bch_submit_bbio(bio, b->c, &b->key, 0);
	closure_sync(&cl);

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
		set_btree_node_io_error(b);

	bch_bbio_free(bio, b->c);

	if (btree_node_io_error(b))
		goto err;

	bch_btree_node_read_done(b);

	spin_lock(&b->c->btree_read_time_lock);
	bch_time_stats_update(&b->c->btree_read_time, start_time);
	spin_unlock(&b->c->btree_read_time_lock);

	return;
err:
	bch_cache_set_error(b->c, "io error reading bucket %lu",
			    PTR_BUCKET_NR(b->c, &b->key, 0));
}

static void btree_complete_write(struct btree *b, struct btree_write *w)
{
	if (w->journal) {
		atomic_dec_bug(w->journal);
		__closure_wake_up(&b->c->journal.wait);
	}

	w->journal	= NULL;
}

static void __btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);
	struct btree_write *w = btree_prev_write(b);

	bch_bbio_free(b->bio, b->c);
	b->bio = NULL;
	btree_complete_write(b, w);

	if (btree_node_dirty(b))
		queue_delayed_work(btree_io_wq, &b->work,
				   msecs_to_jiffies(30000));

	closure_return(cl);
}

static void btree_node_write_done(struct closure *cl)
{
	struct btree *b = container_of(cl, struct btree, io.cl);
	struct bio_vec *bv;
	int n;

	__bio_for_each_segment(bv, b->bio, n, 0)
		__free_page(bv->bv_page);

	__btree_node_write_done(cl);
}

static void btree_node_write_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	struct btree *b = container_of(cl, struct btree, io.cl);

	if (error)
		set_btree_node_io_error(b);

	bch_bbio_count_io_errors(b->c, bio, error, "writing btree");
	closure_put(cl);
}

static void do_btree_node_write(struct btree *b)
{
	struct closure *cl = &b->io.cl;
	struct bset *i = b->sets[b->nsets].data;
	BKEY_PADDED(key) k;

	i->version	= BCACHE_BSET_VERSION;
	i->csum		= btree_csum_set(b, i);

	BUG_ON(b->bio);
	b->bio = bch_bbio_alloc(b->c);

	b->bio->bi_end_io	= btree_node_write_endio;
	b->bio->bi_private	= cl;
	b->bio->bi_rw	= REQ_META|WRITE_SYNC;
	b->bio->bi_size	= set_blocks(i, b->c) * block_bytes(b->c);
	bch_bio_map(b->bio, i);

	bkey_copy(&k.key, &b->key);
	SET_PTR_OFFSET(&k.key, 0, PTR_OFFSET(&k.key, 0) + bset_offset(b, i));

	if (!bch_bio_alloc_pages(b->bio, GFP_NOIO)) {
		int j;
		struct bio_vec *bv;
		void *base = (void *) ((unsigned long) i & ~(PAGE_SIZE - 1));

		bio_for_each_segment(bv, b->bio, j)
			memcpy(page_address(bv->bv_page),
			       base + j * PAGE_SIZE, PAGE_SIZE);

		bch_submit_bbio(b->bio, b->c, &k.key, 0);

		continue_at(cl, btree_node_write_done, NULL);
	} else {
		b->bio->bi_vcnt = 0;
		bch_bio_map(b->bio, i);

		bch_submit_bbio(b->bio, b->c, &k.key, 0);

		closure_sync(cl);
		__btree_node_write_done(cl);
	}
}

void bch_btree_node_write(struct btree *b, struct closure *parent)
{
	struct bset *i = b->sets[b->nsets].data;

	trace_bcache_btree_write(b);

	BUG_ON(current->bio_list);
	BUG_ON(b->written >= btree_blocks(b));
	BUG_ON(b->written && !i->keys);
	BUG_ON(b->sets->data->seq != i->seq);
	bch_check_key_order(b, i);

	cancel_delayed_work(&b->work);

	/* If caller isn't waiting for write, parent refcount is cache set */
	closure_lock(&b->io, parent ?: &b->c->cl);

	clear_bit(BTREE_NODE_dirty,	 &b->flags);
	change_bit(BTREE_NODE_write_idx, &b->flags);

	do_btree_node_write(b);

	b->written += set_blocks(i, b->c);
	atomic_long_add(set_blocks(i, b->c) * b->c->sb.block_size,
			&PTR_CACHE(b->c, &b->key, 0)->btree_sectors_written);

	bch_btree_sort_lazy(b);

	if (b->written < btree_blocks(b))
		bch_bset_init_next(b);
}

static void btree_node_write_work(struct work_struct *w)
{
	struct btree *b = container_of(to_delayed_work(w), struct btree, work);

	rw_lock(true, b, b->level);

	if (btree_node_dirty(b))
		bch_btree_node_write(b, NULL);
	rw_unlock(true, b);
}

static void bch_btree_leaf_dirty(struct btree *b, struct btree_op *op)
{
	struct bset *i = b->sets[b->nsets].data;
	struct btree_write *w = btree_current_write(b);

	BUG_ON(!b->written);
	BUG_ON(!i->keys);

	if (!btree_node_dirty(b))
		queue_delayed_work(btree_io_wq, &b->work, 30 * HZ);

	set_btree_node_dirty(b);

	if (op->journal) {
		if (w->journal &&
		    journal_pin_cmp(b->c, w, op)) {
			atomic_dec_bug(w->journal);
			w->journal = NULL;
		}

		if (!w->journal) {
			w->journal = op->journal;
			atomic_inc(w->journal);
		}
	}

	/* Force write if set is too big */
	if (set_bytes(i) > PAGE_SIZE - 48 &&
	    !current->bio_list)
		bch_btree_node_write(b, NULL);
}

/*
 * Btree in memory cache - allocation/freeing
 * mca -> memory cache
 */

static void mca_reinit(struct btree *b)
{
	unsigned i;

	b->flags	= 0;
	b->written	= 0;
	b->nsets	= 0;

	for (i = 0; i < MAX_BSETS; i++)
		b->sets[i].size = 0;
	/*
	 * Second loop starts at 1 because b->sets[0]->data is the memory we
	 * allocated
	 */
	for (i = 1; i < MAX_BSETS; i++)
		b->sets[i].data = NULL;
}

void bch_recalc_btree_reserve(struct cache_set *c)
{
	unsigned i, reserve = 16;

	if (!c->btree_roots[0])
		reserve += 8;

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i])
			reserve += min_t(unsigned, 1,
					 c->btree_roots[i]->level) * 8;

	c->btree_root_reserve = reserve;
}

#define mca_can_free(c)						\
	max_t(int, 0, c->bucket_cache_used - c->btree_root_reserve)

static void mca_data_free(struct btree *b)
{
	struct bset_tree *t = b->sets;
	BUG_ON(!closure_is_unlocked(&b->io.cl));

	if (bset_prev_bytes(b) < PAGE_SIZE)
		kfree(t->prev);
	else
		free_pages((unsigned long) t->prev,
			   get_order(bset_prev_bytes(b)));

	if (bset_tree_bytes(b) < PAGE_SIZE)
		kfree(t->tree);
	else
		free_pages((unsigned long) t->tree,
			   get_order(bset_tree_bytes(b)));

	free_pages((unsigned long) t->data, b->page_order);

	t->prev = NULL;
	t->tree = NULL;
	t->data = NULL;
	list_move(&b->list, &b->c->btree_cache_freed);
	b->c->bucket_cache_used--;
}

static void mca_bucket_free(struct btree *b)
{
	BUG_ON(btree_node_dirty(b));

	b->key.ptr[0] = 0;
	hlist_del_init_rcu(&b->hash);
	list_move(&b->list, &b->c->btree_cache_freeable);
}

static unsigned btree_order(struct bkey *k)
{
	return ilog2(KEY_SIZE(k) / PAGE_SECTORS ?: 1);
}

static void mca_data_alloc(struct btree *b, struct bkey *k, gfp_t gfp)
{
	struct bset_tree *t = b->sets;
	BUG_ON(t->data);

	b->page_order = max_t(unsigned,
			      ilog2(b->c->btree_pages),
			      btree_order(k));

	t->data = (void *) __get_free_pages(gfp, b->page_order);
	if (!t->data)
		goto err;

	t->tree = bset_tree_bytes(b) < PAGE_SIZE
		? kmalloc(bset_tree_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_tree_bytes(b)));
	if (!t->tree)
		goto err;

	t->prev = bset_prev_bytes(b) < PAGE_SIZE
		? kmalloc(bset_prev_bytes(b), gfp)
		: (void *) __get_free_pages(gfp, get_order(bset_prev_bytes(b)));
	if (!t->prev)
		goto err;

	list_move(&b->list, &b->c->btree_cache);
	b->c->bucket_cache_used++;
	return;
err:
	mca_data_free(b);
}

static struct btree *mca_bucket_alloc(struct cache_set *c,
				      struct bkey *k, gfp_t gfp)
{
	struct btree *b = kzalloc(sizeof(struct btree), gfp);
	if (!b)
		return NULL;

	init_rwsem(&b->lock);
	lockdep_set_novalidate_class(&b->lock);
	INIT_LIST_HEAD(&b->list);
	INIT_DELAYED_WORK(&b->work, btree_node_write_work);
	b->c = c;
	closure_init_unlocked(&b->io);

	mca_data_alloc(b, k, gfp);
	return b;
}

static int mca_reap(struct btree *b, unsigned min_order, bool flush)
{
	struct closure cl;

	closure_init_stack(&cl);
	lockdep_assert_held(&b->c->bucket_lock);

	if (!down_write_trylock(&b->lock))
		return -ENOMEM;

	BUG_ON(btree_node_dirty(b) && !b->sets[0].data);

	if (b->page_order < min_order ||
	    (!flush &&
	     (btree_node_dirty(b) ||
	      atomic_read(&b->io.cl.remaining) != -1))) {
		rw_unlock(true, b);
		return -ENOMEM;
	}

	if (btree_node_dirty(b)) {
		bch_btree_node_write(b, &cl);
		closure_sync(&cl);
	}

	/* wait for any in flight btree write */
	closure_wait_event(&b->io.wait, &cl,
			   atomic_read(&b->io.cl.remaining) == -1);

	return 0;
}

static int bch_mca_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
	struct cache_set *c = container_of(shrink, struct cache_set, shrink);
	struct btree *b, *t;
	unsigned long i, nr = sc->nr_to_scan;

	if (c->shrinker_disabled)
		return 0;

	if (c->try_harder)
		return 0;

	/*
	 * If nr == 0, we're supposed to return the number of items we have
	 * cached. Not allowed to return -1.
	 */
	if (!nr)
		return mca_can_free(c) * c->btree_pages;

	/* Return -1 if we can't do anything right now */
	if (sc->gfp_mask & __GFP_WAIT)
		mutex_lock(&c->bucket_lock);
	else if (!mutex_trylock(&c->bucket_lock))
		return -1;

	/*
	 * It's _really_ critical that we don't free too many btree nodes - we
	 * have to always leave ourselves a reserve. The reserve is how we
	 * guarantee that allocating memory for a new btree node can always
	 * succeed, so that inserting keys into the btree can always succeed and
	 * IO can always make forward progress:
	 */
	nr /= c->btree_pages;
	nr = min_t(unsigned long, nr, mca_can_free(c));

	i = 0;
	list_for_each_entry_safe(b, t, &c->btree_cache_freeable, list) {
		if (!nr)
			break;

		if (++i > 3 &&
		    !mca_reap(b, 0, false)) {
			mca_data_free(b);
			rw_unlock(true, b);
			--nr;
		}
	}

	/*
	 * Can happen right when we first start up, before we've read in any
	 * btree nodes
	 */
	if (list_empty(&c->btree_cache))
		goto out;

	for (i = 0; nr && i < c->bucket_cache_used; i++) {
		b = list_first_entry(&c->btree_cache, struct btree, list);
		list_rotate_left(&c->btree_cache);

		if (!b->accessed &&
		    !mca_reap(b, 0, false)) {
			mca_bucket_free(b);
			mca_data_free(b);
			rw_unlock(true, b);
			--nr;
		} else
			b->accessed = 0;
	}
out:
	nr = mca_can_free(c) * c->btree_pages;
	mutex_unlock(&c->bucket_lock);
	return nr;
}

void bch_btree_cache_free(struct cache_set *c)
{
	struct btree *b;
	struct closure cl;
	closure_init_stack(&cl);

	if (c->shrink.list.next)
		unregister_shrinker(&c->shrink);

	mutex_lock(&c->bucket_lock);

#ifdef CONFIG_BCACHE_DEBUG
	if (c->verify_data)
		list_move(&c->verify_data->list, &c->btree_cache);
#endif

	list_splice(&c->btree_cache_freeable,
		    &c->btree_cache);

	while (!list_empty(&c->btree_cache)) {
		b = list_first_entry(&c->btree_cache, struct btree, list);

		if (btree_node_dirty(b))
			btree_complete_write(b, btree_current_write(b));
		clear_bit(BTREE_NODE_dirty, &b->flags);

		mca_data_free(b);
	}

	while (!list_empty(&c->btree_cache_freed)) {
		b = list_first_entry(&c->btree_cache_freed,
				     struct btree, list);
		list_del(&b->list);
		cancel_delayed_work_sync(&b->work);
		kfree(b);
	}

	mutex_unlock(&c->bucket_lock);
}

int bch_btree_cache_alloc(struct cache_set *c)
{
	unsigned i;

	/* XXX: doesn't check for errors */

	closure_init_unlocked(&c->gc);

	bch_recalc_btree_reserve(c);

	for (i = 0; i < c->btree_root_reserve; i++)
		mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL);

	list_splice_init(&c->btree_cache,
			 &c->btree_cache_freeable);

#ifdef CONFIG_BCACHE_DEBUG
	mutex_init(&c->verify_lock);

	c->verify_data = mca_bucket_alloc(c, &ZERO_KEY, GFP_KERNEL);

	if (c->verify_data &&
	    c->verify_data->sets[0].data)
		list_del_init(&c->verify_data->list);
	else
		c->verify_data = NULL;
#endif

	c->shrink.shrink = bch_mca_shrink;
	c->shrink.seeks = 4;
	c->shrink.batch = c->btree_pages * 2;
	register_shrinker(&c->shrink);

	return 0;
}

/* Btree in memory cache - hash table */

static struct hlist_head *mca_hash(struct cache_set *c, struct bkey *k)
{
	return &c->bucket_hash[hash_32(PTR_HASH(c, k), BUCKET_HASH_BITS)];
}

static struct btree *mca_find(struct cache_set *c, struct bkey *k)
{
	struct btree *b;

	rcu_read_lock();
	hlist_for_each_entry_rcu(b, mca_hash(c, k), hash)
		if (PTR_HASH(c, &b->key) == PTR_HASH(c, k))
			goto out;
	b = NULL;
out:
	rcu_read_unlock();
	return b;
}

static struct btree *mca_cannibalize(struct cache_set *c, struct bkey *k)
{
	struct btree *b;

	trace_bcache_btree_cache_cannibalize(c);

	if (!c->try_harder) {
		c->try_harder = current;
		c->try_harder_start = local_clock();
	} else if (c->try_harder != current)
		return ERR_PTR(-ENOSPC);

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, btree_order(k), false))
			return b;

	list_for_each_entry_reverse(b, &c->btree_cache, list)
		if (!mca_reap(b, btree_order(k), true))
			return b;

	return ERR_PTR(-ENOMEM);
}

/*
 * We can only have one thread cannibalizing other cached btree nodes at a time,
 * or we'll deadlock. We use an open coded mutex to ensure that, which a
 * cannibalize_bucket() will take. This means every time we unlock the root of
 * the btree, we need to release this lock if we have it held.
 */
static void bch_cannibalize_unlock(struct cache_set *c)
{
	if (c->try_harder == current) {
		bch_time_stats_update(&c->try_harder_time, c->try_harder_start);
		c->try_harder = NULL;
		wake_up(&c->try_wait);
	}
}

static struct btree *mca_alloc(struct cache_set *c, struct bkey *k,
			       int level, enum btree_id id)
{
	struct btree *b;

	BUG_ON(current->bio_list);

	lockdep_assert_held(&c->bucket_lock);

	if (mca_find(c, k))
		return NULL;

	/* btree_free() doesn't free memory; it sticks the node on the end of
	 * the list. Check if there's any freed nodes there:
	 */
	list_for_each_entry(b, &c->btree_cache_freeable, list)
		if (!mca_reap(b, btree_order(k), false))
			goto out;

	/* We never free struct btree itself, just the memory that holds the on
	 * disk node. Check the freed list before allocating a new one:
	 */
	list_for_each_entry(b, &c->btree_cache_freed, list)
		if (!mca_reap(b, 0, false)) {
			mca_data_alloc(b, k, __GFP_NOWARN|GFP_NOIO);
			if (!b->sets[0].data)
				goto err;
			else
				goto out;
		}

	b = mca_bucket_alloc(c, k, __GFP_NOWARN|GFP_NOIO);
	if (!b)
		goto err;

	BUG_ON(!down_write_trylock(&b->lock));
	if (!b->sets->data)
		goto err;
out:
	BUG_ON(!closure_is_unlocked(&b->io.cl));

	bkey_copy(&b->key, k);
	list_move(&b->list, &c->btree_cache);
	hlist_del_init_rcu(&b->hash);
	hlist_add_head_rcu(&b->hash, mca_hash(c, k));

	lock_set_subclass(&b->lock.dep_map, level + 1, _THIS_IP_);
	b->level	= level;
	b->btree_id	= id;
	b->parent	= (void *) ~0UL;

	mca_reinit(b);

	return b;
err:
	if (b)
		rw_unlock(true, b);

	b = mca_cannibalize(c, k);
	if (!IS_ERR(b))
		goto out;

	return b;
}

/**
 * bch_btree_node_get - find a btree node in the cache and lock it, reading it
 * in from disk if necessary.
 *
 * If IO is necessary, it uses the closure embedded in struct btree_op to wait;
 * if that closure is in non blocking mode, will return -EAGAIN.
 *
 * The btree node will have either a read or a write lock held, depending on
 * level and op->lock.
 */
struct btree *bch_btree_node_get(struct cache_set *c, struct bkey *k,
				 int level, enum btree_id id, bool write)
{
	int i = 0;
	struct btree *b;

	BUG_ON(level < 0);
retry:
	b = mca_find(c, k);

	if (!b) {
		if (current->bio_list)
			return ERR_PTR(-EAGAIN);

		mutex_lock(&c->bucket_lock);
		b = mca_alloc(c, k, level, id);
		mutex_unlock(&c->bucket_lock);

		if (!b)
			goto retry;
		if (IS_ERR(b))
			return b;

		bch_btree_node_read(b);

		if (!write)
			downgrade_write(&b->lock);
	} else {
		rw_lock(write, b, level);
		if (PTR_HASH(c, &b->key) != PTR_HASH(c, k)) {
			rw_unlock(write, b);
			goto retry;
		}
		BUG_ON(b->level != level);
	}

	b->accessed = 1;

	for (; i <= b->nsets && b->sets[i].size; i++) {
		prefetch(b->sets[i].tree);
		prefetch(b->sets[i].data);
	}

	for (; i <= b->nsets; i++)
		prefetch(b->sets[i].data);

	if (btree_node_io_error(b)) {
		rw_unlock(write, b);
		return ERR_PTR(-EIO);
	}

	BUG_ON(!b->written);

	return b;
}

static void btree_node_prefetch(struct cache_set *c, struct bkey *k,
				int level, enum btree_id id)
{
	struct btree *b;

	mutex_lock(&c->bucket_lock);
	b = mca_alloc(c, k, level, id);
	mutex_unlock(&c->bucket_lock);

	if (!IS_ERR_OR_NULL(b)) {
		bch_btree_node_read(b);
		rw_unlock(true, b);
	}
}

/* Btree alloc */

static void btree_node_free(struct btree *b)
{
	unsigned i;

	trace_bcache_btree_node_free(b);

	if (btree_node_dirty(b))
		btree_complete_write(b, btree_current_write(b));
	clear_bit(BTREE_NODE_dirty, &b->flags);

	cancel_delayed_work(&b->work);

	mutex_lock(&b->c->bucket_lock);

	for (i = 0; i < KEY_PTRS(&b->key); i++)
		BUG_ON(atomic_read(&PTR_BUCKET(b->c, &b->key, i)->pin));

	bch_bucket_free(b->c, &b->key);
	mca_bucket_free(b);
	mutex_unlock(&b->c->bucket_lock);
}

struct btree *bch_btree_node_alloc(struct cache_set *c,
				   int level, enum btree_id id)
{
	BKEY_PADDED(key) k;
	struct btree *b = ERR_PTR(-EAGAIN);

	mutex_lock(&c->bucket_lock);
retry:
	if (__bch_bucket_alloc_set(c, WATERMARK_METADATA, &k.key, 1, true))
		goto err;

	SET_KEY_SIZE(&k.key, c->btree_pages * PAGE_SECTORS);

	b = mca_alloc(c, &k.key, level, id);
	if (IS_ERR(b))
		goto err_free;

	if (!b) {
		cache_bug(c,
			"Tried to allocate bucket that was in btree cache");
		__bkey_put(c, &k.key);
		goto retry;
	}

	b->accessed = 1;
	bch_bset_init_next(b);

	mutex_unlock(&c->bucket_lock);

	trace_bcache_btree_node_alloc(b);
	return b;
err_free:
	bch_bucket_free(c, &k.key);
	__bkey_put(c, &k.key);
err:
	mutex_unlock(&c->bucket_lock);

	trace_bcache_btree_node_alloc_fail(b);
	return b;
}

static struct btree *btree_node_alloc_replacement(struct btree *b)
{
	struct btree *n = bch_btree_node_alloc(b->c, b->level, b->btree_id);
	if (!IS_ERR_OR_NULL(n))
		bch_btree_sort_into(b, n);

	return n;
}

/* Garbage collection */

uint8_t __bch_btree_mark_key(struct cache_set *c, int level, struct bkey *k)
{
	uint8_t stale = 0;
	unsigned i;
	struct bucket *g;

	for (i = 0; i < KEY_PTRS(k); i++) {
		if (!ptr_available(c, k, i))
			continue;

		g = PTR_BUCKET(c, k, i);

		if (gen_after(g->gc_gen, PTR_GEN(k, i)))
			g->gc_gen = PTR_GEN(k, i);

		if (ptr_stale(c, k, i)) {
			stale = max(stale, ptr_stale(c, k, i));
			continue;
		}

		cache_bug_on(GC_MARK(g) &&
			     (GC_MARK(g) == GC_MARK_METADATA) != (level != 0),
			     c, "inconsistent ptrs: mark = %llu, level = %i",
			     GC_MARK(g), level);

		if (level)
			SET_GC_MARK(g, GC_MARK_METADATA);
		else if (KEY_DIRTY(k))
			SET_GC_MARK(g, GC_MARK_DIRTY);

		/* guard against overflow */
		SET_GC_SECTORS_USED(g, min_t(unsigned,
					     GC_SECTORS_USED(g) + KEY_SIZE(k),
					     (1 << 14) - 1));

		BUG_ON(!GC_SECTORS_USED(g));
	}

	return stale;
}

#define btree_mark_key(b, k)	__bch_btree_mark_key(b->c, b->level, k)

static bool btree_gc_mark_node(struct btree *b, struct gc_stat *gc)
{
	uint8_t stale = 0;
	unsigned keys = 0, good_keys = 0;
	struct bcache_device *d = NULL;
	struct bkey *k;
	struct btree_iter iter;
	struct bset_tree *t;

	gc->nodes++;

	if (b->btree_id != BTREE_ID_EXTENTS && b->level == 0)
		return 0;

	for_each_key_filter(b, k, &iter, bch_ptr_invalid) {
		if (d && KEY_INODE(k) != KEY_INODE(&d->inode.k)) {
			if (d)
				closure_put(&d->cl);

			d = bch_dev_get_by_inode(b->c, KEY_INODE(k));
		}

		stale = max(stale, btree_mark_key(b, k));
		keys++;

		if (bch_ptr_bad(b, k))
			continue;

		gc->key_bytes += bkey_u64s(k);
		gc->nkeys++;
		good_keys++;

		gc->data += KEY_SIZE(k);
		if (KEY_DIRTY(k))
			gc->dirty += KEY_SIZE(k);
	}

	if (d)
		closure_put(&d->cl);

	for (t = b->sets; t <= &b->sets[b->nsets]; t++)
		btree_bug_on(t->size &&
			     bset_written(b, t) &&
			     bkey_cmp(&b->key, &t->end) < 0,
			     b, "found short btree key in gc");

	if (b->c->gc_always_rewrite)
		return true;

	if (stale > 10)
		return true;

	if ((keys - good_keys) * 2 > keys)
		return true;

	return false;
}

#define GC_MERGE_NODES	4U

struct gc_merge_info {
	struct btree	*b;
	struct btree	*n;
	unsigned	keys;
	unsigned	stale;
};

static int btree_gc_coalesce(struct btree *b, struct btree_op *op,
			     struct keylist *keylist, struct gc_stat *gc,
			     struct gc_merge_info *r)
{
	unsigned i, nodes = 0, keys = 0, blocks;
	struct closure cl;

	closure_init_stack(&cl);

	while (nodes < GC_MERGE_NODES && !IS_ERR_OR_NULL(r[nodes].b))
		keys += r[nodes++].keys;

	blocks = btree_default_blocks(b->c) * 2 / 3;

	if (nodes < 2 ||
	    __set_blocks(b->sets[0].data, keys, b->c) > blocks * (nodes - 1))
		return 0;

	for (i = 0; i < nodes; i++)
		r[i].n = NULL;

	for (i = nodes - 1; i > 0; --i) {
		r[i].n = btree_node_alloc_replacement(r[i].b);
		if (!r[i].n)
			goto out_nocoalesce;
	}

	for (i = nodes - 1; i > 0; --i) {
		struct bset *n1 = r[i].n->sets->data;
		struct bset *n2 = i - 1
			? r[i - 1].n->sets->data
			: r[i - 1].b->sets->data;
		struct bkey *k, *last = NULL;

		keys = 0;

		if (i == 1) {
			/*
			 * Last node we're not getting rid of - we're getting
			 * rid of the node at r[0]. Have to try and fit all of
			 * the remaining keys into this node; we can't ensure
			 * they will always fit due to rounding and variable
			 * length keys (shouldn't be possible in practice,
			 * though)
			 */
			if (__set_blocks(n1, n1->keys + n2->keys,
					 b->c) > btree_blocks(r[i].n))
				goto out_nocoalesce;

			keys = n2->keys;
			/* Take the key of the node we're getting rid of */
			last = &r->b->key;
		} else
			for (k = n2->start;
			     k < end(n2);
			     k = bkey_next(k)) {
				if (__set_blocks(n1, n1->keys + keys +
						 bkey_u64s(k), b->c) > blocks)
					break;

				last = k;
				keys += bkey_u64s(k);
			}

		BUG_ON(__set_blocks(n1, n1->keys + keys,
				    b->c) > btree_blocks(r[i].n));

		if (last)
			bkey_copy_key(&r[i].n->key, last);

		memcpy(end(n1),
		       n2->start,
		       (void *) node(n2, keys) - (void *) n2->start);

		n1->keys += keys;
		r[i].keys = n1->keys;

		memmove(n2->start,
			node(n2, keys),
			(void *) end(n2) - (void *) node(n2, keys));

		n2->keys -= keys;

		bch_btree_node_write(r[i].n, &cl);
		bch_keylist_add(keylist, &r[i].n->key);
	}

	closure_sync(&cl);

	bch_btree_insert_node(b, op, keylist);
	BUG_ON(!bch_keylist_empty(keylist));

	for (i = 0; i < nodes; i++) {
		btree_node_free(r[i].b);
		rw_unlock(true, r[i].b);

		r[i].b = r[i].n;
	}

	memmove(r, r + 1, sizeof(r[0]) * (nodes - 1));
	r[nodes - 1].b = ERR_PTR(-EINTR);

	trace_bcache_btree_gc_coalesce(nodes);
	gc->nodes--;

	/* Invalidated our iterator */
	return -EINTR;

out_nocoalesce:
	for (i = 0; i < nodes; i++)
		if (r[i].n) {
			__bkey_put(b->c, &r[i].n->key);
			btree_node_free(r[i].n);
		}
	return 0;
}

static unsigned btree_gc_count_keys(struct btree *b)
{
	struct bkey *k;
	struct btree_iter iter;
	unsigned ret = 0;

	for_each_key_filter(b, k, &iter, bch_ptr_bad)
		ret += bkey_u64s(k);

	return ret;
}

static int btree_gc_recurse(struct btree *b, struct btree_op *op,
			    struct gc_stat *gc)
{
	void write(struct btree *r)
	{
		BUG_ON(!r->written);
		up_write(&r->lock);
	}

	unsigned i;
	int ret = 0;
	bool should_rewrite;
	struct btree *n;
	struct bkey *k;
	struct keylist keys;
	struct btree_iter iter;
	struct gc_merge_info r[GC_MERGE_NODES];
	struct gc_merge_info *last = r + GC_MERGE_NODES - 1;

	bch_keylist_init(&keys);
	bch_btree_iter_init(b, &iter, &b->c->gc_cur_key);

	for (i = 0; i < GC_MERGE_NODES; i++)
		r[i].b = ERR_PTR(-EINTR);

	while (1) {
		k = bch_btree_iter_next_filter(&iter, b, bch_ptr_bad);
		if (k) {
			r->b = bch_btree_node_get(b->c, k, b->level - 1,
						  b->btree_id, true);
			if (IS_ERR(r->b)) {
				ret = PTR_ERR(r->b);
				break;
			}

			r->keys = btree_gc_count_keys(r->b);

			ret = btree_gc_coalesce(b, op, &keys, gc, r);
			if (ret)
				break;
		}

		if (!last->b)
			break;

		if (!IS_ERR(last->b)) {
			should_rewrite = btree_gc_mark_node(last->b, gc);
			if (should_rewrite) {
				n = btree_node_alloc_replacement(last->b);

				if (!IS_ERR_OR_NULL(n)) {
					struct closure cl;

					closure_init_stack(&cl);
					bch_btree_node_write(n, &cl);
					closure_sync(&cl);

					bch_keylist_add(&keys, &n->key);
					bch_btree_insert_node(b, op, &keys);
					BUG_ON(!bch_keylist_empty(&keys));

					btree_node_free(last->b);
					rw_unlock(true, last->b);
					last->b = n;

					/* Invalidated our iterator */
					ret = -EINTR;
					break;
				}
			}

			if (last->b->level) {
				ret = btree_gc_recurse(last->b, op, gc);
				if (ret)
					break;
			}

			bkey_copy_key(&b->c->gc_cur_key, &last->b->key);
			rw_unlock(true, last->b);
		}

		memmove(r + 1, r, sizeof(r[0]) * (GC_MERGE_NODES - 1));
		r->b = NULL;

		if (need_resched()) {
			ret = -EAGAIN;
			break;
		}
	}

	for (i = 0; i < GC_MERGE_NODES; i++)
		if (!IS_ERR_OR_NULL(r[i].b))
			rw_unlock(true, r[i].b);

	return ret;
}

static int bch_btree_gc_root(struct btree *b, struct btree_op *op,
			     struct gc_stat *gc)
{
	struct btree *n = NULL;
	int ret = 0;
	bool should_rewrite;
	struct closure cl;

	closure_init_stack(&cl);

	should_rewrite = btree_gc_mark_node(b, gc);
	if (should_rewrite) {
		n = btree_node_alloc_replacement(b);

		if (!IS_ERR_OR_NULL(n)) {
			bch_btree_node_write(n, &cl);
			closure_sync(&cl);

			bch_btree_set_root(n);
			btree_node_free(b);
			rw_unlock(true, n);

			return -EINTR;
		}
	}

	if (b->level) {
		ret = btree_gc_recurse(b, op, gc);
		if (ret)
			return ret;
	}

	bkey_copy_key(&b->c->gc_cur_key, &b->key);

	return ret;
}

static void btree_gc_start(struct cache_set *c)
{
	struct cache *ca;
	struct bucket *b;
	unsigned i;

	if (!c->gc_mark_valid)
		return;

	mutex_lock(&c->bucket_lock);

	c->gc_mark_valid = 0;
	c->gc_cur_btree = 0;
	c->gc_cur_key = ZERO_KEY;

	for_each_cache(ca, c, i)
		for_each_bucket(b, ca) {
			b->gc_gen = b->gen;
			if (!atomic_read(&b->pin))
				SET_GC_MARK(b, GC_MARK_RECLAIMABLE);
		}

	mutex_unlock(&c->bucket_lock);
}

size_t bch_btree_gc_finish(struct cache_set *c)
{
	size_t available = 0;
	struct bucket *b;
	struct cache *ca;
	unsigned i, id;

	mutex_lock(&c->bucket_lock);

	set_gc_sectors(c);
	c->gc_mark_valid = 1;
	c->need_gc	= 0;

	for (id = 0; id < BTREE_ID_NR; id++)
		if (c->btree_roots[id]) {
			struct bkey *k = &c->btree_roots[id]->key;

			for (i = 0; i < KEY_PTRS(k); i++)
				SET_GC_MARK(PTR_BUCKET(c, k, i),
					    GC_MARK_METADATA);
		}

	for_each_cache(ca, c, i) {
		uint64_t *i;

		ca->invalidate_needs_gc = 0;

		for (i = ca->sb.d; i < ca->sb.d + ca->sb.keys; i++)
			SET_GC_MARK(ca->buckets + *i, GC_MARK_METADATA);

		for (i = ca->prio_buckets;
		     i < ca->prio_buckets + prio_buckets(ca) * 2; i++)
			SET_GC_MARK(ca->buckets + *i, GC_MARK_METADATA);

		for_each_bucket(b, ca) {
			b->last_gc	= b->gc_gen;
			c->need_gc	= max(c->need_gc, bucket_gc_gen(b));

			if (!atomic_read(&b->pin) &&
			    GC_MARK(b) == GC_MARK_RECLAIMABLE) {
				available++;
				if (!GC_SECTORS_USED(b))
					bch_bucket_add_unused(ca, b);
			}
		}
	}

	mutex_unlock(&c->bucket_lock);
	return available;
}

static void bch_btree_gc(struct closure *cl)
{
	struct cache_set *c = container_of(cl, struct cache_set, gc.cl);
	unsigned long available;
	struct gc_stat stats;
	struct btree_op op;
	uint64_t start_time = local_clock();

	trace_bcache_gc_start(c);

	memset(&stats, 0, sizeof(struct gc_stat));
	bch_btree_op_init_stack(&op);
	op.lock = SHRT_MAX;

	btree_gc_start(c);

	while (c->gc_cur_btree < BTREE_ID_NR) {
		int ret = 0;

		if (c->btree_roots[c->gc_cur_btree])
			ret = btree_root(gc_root, c, c->gc_cur_btree,
					 &op, &stats);

		if (ret) {
			if (ret != -EAGAIN)
				pr_warn("gc failed!");

			cond_resched();
			continue;
		}

		c->gc_cur_btree++;
		c->gc_cur_key = ZERO_KEY;
	}

	available = bch_btree_gc_finish(c);

	bch_time_stats_update(&c->btree_gc_time, start_time);

	stats.key_bytes *= sizeof(uint64_t);
	stats.dirty	<<= 9;
	stats.data	<<= 9;
	stats.in_use	= (c->nbuckets - available) * 100 / c->nbuckets;
	memcpy(&c->gc_stats, &stats, sizeof(struct gc_stat));

	trace_bcache_gc_end(c);

	continue_at(cl, bch_moving_gc, bch_gc_wq);
}

void bch_queue_gc(struct cache_set *c)
{
	closure_trylock_call(&c->gc.cl, bch_btree_gc, bch_gc_wq, &c->cl);
}

/* Initial partial gc */

static int bch_btree_check_recurse(struct btree *b, struct btree_op *op,
				   unsigned long **seen)
{
	int ret = 0;
	unsigned i;
	struct bkey *k, *p = NULL;
	struct bucket *g;
	struct btree_iter iter;

	if (!b->level && b->btree_id != BTREE_ID_EXTENTS)
		return ret;

	for_each_key_filter(b, k, &iter, bch_ptr_invalid) {
		if (!b->level) {
			for (i = 0; i < KEY_PTRS(k); i++) {
				if (!ptr_available(b->c, k, i))
					continue;

				if (!__test_and_set_bit(PTR_BUCKET_NR(b->c, k, i),
							seen[PTR_DEV(k, i)]) ||
				    !ptr_stale(b->c, k, i)) {
					g = PTR_BUCKET(b->c, k, i);
					g->gen = PTR_GEN(k, i);
					g->prio = INITIAL_PRIO;
				}
			}
		}

		btree_mark_key(b, k);
	}

	if ((b->btree_id == BTREE_ID_EXTENTS && b->level) || b->level > 1) {
		bch_btree_iter_init(b, &iter, NULL);

		do {
			k = bch_btree_iter_next_filter(&iter, b, bch_ptr_bad);
			if (k)
				btree_node_prefetch(b->c, k, b->level - 1,
						    b->btree_id);

			if (p)
				ret = btree(check_recurse, p, b, op, seen);

			p = k;
		} while (p && !ret);
	}

	return ret;
}

int bch_btree_check(struct cache_set *c)
{
	int ret = -ENOMEM;
	unsigned i;
	unsigned long *seen[MAX_CACHES_PER_SET];
	struct btree_op op;

	memset(seen, 0, sizeof(seen));
	bch_btree_op_init_stack(&op);
	op.lock = SHRT_MAX;

	for (i = 0; c->cache[i]; i++) {
		size_t n = DIV_ROUND_UP(c->cache[i]->sb.nbuckets, 8);
		seen[i] = kmalloc(n, GFP_KERNEL);
		if (!seen[i])
			goto err;

		/* Disables the seen array until prio_read() uses it too */
		memset(seen[i], 0xFF, n);
	}

	for (i = 0; i < BTREE_ID_NR; i++)
		if (c->btree_roots[i]) {
			ret = btree_root(check_recurse, c, i, &op, seen);
			if (ret)
				goto err;
		}

err:
	for (i = 0; i < MAX_CACHES_PER_SET; i++)
		kfree(seen[i]);
	return ret;
}

/* Btree insertion */

static void shift_keys(struct btree *b, struct bkey *where, struct bkey *insert)
{
	struct bset *i = b->sets[b->nsets].data;

	memmove((uint64_t *) where + bkey_u64s(insert),
		where,
		(void *) end(i) - (void *) where);

	i->keys += bkey_u64s(insert);
	bkey_copy(where, insert);
	bch_bset_fix_lookup_table(b, where);
}

static bool fix_overlapping_extents(struct btree *b,
				    struct bkey *insert,
				    struct btree_iter *iter,
				    struct btree_op *op)
{
	void subtract_dirty(struct bkey *k, uint64_t offset, int sectors)
	{
		if (KEY_DIRTY(k))
			bcache_dev_sectors_dirty_add(b->c, KEY_INODE(k),
						     offset, -sectors);
	}

	uint64_t old_offset;
	unsigned old_size, sectors_found = 0;

	while (1) {
		struct bkey *k = bch_btree_iter_next(iter);
		if (!k ||
		    bkey_cmp(&START_KEY(k), insert) >= 0)
			break;

		if (bkey_cmp(k, &START_KEY(insert)) <= 0)
			continue;

		old_offset = KEY_START(k);
		old_size = KEY_SIZE(k);

		/*
		 * We might overlap with 0 size extents; we can't skip these
		 * because if they're in the set we're inserting to we have to
		 * adjust them so they don't overlap with the key we're
		 * inserting. But we don't want to check them for BTREE_REPLACE
		 * operations.
		 */

		if (op->type == BTREE_REPLACE &&
		    KEY_SIZE(k)) {
			/*
			 * k might have been split since we inserted/found the
			 * key we're replacing
			 */
			unsigned i;
			uint64_t offset = KEY_START(k) -
				KEY_START(&op->replace);

			/* But it must be a subset of the replace key */
			if (KEY_START(k) < KEY_START(&op->replace) ||
			    KEY_OFFSET(k) > KEY_OFFSET(&op->replace))
				goto check_failed;

			/* We didn't find a key that we were supposed to */
			if (KEY_START(k) > KEY_START(insert) + sectors_found)
				goto check_failed;

			if (KEY_PTRS(&op->replace) != KEY_PTRS(k))
				goto check_failed;

			/* skip past gen */
			offset <<= 8;

			BUG_ON(!KEY_PTRS(&op->replace));

			for (i = 0; i < KEY_PTRS(&op->replace); i++)
				if (k->ptr[i] != op->replace.ptr[i] + offset)
					goto check_failed;

			sectors_found = KEY_OFFSET(k) - KEY_START(insert);
		}

		if (bkey_cmp(insert, k) < 0 &&
		    bkey_cmp(&START_KEY(insert), &START_KEY(k)) > 0) {
			/*
			 * We overlapped in the middle of an existing key: that
			 * means we have to split the old key. But we have to do
			 * slightly different things depending on whether the
			 * old key has been written out yet.
			 */

			struct bkey *top;

			subtract_dirty(k, KEY_START(insert), KEY_SIZE(insert));

			if (bkey_written(b, k)) {
				/*
				 * We insert a new key to cover the top of the
				 * old key, and the old key is modified in place
				 * to represent the bottom split.
				 *
				 * It's completely arbitrary whether the new key
				 * is the top or the bottom, but it has to match
				 * up with what btree_sort_fixup() does - it
				 * doesn't check for this kind of overlap, it
				 * depends on us inserting a new key for the top
				 * here.
				 */
				top = bch_bset_search(b, &b->sets[b->nsets],
						      insert);
				shift_keys(b, top, k);
			} else {
				BKEY_PADDED(key) temp;
				bkey_copy(&temp.key, k);
				shift_keys(b, k, &temp.key);
				top = bkey_next(k);
			}

			bch_cut_front(insert, top);
			bch_cut_back(&START_KEY(insert), k);
			bch_bset_fix_invalidated_key(b, k);
			return false;
		}

		if (bkey_cmp(insert, k) < 0) {
			bch_cut_front(insert, k);
		} else {
			if (bkey_written(b, k) &&
			    bkey_cmp(&START_KEY(insert), &START_KEY(k)) <= 0) {
				/*
				 * Completely overwrote, so we don't have to
				 * invalidate the binary search tree
				 */
				bch_cut_front(k, k);
			} else {
				__bch_cut_back(&START_KEY(insert), k);
				bch_bset_fix_invalidated_key(b, k);
			}
		}

		subtract_dirty(k, old_offset, old_size - KEY_SIZE(k));
	}

check_failed:
	if (op->type == BTREE_REPLACE) {
		if (!sectors_found) {
			op->insert_collision = true;
			return true;
		} else if (sectors_found < KEY_SIZE(insert)) {
			SET_KEY_OFFSET(insert, KEY_OFFSET(insert) -
				       (KEY_SIZE(insert) - sectors_found));
			SET_KEY_SIZE(insert, sectors_found);
		}
	}

	return false;
}

static bool fix_overlapping_keys(struct btree *b,
				 struct bkey *insert,
				 struct btree_iter *iter,
				 struct btree_op *op)
{
	while (1) {
		struct bkey *k = bch_btree_iter_next(iter);
		if (!k ||
		    bkey_cmp(k, insert) >= 0)
			break;

		if (bkey_cmp(k, insert) <= 0)
			continue;

		SET_KEY_DELETED(k, 1);
	}

	return false;
}

static bool btree_insert_key(struct btree *b, struct btree_op *op,
			     struct bkey *k)
{
	unsigned status = BTREE_INSERT_STATUS_INSERT;
	struct bset *i = b->sets[b->nsets].data;
	struct bkey *m, *prev = NULL;
	struct btree_iter iter;

	BUG_ON(bkey_cmp(k, &b->key) > 0);
	BUG_ON(b->level && bkey_cmp(k, &ZERO_KEY) == 0);
	BUG_ON(b->level && !KEY_PTRS(k));

	m = bch_btree_iter_init(b, &iter, PRECEDING_KEY(&START_KEY(k)));

	if (!b->level && b->btree_id == BTREE_ID_EXTENTS) {
		BUG_ON(!KEY_OFFSET(k));

		if (fix_overlapping_extents(b, k, &iter, op))
			return false;

		while (m != end(i) &&
		       bkey_cmp(k, &START_KEY(m)) > 0)
			prev = m, m = bkey_next(m);

		if (key_merging_disabled(b->c))
			goto insert;

		/* prev is in the tree, if we merge we're done */
		status = BTREE_INSERT_STATUS_BACK_MERGE;
		if (prev &&
		    bch_bkey_try_merge(b, prev, k))
			goto merged;

		status = BTREE_INSERT_STATUS_OVERWROTE;
		if (m != end(i) &&
		    KEY_PTRS(m) == KEY_PTRS(k) && !KEY_SIZE(m))
			goto copy;

		status = BTREE_INSERT_STATUS_FRONT_MERGE;
		if (m != end(i) &&
		    bch_bkey_try_merge(b, k, m))
			goto copy;
	} else {
		fix_overlapping_keys(b, k, &iter, op);

		while (m != end(i) &&
		       bkey_cmp(k, &START_KEY(m)) > 0)
			prev = m, m = bkey_next(m);
	}

insert:	shift_keys(b, m, k);
copy:	bkey_copy(m, k);
merged:
	if (KEY_DIRTY(k))
		bcache_dev_sectors_dirty_add(b->c, KEY_INODE(k),
					     KEY_START(k), KEY_SIZE(k));

	bch_check_keys(b, "%u for %s", status, op_type(op));

	trace_bcache_btree_insert_key(b, k, op->type, status);

	return true;
}

static bool bch_btree_insert_keys(struct btree *b, struct btree_op *op,
				  struct keylist *insert_keys)
{
	bool ret = false;
	unsigned oldsize = bch_count_data(b);
	unsigned prev = 0;
	struct bkey prevk;

	//BUG_ON(!insert_lock(op, b));

	while (!bch_keylist_empty(insert_keys)) {
		struct bset *i = write_block(b);
		struct bkey *k = insert_keys->keys;

		if (b->written + __set_blocks(i, i->keys + bkey_u64s(k), b->c)
		    > btree_blocks(b))
			break;

		if (!b->level && prev)
			BUG_ON(bkey_cmp(k, &prevk) < 0);

		prevk = *k;
		prev = 1;

		if (bkey_cmp(k, &b->key) <= 0) {
			bkey_put(b->c, k, b->level);

			ret |= btree_insert_key(b, op, k);
			bch_keylist_pop_front(insert_keys);
		} else if (bkey_cmp(&START_KEY(k), &b->key) < 0) {
#if 0
			if (op->type == BTREE_REPLACE) {
				bkey_put(b->c, k, b->level);
				bch_keylist_pop_front(insert_keys);
				op->insert_collision = true;
				break;
			}
#endif
			BKEY_PADDED(key) temp;
			bkey_copy(&temp.key, insert_keys->keys);

			bch_cut_back(&b->key, &temp.key);
			bch_cut_front(&b->key, insert_keys->keys);

			ret |= btree_insert_key(b, op, &temp.key);
			break;
		} else {
			break;
		}
	}

	BUG_ON(!bch_keylist_empty(insert_keys) && b->level);

	BUG_ON(bch_count_data(b) < oldsize);
	return ret;
}

static int btree_split(struct btree *b, struct btree_op *op,
		       struct keylist *insert_keys,
		       struct keylist *parent_keys)
{
	bool split;
	struct btree *n1, *n2 = NULL, *n3 = NULL;
	uint64_t start_time = local_clock();
	struct closure cl;

	closure_init_stack(&cl);

	n1 = btree_node_alloc_replacement(b);
	if (IS_ERR(n1))
		goto err;

	split = set_blocks(n1->sets[0].data, n1->c) > (btree_blocks(b) * 4) / 5;

	if (split) {
		unsigned keys = 0;

		trace_bcache_btree_node_split(b, n1->sets[0].data->keys);

		n2 = bch_btree_node_alloc(b->c, b->level, b->btree_id);
		if (IS_ERR(n2))
			goto err_free1;

		if (!b->parent) {
			n3 = bch_btree_node_alloc(b->c, b->level + 1,
						  b->btree_id);
			if (IS_ERR(n3))
				goto err_free2;
		}

		bch_btree_insert_keys(n1, op, insert_keys);

		/*
		 * Has to be a linear search because we don't have an auxiliary
		 * search tree yet
		 */

		while (keys < (n1->sets[0].data->keys * 3) / 5)
			keys += bkey_u64s(node(n1->sets[0].data, keys));

		bkey_copy_key(&n1->key, node(n1->sets[0].data, keys));
		keys += bkey_u64s(node(n1->sets[0].data, keys));

		n2->sets[0].data->keys = n1->sets[0].data->keys - keys;
		n1->sets[0].data->keys = keys;

		memcpy(n2->sets[0].data->start,
		       end(n1->sets[0].data),
		       n2->sets[0].data->keys * sizeof(uint64_t));

		bkey_copy_key(&n2->key, &b->key);

		bch_keylist_add(parent_keys, &n2->key);
		bch_btree_node_write(n2, &cl);
		rw_unlock(true, n2);
	} else {
		trace_bcache_btree_node_compact(b, n1->sets[0].data->keys);

		bch_btree_insert_keys(n1, op, insert_keys);
	}

	bch_keylist_add(parent_keys, &n1->key);
	bch_btree_node_write(n1, &cl);

	if (n3) {
		/* Depth increases, make a new root */

		bkey_copy_key(&n3->key, &MAX_KEY);
		bch_btree_insert_keys(n3, op, parent_keys);
		bch_btree_node_write(n3, &cl);

		closure_sync(&cl);
		bch_btree_set_root(n3);
		rw_unlock(true, n3);
	} else if (!b->parent) {
		/* Root filled up but didn't need to be split */

		bch_keylist_reset(parent_keys);
		closure_sync(&cl);
		bch_btree_set_root(n1);
	} else {
		/* Split a non root node */
		closure_sync(&cl);
	}

	rw_unlock(true, n1);
	btree_node_free(b);

	bch_time_stats_update(&b->c->btree_split_time, start_time);

	return 0;
err_free2:
	__bkey_put(n2->c, &n2->key);
	btree_node_free(n2);
	rw_unlock(true, n2);
err_free1:
	__bkey_put(n1->c, &n1->key);
	btree_node_free(n1);
	rw_unlock(true, n1);
err:
	if (n3 == ERR_PTR(-EAGAIN) ||
	    n2 == ERR_PTR(-EAGAIN) ||
	    n1 == ERR_PTR(-EAGAIN))
		return -EAGAIN;

	pr_warn("couldn't split");
	return -ENOMEM;
}

int bch_btree_insert_node(struct btree *b, struct btree_op *op,
			  struct keylist *insert_keys)
{
	int ret = 0;
	struct keylist split_keys;

	bch_keylist_init(&split_keys);

	do {
		if (should_split(b)) {
			if (current->bio_list) {
				op->lock = btree_node_root(b)->level + 1;
				ret = -EAGAIN;
			} else if (op->lock <= btree_node_root(b)->level) {
				op->lock = btree_node_root(b)->level + 1;
				ret = -EINTR;
			} else {
				struct btree *parent = b->parent;

				ret = btree_split(b, op, insert_keys, &split_keys);
				insert_keys = &split_keys;
				b = parent;
				if (!ret)
					ret = -EINTR;
			}
		} else {
			BUG_ON(write_block(b) != b->sets[b->nsets].data);

			if (bch_btree_insert_keys(b, op, insert_keys)) {
				if (!b->level)
					bch_btree_leaf_dirty(b, op);
				else {
					struct closure cl;

					closure_init_stack(&cl);
					bch_btree_node_write(b, &cl);
					closure_sync(&cl);
				}
			}
		}
	} while (!bch_keylist_empty(&split_keys));

	return ret;
}

bool bch_btree_insert_check_key(struct btree *b, struct btree_op *op,
				unsigned inode, struct bio *bio)
{
	bool ret = false;
	uint64_t btree_ptr = b->key.ptr[0];
	unsigned long seq = b->seq;
	struct keylist insert;

	bch_keylist_init(&insert);

	rw_unlock(false, b);
	rw_lock(true, b, b->level);

	if (b->key.ptr[0] != btree_ptr ||
	    b->seq != seq + 1 ||
	    should_split(b))
		goto out;

	op->replace = KEY(inode, bio_end(bio), bio_sectors(bio));

	SET_KEY_PTRS(&op->replace, 1);
	get_random_bytes(&op->replace.ptr[0], sizeof(uint64_t));

	SET_PTR_DEV(&op->replace, 0, PTR_CHECK_DEV);

	bch_keylist_add(&insert, &op->replace);

	BUG_ON(op->type != BTREE_INSERT);

	bch_btree_insert_node(b, op, &insert);
	ret = bch_keylist_empty(&insert);
out:
	downgrade_write(&b->lock);
	return ret;
}

int bch_btree_insert(struct btree_op *op, struct cache_set *c,
		     enum btree_id id, struct keylist *keys)
{
	int btree_insert_fn(struct btree_op *op, struct btree *b)
	{
		int ret = bch_btree_insert_node(b, op, keys);

		if (!ret && !bch_keylist_empty(keys))
			return MAP_CONTINUE;
		return ret;
	}

	int ret = 0;

	BUG_ON(bch_keylist_empty(keys));

	while (!bch_keylist_empty(keys)) {
		op->lock = 0;
		ret = bch_btree_map_nodes(op, c, id, &START_KEY(keys->keys),
					  btree_insert_fn, MAP_LEAF_NODES);

		if (ret == -EAGAIN) {
			BUG();
			ret = 0;
		} else if (ret) {
			struct bkey *k;

			pr_err("error %i trying to insert key for %s",
			       ret, op_type(op));

			while ((k = bch_keylist_pop(keys)))
				bkey_put(c, k, 0);
		}
	}

	return ret;
}

void bch_btree_set_root(struct btree *b)
{
	struct closure cl;

	closure_init_stack(&cl);

	trace_bcache_btree_set_root(b);

	BUG_ON(!b->written);

	mutex_lock(&b->c->bucket_lock);
	list_del_init(&b->list);
	mutex_unlock(&b->c->bucket_lock);

	spin_lock(&b->c->btree_root_lock);
	btree_node_root(b) = b;
	spin_unlock(&b->c->btree_root_lock);

	__bkey_put(b->c, &b->key);

	bch_journal_meta(b->c, &cl);
	closure_sync(&cl);
}

/* Cache lookup */

static int submit_partial_cache_miss(struct btree *b, struct btree_op *op,
				     struct bkey *k)
{
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;
	int ret = MAP_CONTINUE;

	/*
	 * b->key would be exactly what we want, except that
	 * pointers to btree nodes have nonzero size - we
	 * wouldn't go far enough
	 */
	if (!k)
		k = &KEY(KEY_INODE(&b->key), KEY_OFFSET(&b->key), 0);

	do {
		unsigned sectors = INT_MAX;

		if (KEY_INODE(k) == KEY_INODE(&s->d->inode.k)) {
			if (KEY_START(k) <= bio->bi_sector)
				break;

			sectors = min_t(uint64_t, sectors,
					KEY_START(k) - bio->bi_sector);
		}

		ret = s->d->cache_miss(b, s, bio, sectors);
	} while (ret == MAP_CONTINUE);

	return ret;
}

/*
 * Read from a single key, handling the initial cache miss if the key starts in
 * the middle of the bio
 */
static int submit_partial_cache_hit(struct btree_op *op, struct btree *b,
				    struct bkey *k)
{
	struct search *s = container_of(op, struct search, op);
	struct bio *bio = &s->bio.bio;
	unsigned ptr;
	struct bio *n;

	int ret = submit_partial_cache_miss(b, op, k);
	if (ret != MAP_CONTINUE || !k)
		return ret;

	/* XXX: figure out best pointer - for multiple cache devices */
	ptr = 0;

	PTR_BUCKET(b->c, k, ptr)->prio = INITIAL_PRIO;

	while (ret == MAP_CONTINUE &&
	       KEY_INODE(k) == KEY_INODE(&s->d->inode.k) &&
	       bio->bi_sector < KEY_OFFSET(k)) {
		struct bkey *bio_key;
		sector_t sector = PTR_OFFSET(k, ptr) +
			(bio->bi_sector - KEY_START(k));
		unsigned sectors = min_t(uint64_t, INT_MAX,
					 KEY_OFFSET(k) - bio->bi_sector);

		n = bch_bio_split(bio, sectors, GFP_NOIO, s->d->bio_split);
		if (!n)
			return -EAGAIN;

		if (n == bio)
			ret = MAP_DONE;

		bio_key = &container_of(n, struct bbio, bio)->key;

		/*
		 * The bucket we're reading from might be reused while our bio
		 * is in flight, and we could then end up reading the wrong
		 * data.
		 *
		 * We guard against this by checking (in cache_read_endio()) if
		 * the pointer is stale again; if so, we treat it as an error
		 * and reread from the backing device (but we don't pass that
		 * error up anywhere).
		 */

		bch_bkey_copy_single_ptr(bio_key, k, ptr);
		SET_PTR_OFFSET(bio_key, 0, sector);

		n->bi_end_io	= bch_cache_read_endio;
		n->bi_private	= &s->cl;

		__bch_submit_bbio(n, b->c);
	}

	return ret;
}

void bch_btree_search_async(struct closure *cl)
{
	struct search *s = container_of(cl, struct search, btree);
	struct btree_op *op = &s->op;
	struct bio *bio = &s->bio.bio;

	int ret = bch_btree_map_keys(op, s->c, BTREE_ID_EXTENTS,
				     &KEY(KEY_INODE(&s->d->inode.k),
					  bio->bi_sector, 0),
				     submit_partial_cache_hit, 1);
	if (ret == -EAGAIN)
		continue_at(cl, bch_btree_search_async, bcache_wq);

	closure_return(cl);
}

/* Generic... lookup? */

static int bch_btree_map_nodes_recurse(struct btree *b, struct btree_op *op,
				       struct bkey *from,
				       btree_map_nodes_fn *fn, int flags)
{
	int ret = MAP_CONTINUE;

	if (b->level) {
		struct bkey *k;
		struct btree_iter iter;

		bch_btree_iter_init(b, &iter, from);

		while ((k = bch_btree_iter_next_filter(&iter, b, bch_ptr_bad))) {
			ret = btree(map_nodes_recurse, k, b, op, from, fn, flags);
			from = NULL;

			if (ret != MAP_CONTINUE)
				return ret;
		}
	}

	if (!b->level || flags == MAP_ALL_NODES)
		ret = fn(op, b);

	return ret;
}

int bch_btree_map_nodes(struct btree_op *op, struct cache_set *c,
			enum btree_id id, struct bkey *from,
			btree_map_nodes_fn *fn, int flags)
{
	return btree_root(map_nodes_recurse, c, id, op, from, fn, flags);
}

static int bch_btree_map_keys_recurse(struct btree *b, struct btree_op *op,
				      struct bkey *from, btree_map_keys_fn *fn,
				      int flags)
{
	int ret = MAP_CONTINUE;
	struct bkey *k;
	struct btree_iter iter;

	bch_btree_iter_init(b, &iter, from);

	while ((k = bch_btree_iter_next_filter(&iter, b, bch_ptr_bad))) {
		ret = !b->level
			? fn(op, b, k)
			: btree(map_keys_recurse, k, b, op, from, fn, flags);
		from = NULL;

		if (ret != MAP_CONTINUE)
			return ret;
	}

	if (!b->level && flags)
		ret = fn(op, b, NULL);

	return ret;
}

int bch_btree_map_keys(struct btree_op *op, struct cache_set *c,
		       enum btree_id id, struct bkey *from,
		       btree_map_keys_fn *fn, int flags)
{
	return btree_root(map_keys_recurse, c, id, op, from, fn, flags);
}

/* Keybuf code */

static inline int keybuf_cmp(struct keybuf_key *l, struct keybuf_key *r)
{
	/* Overlapping keys compare equal */
	if (bkey_cmp(&l->key, &START_KEY(&r->key)) <= 0)
		return -1;
	if (bkey_cmp(&START_KEY(&l->key), &r->key) >= 0)
		return 1;
	return 0;
}

static inline int keybuf_nonoverlapping_cmp(struct keybuf_key *l,
					    struct keybuf_key *r)
{
	return clamp_t(int64_t, bkey_cmp(&l->key, &r->key), -1, 1);
}

struct refill {
	struct btree_op	op;
	struct keybuf	*buf;
	struct bkey	*end;
	keybuf_pred_fn	*pred;
};

static int refill_keybuf_fn(struct btree_op *op, struct btree *b,
			    struct bkey *k)
{
	struct refill *refill = container_of(op, struct refill, op);
	struct keybuf *buf = refill->buf;

	if (array_freelist_empty(&buf->freelist))
		return MAP_DONE;

	buf->last_scanned = *k;
	if (bkey_cmp(&buf->last_scanned, refill->end) >= 0)
		return MAP_DONE;

	if (refill->pred(buf, k)) {
		struct keybuf_key *w;

		spin_lock(&buf->lock);

		w = array_alloc(&buf->freelist);

		w->private = NULL;
		bkey_copy(&w->key, k);

		if (RB_INSERT(&buf->keys, w, node, keybuf_cmp))
			array_free(&buf->freelist, w);

		spin_unlock(&buf->lock);
	}

	return MAP_CONTINUE;
}

void bch_refill_keybuf(struct cache_set *c, struct keybuf *buf,
		       struct bkey *end, keybuf_pred_fn *pred)
{
	struct bkey start = buf->last_scanned;
	struct refill refill;

	cond_resched();

	bch_btree_op_init_stack(&refill.op);
	refill.buf = buf;
	refill.end = end;
	refill.pred = pred;

	bch_btree_map_keys(&refill.op, c, BTREE_ID_EXTENTS,
			   &buf->last_scanned, refill_keybuf_fn, 0);

	pr_debug("found %s keys from %llu:%llu to %llu:%llu",
		 RB_EMPTY_ROOT(&buf->keys) ? "no" :
		 array_freelist_empty(&buf->freelist) ? "some" : "a few",
		 KEY_INODE(&start), KEY_OFFSET(&start),
		 KEY_INODE(&buf->last_scanned), KEY_OFFSET(&buf->last_scanned));

	spin_lock(&buf->lock);

	if (!RB_EMPTY_ROOT(&buf->keys)) {
		struct keybuf_key *w;
		w = RB_FIRST(&buf->keys, struct keybuf_key, node);
		buf->start	= START_KEY(&w->key);

		w = RB_LAST(&buf->keys, struct keybuf_key, node);
		buf->end	= w->key;
	} else {
		buf->start	= MAX_KEY;
		buf->end	= MAX_KEY;
	}

	spin_unlock(&buf->lock);
}

static void __bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	rb_erase(&w->node, &buf->keys);
	array_free(&buf->freelist, w);
}

void bch_keybuf_del(struct keybuf *buf, struct keybuf_key *w)
{
	spin_lock(&buf->lock);
	__bch_keybuf_del(buf, w);
	spin_unlock(&buf->lock);
}

bool bch_keybuf_check_overlapping(struct keybuf *buf, struct bkey *start,
				  struct bkey *end)
{
	bool ret = false;
	struct keybuf_key *p, *w, s;
	s.key = *start;

	if (bkey_cmp(end, &buf->start) <= 0 ||
	    bkey_cmp(start, &buf->end) >= 0)
		return false;

	spin_lock(&buf->lock);
	w = RB_GREATER(&buf->keys, s, node, keybuf_nonoverlapping_cmp);

	while (w && bkey_cmp(&START_KEY(&w->key), end) < 0) {
		p = w;
		w = RB_NEXT(w, node);

		if (p->private)
			ret = true;
		else
			__bch_keybuf_del(buf, p);
	}

	spin_unlock(&buf->lock);
	return ret;
}

struct keybuf_key *bch_keybuf_next(struct keybuf *buf)
{
	struct keybuf_key *w;
	spin_lock(&buf->lock);

	w = RB_FIRST(&buf->keys, struct keybuf_key, node);

	while (w && w->private)
		w = RB_NEXT(w, node);

	if (w)
		w->private = ERR_PTR(-EINTR);

	spin_unlock(&buf->lock);
	return w;
}

struct keybuf_key *bch_keybuf_next_rescan(struct cache_set *c,
					  struct keybuf *buf,
					  struct bkey *end,
					  keybuf_pred_fn *pred)
{
	struct keybuf_key *ret;

	while (1) {
		ret = bch_keybuf_next(buf);
		if (ret)
			break;

		if (bkey_cmp(&buf->last_scanned, end) >= 0) {
			pr_debug("scan finished");
			break;
		}

		bch_refill_keybuf(c, buf, end, pred);
	}

	return ret;
}

void bch_keybuf_init(struct keybuf *buf)
{
	buf->last_scanned	= MAX_KEY;
	buf->keys		= RB_ROOT;

	spin_lock_init(&buf->lock);
	array_allocator_init(&buf->freelist);
}

void bch_btree_exit(void)
{
	if (btree_io_wq)
		destroy_workqueue(btree_io_wq);
	if (bch_gc_wq)
		destroy_workqueue(bch_gc_wq);
}

int __init bch_btree_init(void)
{
	if (!(bch_gc_wq = create_singlethread_workqueue("bch_btree_gc")) ||
	    !(btree_io_wq = create_singlethread_workqueue("bch_btree_io")))
		return -ENOMEM;

	return 0;
}

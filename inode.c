
#include "bcache.h"
#include "btree.h"
#include "inode.h"

void bch_inode_rm(struct cache_set *c, uint64_t inode_nr)
{
	struct bch_inode_deleted inode;
	struct keylist keys;
	struct closure cl;

	bch_keylist_init(&keys);
	closure_init_stack(&cl);

	BCH_INODE_INIT(&inode);
	SET_KEY_INODE(&inode.k, inode_nr);
	SET_KEY_DELETED(&inode.k, 1);

	bch_keylist_add(&keys, &inode.k);
	bch_btree_insert_journalled(c, BTREE_ID_INODES, &keys, &cl);
	closure_sync(&cl);
}

struct uuid_op {
	struct btree_op		op;
	struct closure		cl;
	struct bch_inode_uuid	*inode;
};

static int uuid_inode_write_new_fn(struct btree_op *op, struct btree *b,
				   struct bkey *k)
{
	struct uuid_op *u = container_of(op, struct uuid_op, op);
	struct keylist keys;
	int ret;

	if (k) {
		if (b->c->unused_inode_hint < KEY_INODE(k))
			goto insert;
	} else {
		k = &b->key;
		if (b->c->unused_inode_hint <= KEY_INODE(k))
			goto insert;
	}

	b->c->unused_inode_hint = KEY_INODE(k) + 1;

	if (b->c->unused_inode_hint == UUID_INODE_MAX) {
		b->c->unused_inode_hint = 0;
		return -EINVAL;
	}

	return MAP_CONTINUE;
insert:
	/* Found a gap */
	SET_KEY_INODE(&u->inode->k, b->c->unused_inode_hint);

	b->c->unused_inode_hint = KEY_INODE(&u->inode->k) + 1;
	b->c->unused_inode_hint %= UUID_INODE_MAX;

	pr_debug("inserting inode %llu, unused_inode_hint now %llu",
		 KEY_INODE(&u->inode->k), b->c->unused_inode_hint);

	bch_keylist_init(&keys);
	bch_keylist_add(&keys, &u->inode->k);
	ret = bch_btree_insert_node(b, op, &keys, NULL, NULL);

	BUG_ON(!bch_keylist_empty(&keys));

	if (!ret) /* this wasn't journalled... */
		bch_btree_node_write(b, &u->cl);

	return ret;
}

int bch_uuid_inode_write_new(struct cache_set *c, struct bch_inode_uuid *inode)
{
	int ret;
	struct uuid_op op;
	struct bkey *search = PRECEDING_KEY(&KEY(c->unused_inode_hint, 0, 0));
	uint64_t hint = c->unused_inode_hint;

	bch_btree_op_init(&op.op, 0);
	closure_init_stack(&op.cl);
	op.inode = inode;

	BUG_ON(inode->i_inode_type != BCH_INODE_UUID);

	ret = bch_btree_map_keys(&op.op, c, BTREE_ID_INODES, search,
				 uuid_inode_write_new_fn, MAP_END_KEY);
	if (!ret)
		goto out;

	if (hint)
		ret = bch_btree_map_keys(&op.op, c, BTREE_ID_INODES, NULL,
					 uuid_inode_write_new_fn, MAP_END_KEY);
out:
	closure_sync(&op.cl);
	return ret;
}

void bch_uuid_inode_write(struct cache_set *c, struct bch_inode_uuid *inode)
{
	struct keylist keys;
	struct closure cl;

	bch_keylist_init(&keys);
	closure_init_stack(&cl);

	BUG_ON(inode->i_inode_type != BCH_INODE_UUID);

	bch_keylist_add(&keys, &inode->k);
	bch_btree_insert_journalled(c, BTREE_ID_INODES, &keys, &cl);
	closure_sync(&cl);
}

struct find_op {
	struct btree_op		op;
	struct bch_inode_uuid	*search;
};

static int uuid_inode_find_fn(struct btree_op *b_op, struct btree *b, struct bkey *k)
{
	struct find_op *op = container_of(b_op, struct find_op, op);
	struct bch_inode_uuid *inode = (void *) k;

	pr_debug("found inode %llu: %pU (ptrs %llu)",
		KEY_INODE(k), inode->uuid, KEY_PTRS(k));

	BUG_ON(inode->i_inode_type != BCH_INODE_UUID);

	if (KEY_INODE(k) >= UUID_INODE_MAX) {
		return -EINVAL;
	} else if (!memcmp(op->search->uuid, inode->uuid, 16)) {
		memcpy(op->search, inode, sizeof(*inode));
		return MAP_DONE;
	}

	return MAP_CONTINUE;
}

int bch_uuid_inode_find(struct cache_set *c, struct bch_inode_uuid *search)
{
	struct find_op op;

	bch_btree_op_init(&op.op, -1);
	op.search = search;

	return bch_btree_map_keys(&op.op, c, BTREE_ID_INODES,
				 NULL, uuid_inode_find_fn, 0);
}

/* Old UUID code */

static void uuid_endio(struct bio *bio, int error)
{
	struct closure *cl = bio->bi_private;
	closure_put(cl);
}

static int uuid_io(struct cache_set *c, struct bkey *k,
		   struct uuid_entry *uuids)
{
	unsigned i;
	int err = -EIO;
	struct closure cl;
	closure_init_stack(&cl);

	for (i = 0; i < KEY_PTRS(k); i++) {
		struct bio *bio = bch_bbio_alloc(c);

		bio->bi_rw	= REQ_SYNC|REQ_META|READ_SYNC;
		bio->bi_iter.bi_size = KEY_SIZE(k) << 9;

		bio->bi_end_io	= uuid_endio;
		bio->bi_private = &cl;
		bch_bio_map(bio, uuids);

		bch_submit_bbio(bio, c, k, i);
		closure_sync(&cl);

		err = !test_bit(BIO_UPTODATE, &bio->bi_flags);
		bch_bbio_free(bio, c);

		if (!err)
			return 0;
	}

	return -EIO;

	return 0;
}

char *bch_uuid_convert(struct cache_set *c, struct jset *j, struct closure *cl)
{
	int i, level;
	unsigned order, nr_uuids = bucket_bytes(c) / sizeof(struct uuid_entry);
	struct uuid_entry *uuids;
	struct bkey *k;

	k = bch_journal_find_btree_root(c, j, BTREE_ID_UUIDS, &level);
	if (!k)
		return "bad uuid pointer";

	order = ilog2(bucket_pages(c));

	uuids = (void *) __get_free_pages(GFP_KERNEL, order);
	if (!uuids)
		return "-ENOMEM";

	if (uuid_io(c, k, uuids))
		return "error reading old style uuids";

	if (j->version < BCACHE_JSET_VERSION_UUIDv1) {
		struct uuid_entry_v0	*u0 = (void *) uuids;
		struct uuid_entry	*u1 = (void *) uuids;

		closure_sync(cl);

		/*
		 * Since the new uuid entry is bigger than the old, we have to
		 * convert starting at the highest memory address and work down
		 * in order to do it in place
		 */

		for (i = nr_uuids - 1;
		     i >= 0;
		     --i) {
			memcpy(u1[i].uuid,	u0[i].uuid, 16);
			memcpy(u1[i].label,	u0[i].label, 32);

			u1[i].first_reg		= u0[i].first_reg;
			u1[i].last_reg		= u0[i].last_reg;
			u1[i].invalidated	= u0[i].invalidated;

			u1[i].flags	= 0;
			u1[i].sectors	= 0;
		}
	}

	for (i = 0; i < nr_uuids; i++) {
		struct uuid_entry *u = uuids + i;
		struct bch_inode_uuid ui;

		if (bch_is_zero(u->uuid, 16))
			continue;

		pr_debug("Slot %zi: %pU: %s: 1st: %u last: %u inv: %u",
			 u - uuids, u->uuid, u->label,
			 u->first_reg, u->last_reg, u->invalidated);

		BCH_INODE_INIT(&ui);
		ui.sectors	= u->sectors;
		ui.flags	= u->flags;
		ui.first_reg	= u->first_reg;
		ui.last_reg	= u->last_reg;

		memcpy(ui.uuid, u->uuid, 16);
		memcpy(ui.label, u->label, 32);
		SET_INODE_FLASH_ONLY(&ui, UUID_FLASH_ONLY(u));

		SET_KEY_INODE(&ui.k, i);

		bch_uuid_inode_write(c, &ui);
	}

	free_pages((unsigned long) uuids, order);

	return NULL;
}

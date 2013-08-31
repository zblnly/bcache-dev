#ifndef _BCACHE_INODE_H
#define _BCACHE_INODE_H

void bch_inode_rm(struct cache_set *c, uint64_t inode_nr);

int bch_uuid_inode_write_new(struct cache_set *c, struct bch_inode_uuid *u);
void bch_uuid_inode_write(struct cache_set *c, struct bch_inode_uuid *u);
int bch_uuid_inode_find(struct cache_set *c, struct bch_inode_uuid *u);

char *bch_uuid_convert(struct cache_set *c, struct jset *j, struct closure *cl);

#endif

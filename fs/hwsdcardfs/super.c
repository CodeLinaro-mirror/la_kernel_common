/* vim:set ts=8 sw=8 tw=0 noet ft=c:
 *
 * fs/sdcardfs/super.c
 *
 * Copyright (C) 2017 HUAWEI, Inc.
 * Author: gaoxiang <gaoxiang25@huawei.com>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of the Linux
 * distribution for more details.
 */
#include "sdcardfs.h"

/*
 * could be triggered after deactivate_locked_super()
 * is called, thus including umount and failed to initialize.
 */
static void sdcardfs_put_super(struct super_block *sb)
{
	struct vfsmount *lower_mnt;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(sb);

	/* failed to read_super */
	if (sbi == NULL)
		return;

	/* if exists, dput(shared_obb) */
	dput(sbi->shared_obb);

	if (sbi->sdcardd_cred != NULL)
		put_cred(sbi->sdcardd_cred);

	free_fs_struct(sbi->override_fs);

	if (sbi->devpath_s == NULL)
		errln("%s, unexpected sbi->devpath_s == NULL",
			__func__);
	else {
		infoln("unmounting on top of %s", sbi->devpath_s);
		__putname(sbi->devpath_s);
	}

	/* deal with lower_sb & lower_mnt */
	lower_mnt = sbi->lower_mnt;
	BUG_ON(lower_mnt == NULL);
	atomic_dec(&lower_mnt->mnt_sb->s_active);
	mntput(lower_mnt);

#ifdef CONFIG_SDCARD_FS_RESERVED_SPACE
	_path_put(&sbi->basepath);
#endif

#ifdef CONFIG_SDCARD_FS_SYSFS
	kobject_put(&sbi->kobj);
#else
	kfree(sbi);
#endif
	sb->s_fs_info = NULL;
}

static int sdcardfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;

#ifdef CONFIG_SDCARD_FS_RESERVED_SPACE
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	err = vfs_statfs(&sbi->basepath, buf);

	if (sbi->options.reserved_mb) {
		u64 min_blocks;

		/* Invalid statfs information */
		if (!buf->f_bsize) {
			errln("f_bsize == 0 returned by underlay_statfs.");
			return -EINVAL;
		}

		min_blocks = ((u64)sbi->options.reserved_mb << 20) / (u64)buf->f_bsize;
		buf->f_blocks -= min_blocks;

		if (buf->f_bavail > min_blocks)
			buf->f_bavail -= min_blocks;
		else
			buf->f_bavail = 0;

		/* Make reserved blocks invisiable to media storage */
		buf->f_bfree = buf->f_bavail;
	}
#else
	struct path lower_path;

	sdcardfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	_path_put(&lower_path);
#endif

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = SDCARDFS_SUPER_MAGIC;

	return err;
}

/* Handle the sdcard file system remount operation */
static int sdcardfs_remount_fs(struct super_block *sb,
	int *flags, char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others. We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
		errln("remount flags 0x%x unsupported", *flags);
		err = -EINVAL;
	}

	return err;
}

static void sdcardfs_evict_inode(struct inode *inode)
{
	struct sdcardfs_tree_entry *te = SDCARDFS_I(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* dentry rcu-walk could still use tree_entry */
	sdcardfs_invalidate_tree_entry(te);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void sdcardfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = sdcardfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

static int sdcardfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct sdcardfs_mount_options *opts = &SDCARDFS_SB(sb)->options;

#define xx(...)  seq_printf(m, __VA_ARGS__)
#define __SDCARDFS_MISC__SHOW_OPTIONS
#include "misc.h"
	return 0;
};

static struct kmem_cache *sdcardfs_tree_entry_cachep;

static void init_once(void *ptr)
{
	struct sdcardfs_tree_entry *te = ptr;

	inode_init_once(&te->vfs_inode);
}

int sdcardfs_init_tree_cache(void)
{
	sdcardfs_tree_entry_cachep = kmem_cache_create("sdcardfs_tree_entry",
		sizeof(struct sdcardfs_tree_entry),
		0, SLAB_RECLAIM_ACCOUNT, init_once);
	return sdcardfs_tree_entry_cachep != NULL ? 0 : -ENOMEM;
}

void sdcardfs_destroy_tree_cache(void)
{
	BUG_ON(sdcardfs_tree_entry_cachep == NULL);
	kmem_cache_destroy(sdcardfs_tree_entry_cachep);
}

static struct inode *sdcardfs_alloc_inode(struct super_block *sb)
{
	struct sdcardfs_tree_entry *te =
		kmem_cache_alloc(sdcardfs_tree_entry_cachep, GFP_KERNEL);

	if (te == NULL)
		return NULL;

	/* zero out everything except vfs_inode */
	memset(te, 0, offsetof(struct sdcardfs_tree_entry, vfs_inode));

	return &te->vfs_inode;
}

static void i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct sdcardfs_tree_entry *te = SDCARDFS_I(inode);

	BUG_ON(te->real.dentry);
	kmem_cache_free(sdcardfs_tree_entry_cachep, te);
}

static void sdcardfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, i_callback);
}

const struct super_operations sdcardfs_sops = {
	.put_super      = sdcardfs_put_super,
	.statfs         = sdcardfs_statfs,
	.remount_fs     = sdcardfs_remount_fs,
	.evict_inode    = sdcardfs_evict_inode,
	.umount_begin   = sdcardfs_umount_begin,
	.show_options   = sdcardfs_show_options,
	.alloc_inode    = sdcardfs_alloc_inode,
	.destroy_inode  = sdcardfs_destroy_inode,
	.drop_inode     = generic_delete_inode,
};


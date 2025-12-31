#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>

#include "http.h"

#define MODULE_NAME "vtfs"
#define VTFS_ROOT_INO 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("VTFS");

static const char *VTFS_TOKEN = "my_token";

struct vtfs_file_content {
    char *data;
    size_t size;
    size_t allocated;
};

struct vtfs_file_info {
    char name[256];
    ino_t ino;
    ino_t parent_ino;
    umode_t mode;
    bool is_dir;
    bool deleted;                 // IMPORTANT: never free nodes while mounted
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

/* ---- forward decls (fix your compile error) ---- */
static struct vtfs_file_info *find_file_info(ino_t ino);
static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

static int vtfs_fill_super(struct super_block *sb, void *data, int silent);
static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *token, void *data);
static void vtfs_kill_sb(struct super_block *sb);

static struct inode *vtfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode, int i_ino);
static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);
static int vtfs_iterate(struct file *filp, struct dir_context *ctx);

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl);
static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);

/* ---- helpers ---- */
static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

/* ---- ops tables ---- */
static const struct inode_operations vtfs_inode_ops = {
    .lookup  = vtfs_lookup,
    .create  = vtfs_create,
    .unlink  = vtfs_unlink,
    .mkdir   = vtfs_mkdir,
    .rmdir   = vtfs_rmdir,
    .setattr = simple_setattr,
};

static const struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

static const struct file_operations vtfs_file_ops = {
    .read  = vtfs_read,
    .write = vtfs_write,
};

static struct file_system_type vtfs_fs_type = {
    .name    = "vtfs",
    .mount   = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

/* ---- inode ---- */
static struct inode *vtfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode, int i_ino)
{
    struct inode *inode = new_inode(sb);
    if (!inode) return NULL;

    inode->i_ino  = i_ino;
    inode->i_mode = mode;

    if (S_ISDIR(mode)) set_nlink(inode, 2);
    else set_nlink(inode, 1);

    i_uid_write(inode, 0);
    i_gid_write(inode, 0);

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &vtfs_dir_ops : &vtfs_file_ops;

    return inode;
}

/* ---- finders (safe because we never free nodes while mounted) ---- */
static struct vtfs_file_info *find_file_info(ino_t ino)
{
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(fi, &vtfs_files, list) {
        if (!fi->deleted && fi->ino == ino) {
            mutex_unlock(&vtfs_files_lock);
            return fi;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino)
{
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->deleted) continue;
        if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0) {
            mutex_unlock(&vtfs_files_lock);
            return fi;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

/* ---- lookup / readdir ---- */
static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    struct vtfs_file_info *fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);
    if (!fi) return NULL;

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, fi->mode, fi->ino);
    if (!inode) return ERR_PTR(-ENOMEM);

    d_add(child_dentry, inode);
    return NULL;
}

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t current_ino = inode->i_ino;

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, current_ino, DT_DIR)) return 0;
        ctx->pos++;
        return 1;
    }

    if (ctx->pos == 1) {
        ino_t parent_ino = VTFS_ROOT_INO;
        struct vtfs_file_info *cur = find_file_info(current_ino);
        if (cur) parent_ino = cur->parent_ino;

        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) return 0;
        ctx->pos++;
        return 1;
    }

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        int idx = 2;

        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino != current_ino) continue;

            if (idx == ctx->pos) {
                unsigned char type = fi->is_dir ? DT_DIR : DT_REG;
                int ok = dir_emit(ctx, fi->name, strlen(fi->name), fi->ino, type);
                if (ok) ctx->pos++;
                mutex_unlock(&vtfs_files_lock);
                return ok ? 1 : 0;
            }
            idx++;
        }
    }
    mutex_unlock(&vtfs_files_lock);

    return 0;
}

/* ---- read/write ---- */
static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = find_file_info(inode->i_ino);
    if (!fi) return -ENOENT;

    mutex_lock(&fi->lock);

    if (*offset >= fi->content.size) {
        mutex_unlock(&fi->lock);
        return 0;
    }

    length = min(length, (size_t)(fi->content.size - *offset));

    if (!fi->content.data || copy_to_user(buffer, fi->content.data + *offset, length)) {
        mutex_unlock(&fi->lock);
        return -EFAULT;
    }

    *offset += length;
    mutex_unlock(&fi->lock);

    // notify server (optional)
    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(fi->name, name_enc);

        (void)vtfs_http_call(VTFS_TOKEN, "read", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return (ssize_t)length;
}

static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = find_file_info(inode->i_ino);
    if (!fi) return -ENOENT;

    // read user data first (don’t hold locks during user copy too long)
    char *tmp = kmalloc(length, GFP_KERNEL);
    if (!tmp) return -ENOMEM;

    if (copy_from_user(tmp, buffer, length)) {
        kfree(tmp);
        return -EFAULT;
    }
    for (size_t i = 0; i < length; i++) {
        if ((unsigned char)tmp[i] > 127) {
            kfree(tmp);
            return -EINVAL;
        }
    }

    mutex_lock(&fi->lock);

    if (*offset == 0) {
        fi->content.size = 0;
        if (fi->content.data)
            memset(fi->content.data, 0, fi->content.allocated);
    }

    if (*offset + length > fi->content.allocated) {
        size_t new_size = max(*offset + length, fi->content.allocated ? fi->content.allocated * 2 : 0UL);
        if (new_size == 0) new_size = PAGE_SIZE;

        char *new_data = krealloc(fi->content.data, new_size, GFP_KERNEL);
        if (!new_data) {
            mutex_unlock(&fi->lock);
            kfree(tmp);
            return -ENOMEM;
        }

        if (new_size > fi->content.allocated)
            memset(new_data + fi->content.allocated, 0, new_size - fi->content.allocated);

        fi->content.data = new_data;
        fi->content.allocated = new_size;
    }

    memcpy(fi->content.data + *offset, tmp, length);

    if (*offset + length > fi->content.size)
        fi->content.size = *offset + length;

    *offset += length;

    inode_set_mtime_to_ts(inode, current_time(inode));

    // prepare encoded payload (limit to 1024 bytes)
    size_t send_len = fi->content.size;
    if (send_len > 1024) send_len = 1024;

    char response[256] = {0};
    char parent_ino_str[32];
    char name_enc[3 * 256 + 1];

    ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
    encode(fi->name, name_enc);

    char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
    if (data_enc) {
        encode_n(fi->content.data ? fi->content.data : "", send_len, data_enc);
    }

    mutex_unlock(&fi->lock);

    if (data_enc) {
        (void)vtfs_http_call(VTFS_TOKEN, "write", response, sizeof(response),
                             3, "parent_ino", parent_ino_str, "name", name_enc, "data", data_enc);
        kfree(data_enc);
    }

    kfree(tmp);
    return (ssize_t)length;
}

/* ---- create/unlink/mkdir/rmdir ---- */
static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = false;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->mode = S_IFREG | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, fi->mode, fi->ino);
    if (!inode) return -ENOMEM;

    d_add(child_dentry, inode);

    // notify server
    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(VTFS_TOKEN, "create", response, sizeof(response),
                             3, "parent_ino", parent_ino_str, "name", name_enc, "data", "");
    }

    return 0;
}

static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    // DO NOT FREE nodes here, just mark deleted (avoid UAF on umount / dentry cache)
    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0 && !fi->is_dir) {
                fi->deleted = true;
                if (fi->content.data) {
                    kfree(fi->content.data);
                    fi->content.data = NULL;
                }
                fi->content.size = 0;
                fi->content.allocated = 0;
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    // notify server
    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(VTFS_TOKEN, "unlink", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, S_IFDIR | 0777, next_ino++);
    if (!inode) return -ENOMEM;

    inc_nlink(parent_inode);

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) {
        drop_nlink(parent_inode);
        iput(inode);
        return -ENOMEM;
    }

    mutex_init(&fi->lock);
    fi->is_dir = true;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->ino = inode->i_ino;
    fi->mode = S_IFDIR | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    d_add(child_dentry, inode);

    // notify server
    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(VTFS_TOKEN, "mkdir", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return 0;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (!simple_empty(child_dentry)) return -ENOTEMPTY;

    // mark deleted, do not free
    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0 && fi->is_dir) {
                fi->deleted = true;
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    drop_nlink(parent_inode);
    return simple_rmdir(parent_inode, child_dentry);
}

/* ---- mount/super ---- */
static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *token, void *data)
{
    return mount_nodev(fs_type, flags, data, vtfs_fill_super);
}

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, VTFS_ROOT_INO);
    if (!inode) return -ENOMEM;

    sb->s_root = d_make_root(inode);
    if (!sb->s_root) return -ENOMEM;

    return 0;
}

static void vtfs_kill_sb(struct super_block *sb)
{
    // IMPORTANT: do not touch vtfs_files here — avoid UAF during teardown
    kill_litter_super(sb);
}

/* ---- module init/exit ---- */
static int __init vtfs_init(void)
{
    return register_filesystem(&vtfs_fs_type);
}

static void __exit vtfs_exit(void)
{
    // assume unmounted before rmmod; now safe to free all nodes
    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi, *tmp;
        list_for_each_entry_safe(fi, tmp, &vtfs_files, list) {
            if (fi->content.data) kfree(fi->content.data);
            list_del(&fi->list);
            kfree(fi);
        }
    }
    mutex_unlock(&vtfs_files_lock);

    unregister_filesystem(&vtfs_fs_type);
}

module_init(vtfs_init);
module_exit(vtfs_exit);

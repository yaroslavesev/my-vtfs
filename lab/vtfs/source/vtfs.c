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

/* ========= data ========= */

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
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static DEFINE_MUTEX(vtfs_files_lock);
static int next_ino = 103;

/* ========= fwd decl ========= */

static struct vtfs_file_info *find_file_info(ino_t ino);
static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

static struct inode *vtfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode, int i_ino);

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);

static int vtfs_iterate(struct file *filp, struct dir_context *ctx);
static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl);
static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);

static int vtfs_fill_super(struct super_block *sb, void *data, int silent);
static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *token, void *data);
static void vtfs_kill_sb(struct super_block *sb);

/* ========= ops ========= */

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

/* ========= helpers ========= */

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

/* ========= inode ========= */

static struct inode *vtfs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode, int i_ino)
{
    struct inode *inode = new_inode(sb);
    if (!inode) return NULL;

    inode->i_ino  = i_ino;
    inode->i_mode = mode;

    if (S_ISDIR(mode))
        set_nlink(inode, 2);
    else
        set_nlink(inode, 1);

    i_uid_write(inode, 0);
    i_gid_write(inode, 0);

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &vtfs_dir_ops : &vtfs_file_ops;

    return inode;
}

/* ========= file ops ========= */

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if (!fi) return ret;

    mutex_lock(&fi->lock);

    if (*offset >= fi->content.size) {
        mutex_unlock(&fi->lock);
        return 0;
    }

    length = min(length, (size_t)(fi->content.size - *offset));

    if (copy_to_user(buffer, fi->content.data + *offset, length)) {
        mutex_unlock(&fi->lock);
        return -EFAULT;
    }

    *offset += length;
    ret = (ssize_t)length;

    mutex_unlock(&fi->lock);

    /* side-call: read */
    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(fi->name, name_enc);

        vtfs_http_call(VTFS_TOKEN, "read", response, sizeof(response),
                       2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return ret;
}

static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if (!fi) return ret;

    /* буфер из user */
    char *tmp = kmalloc(length, GFP_KERNEL);
    if (!tmp) return -ENOMEM;

    if (copy_from_user(tmp, buffer, length)) {
        kfree(tmp);
        return -EFAULT;
    }

    /* ASCII only */
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
        size_t new_size = max(*offset + length, fi->content.allocated * 2);
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
    ret = (ssize_t)length;

    inode_set_mtime_to_ts(inode, current_time(inode));

    /* подготовим данные для HTTP (ограничим, чтобы не улететь в конские URL) */
    size_t send_len = fi->content.size;
    if (send_len > 1024) send_len = 1024;

    char parent_ino_str[32];
    char name_enc[3 * 256 + 1];
    ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
    encode(fi->name, name_enc);

    char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
    if (!data_enc) {
        mutex_unlock(&fi->lock);
        kfree(tmp);
        return ret;
    }

    encode_n(fi->content.data ? fi->content.data : "", send_len, data_enc);

    mutex_unlock(&fi->lock);

    {
        char response[256] = {0};
        vtfs_http_call(VTFS_TOKEN, "write", response, sizeof(response),
                       3, "parent_ino", parent_ino_str, "name", name_enc, "data", data_enc);
    }

    kfree(data_enc);
    kfree(tmp);
    return ret;
}

/* ========= dir iterate ========= */

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t cur_ino = inode->i_ino;

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, cur_ino, DT_DIR)) return 0;
        ctx->pos++;
    }

    if (ctx->pos == 1) {
        ino_t parent_ino = VTFS_ROOT_INO;
        struct vtfs_file_info *cur = find_file_info(cur_ino);
        if (cur) parent_ino = cur->parent_ino;

        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) return 0;
        ctx->pos++;
    }

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        long idx = 2;

        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->parent_ino != cur_ino) continue;
            if (idx >= ctx->pos) {
                unsigned char type = fi->is_dir ? DT_DIR : DT_REG;
                if (!dir_emit(ctx, fi->name, strlen(fi->name), fi->ino, type)) {
                    mutex_unlock(&vtfs_files_lock);
                    return 0;
                }
                ctx->pos++;
            }
            idx++;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return 0;
}

/* ========= lookup ========= */

static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    struct vtfs_file_info *fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);
    if (!fi) return NULL;

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, fi->mode, fi->ino);
    if (!inode) return ERR_PTR(-ENOMEM);

    d_add(child_dentry, inode);
    return NULL;
}

/* ========= create/unlink/mkdir/rmdir ========= */

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                       struct dentry *child_dentry, umode_t mode, bool excl)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = false;
    fi->parent_ino = parent_ino;
    fi->mode = S_IFREG | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, fi->mode, fi->ino);
    if (!inode) {
        mutex_lock(&vtfs_files_lock);
        list_del(&fi->list);
        mutex_unlock(&vtfs_files_lock);
        kfree(fi);
        return -ENOMEM;
    }

    d_add(child_dentry, inode);

    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        vtfs_http_call(VTFS_TOKEN, "create", response, sizeof(response),
                       3, "parent_ino", parent_ino_str, "name", name_enc, "data", "");
    }

    return 0;
}

static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi, *tmp;
        list_for_each_entry_safe(fi, tmp, &vtfs_files, list) {
            if (!fi->is_dir &&
                fi->parent_ino == parent_ino &&
                strcmp(fi->name, name) == 0) {
                if (fi->content.data) kfree(fi->content.data);
                list_del(&fi->list);
                kfree(fi);
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        vtfs_http_call(VTFS_TOKEN, "unlink", response, sizeof(response),
                       2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
                      struct dentry *child_dentry, umode_t mode)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, parent_inode, S_IFDIR | 0777, next_ino++);
    if (!inode) return -ENOMEM;

    /* для каталогов VFS ожидает nlink++ у родителя */
    inc_nlink(parent_inode);

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) {
        drop_nlink(parent_inode);
        iput(inode);
        return -ENOMEM;
    }

    mutex_init(&fi->lock);
    fi->is_dir = true;
    fi->parent_ino = parent_ino;
    fi->ino = inode->i_ino;
    fi->mode = S_IFDIR | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    d_add(child_dentry, inode);

    {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        vtfs_http_call(VTFS_TOKEN, "mkdir", response, sizeof(response),
                       2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return 0;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (!simple_empty(child_dentry)) return -ENOTEMPTY;

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi, *tmp;
        list_for_each_entry_safe(fi, tmp, &vtfs_files, list) {
            if (fi->is_dir &&
                fi->parent_ino == parent_ino &&
                strcmp(fi->name, name) == 0) {
                list_del(&fi->list);
                kfree(fi);
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    /* simple_rmdir сам сделает drop_nlink(parent) и clear_nlink(child) */
    return simple_rmdir(parent_inode, child_dentry);
}

/* ========= super/mount ========= */

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, VTFS_ROOT_INO);
    if (!inode) return -ENOMEM;

    sb->s_root = d_make_root(inode);
    if (!sb->s_root) return -ENOMEM;

    return 0;
}

static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *token, void *data)
{
    return mount_nodev(fs_type, flags, data, vtfs_fill_super);
}

static void vtfs_kill_sb(struct super_block *sb)
{
    struct vtfs_file_info *fi, *tmp;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry_safe(fi, tmp, &vtfs_files, list) {
        if (fi->content.data) kfree(fi->content.data);
        list_del(&fi->list);
        kfree(fi);
    }
    mutex_unlock(&vtfs_files_lock);

    kill_litter_super(sb);
}

/* ========= finders ========= */

static struct vtfs_file_info *find_file_info(ino_t ino)
{
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->ino == ino) {
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
        if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0) {
            mutex_unlock(&vtfs_files_lock);
            return fi;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

/* ========= module ========= */

static int __init vtfs_init(void)
{
    return register_filesystem(&vtfs_fs_type);
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
}

module_init(vtfs_init);
module_exit(vtfs_exit);

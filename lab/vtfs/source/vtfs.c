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
#include <linux/namei.h>

#include "http.h"

#define MODULE_NAME "vtfs"
#define VTFS_ROOT_INO 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module with RAM storage");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

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
    bool is_dir;
    bool deleted;
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

static struct vtfs_file_info *find_file_info(ino_t ino);
static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

static struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data);
static void vtfs_kill_sb(struct super_block* sb);
static int vtfs_fill_super(struct super_block *sb, void *data, int silent);

static int vtfs_iterate(struct file* filp, struct dir_context* ctx);
static struct dentry* vtfs_lookup(struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag);

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool b);
static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);

static int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry);

static const struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link,
};

static const struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

static const struct file_operations vtfs_file_ops = {
    .read = vtfs_read,
    .write = vtfs_write,
};

static struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

static struct vtfs_file_info *find_file_info(ino_t ino)
{
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->ino == ino && !fi->deleted) {
            mutex_unlock(&vtfs_files_lock);
            return fi;
        }
    }
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->ino == ino && fi->deleted) {
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
        if (!fi->deleted && fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0) {
            mutex_unlock(&vtfs_files_lock);
            return fi;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = file_inode(filp);
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

    {
        int64_t ret_http;
        char response[512] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(fi->name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "read", response, sizeof(response),
                                  2,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc);
        if (ret_http < 0)
            pr_err("HTTP read failed: %lld\n", ret_http);
    }

    return ret;
}

static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = file_inode(filp);
    struct vtfs_file_info *fi = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if (!fi) return ret;

    if (length == 0) return 0;

    {
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
            size_t new_size = max(*offset + length, fi->content.allocated ? fi->content.allocated * 2 : (size_t)PAGE_SIZE);
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

        {
            size_t snap_len = fi->content.size;
            if (snap_len > 1024) snap_len = 1024;

            if (snap_len > 0) {
                char *snap = kmalloc(snap_len, GFP_KERNEL);
                if (snap) {
                    memcpy(snap, fi->content.data, snap_len);
                    mutex_unlock(&fi->lock);

                    {
                        char *data_enc = kmalloc(3 * snap_len + 1, GFP_KERNEL);
                        if (data_enc) {
                            int64_t ret_http;
                            char response[512] = {0};
                            char parent_ino_str[32];
                            char name_enc[3 * 256 + 1];

                            ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
                            encode(fi->name, name_enc);
                            encode_n(snap, snap_len, data_enc);

                            ret_http = vtfs_http_call(VTFS_TOKEN, "write", response, sizeof(response),
                                                      3,
                                                      "parent_ino", parent_ino_str,
                                                      "name", name_enc,
                                                      "data", data_enc);
                            if (ret_http < 0)
                                pr_err("HTTP write failed: %lld\n", ret_http);

                            kfree(data_enc);
                        }
                    }

                    kfree(snap);
                } else {
                    mutex_unlock(&fi->lock);
                }
            } else {
                mutex_unlock(&fi->lock);
            }
        }

        kfree(tmp);
    }

    return ret;
}

static struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data)
{
    struct dentry* ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
    if (!ret)
        pr_err("Can't mount file system\n");
    else
        pr_info("Mounted successfully\n");
    return ret;
}

static struct inode* vtfs_make_inode(struct super_block* sb, umode_t mode, ino_t ino)
{
    struct inode *inode = new_inode(sb);
    if (!inode) return NULL;

    inode_init_owner(&nop_mnt_idmap, inode, NULL, mode);
    inode->i_ino = ino;

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    if (S_ISDIR(mode)) {
        inode->i_op = &vtfs_inode_ops;
        inode->i_fop = &vtfs_dir_ops;
        set_nlink(inode, 2);
    } else {
        inode->i_op = &vtfs_inode_ops;
        inode->i_fop = &vtfs_file_ops;
        set_nlink(inode, 1);
    }

    return inode;
}

static struct dentry* vtfs_lookup(struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag)
{
    struct vtfs_file_info *fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);
    if (!fi) {
        d_add(child_dentry, NULL);
        return NULL;
    }

    {
        umode_t mode = fi->is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0777);
        struct inode *inode = vtfs_make_inode(parent_inode->i_sb, mode, fi->ino);
        if (!inode)
            return ERR_PTR(-ENOMEM);

        d_add(child_dentry, inode);
    }

    return NULL;
}

static int vtfs_iterate(struct file* filp, struct dir_context* ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t dir_ino = inode->i_ino;
    int pos = ctx->pos;

    if (pos < 0)
        return 0;

    if (pos == 0) {
        if (!dir_emit(ctx, ".", 1, dir_ino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }

    if (pos == 1) {
        ino_t pino = dir_ino;
        struct vtfs_file_info *cur = find_file_info(dir_ino);
        if (cur && cur->is_dir) pino = cur->parent_ino;
        if (!dir_emit(ctx, "..", 2, pino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        int count = 2;

        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino != dir_ino) continue;

            if (count == pos) {
                unsigned char type = fi->is_dir ? DT_DIR : DT_REG;
                int ok = dir_emit(ctx, fi->name, strlen(fi->name), fi->ino, type);
                if (ok) ctx->pos++;
                mutex_unlock(&vtfs_files_lock);
                return ok ? 1 : 0;
            }
            count++;
        }
    }
    mutex_unlock(&vtfs_files_lock);

    return 0;
}

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *root_inode;
    struct vtfs_file_info *root;

    sb->s_magic = 0x76746673;

    root = kmalloc(sizeof(*root), GFP_KERNEL);
    if (!root) return -ENOMEM;

    memset(root, 0, sizeof(*root));
    mutex_init(&root->lock);

    root->ino = VTFS_ROOT_INO;
    root->parent_ino = VTFS_ROOT_INO;
    root->is_dir = true;
    root->deleted = false;
    snprintf(root->name, sizeof(root->name), "%s", "");

    mutex_lock(&vtfs_files_lock);
    list_add(&root->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    root_inode = vtfs_make_inode(sb, S_IFDIR | 0777, VTFS_ROOT_INO);
    if (!root_inode) return -ENOMEM;

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) return -ENOMEM;

    return 0;
}

static void vtfs_kill_sb(struct super_block* sb)
{
    struct vtfs_file_info *fi, *tmp;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry_safe(fi, tmp, &vtfs_files, list) {
        if (fi->content.data)
            kfree(fi->content.data);
        list_del(&fi->list);
        kfree(fi);
    }
    mutex_unlock(&vtfs_files_lock);

    kill_litter_super(sb);
    pr_info("vtfs super block is destroyed. Unmount successfully.\n");
}

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool b)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;
    struct vtfs_file_info *fi;
    struct inode *inode;

    if (find_file_in_dir(name, parent_ino))
        return -EEXIST;

    fi = kmalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    memset(fi, 0, sizeof(*fi));
    mutex_init(&fi->lock);

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    fi->parent_ino = parent_ino;
    fi->is_dir = false;
    fi->deleted = false;
    snprintf(fi->name, sizeof(fi->name), "%s", name);
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_make_inode(parent_inode->i_sb, S_IFREG | 0777, fi->ino);
    if (!inode) return -ENOMEM;

    d_instantiate(child_dentry, inode);

    {
        int64_t ret_http;
        char response[512] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "create", response, sizeof(response),
                                  3,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc,
                                  "data", "");
        if (ret_http < 0)
            pr_err("HTTP create failed: %lld\n", ret_http);
    }

    return 0;
}

static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0) {
                fi->deleted = true;
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    {
        int64_t ret_http;
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "unlink", response, sizeof(response),
                                  2,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc);
        if (ret_http < 0)
            pr_err("HTTP unlink failed: %lld\n", ret_http);
    }

    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;
    struct vtfs_file_info *fi;
    struct inode *inode;

    if (find_file_in_dir(name, parent_ino))
        return -EEXIST;

    fi = kmalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    memset(fi, 0, sizeof(*fi));
    mutex_init(&fi->lock);

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    fi->parent_ino = parent_ino;
    fi->is_dir = true;
    fi->deleted = false;
    snprintf(fi->name, sizeof(fi->name), "%s", name);
    list_add(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_make_inode(parent_inode->i_sb, S_IFDIR | (mode & 0777), fi->ino);
    if (!inode) return -ENOMEM;

    inc_nlink(parent_inode);
    d_instantiate(child_dentry, inode);

    {
        int64_t ret_http;
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "mkdir", response, sizeof(response),
                                  2,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc);
        if (ret_http < 0)
            pr_err("HTTP mkdir failed: %lld\n", ret_http);
    }

    return 0;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (!simple_empty(child_dentry))
        return -ENOTEMPTY;

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

    return simple_rmdir(parent_inode, child_dentry);
}

static int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry)
{
    return -EPERM;
}

static int __init vtfs_init(void)
{
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0)
        LOG("VTFS joined the kernel\n");
    else
        LOG("Failed to register filesystem\n");
    return ret;
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
    LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);

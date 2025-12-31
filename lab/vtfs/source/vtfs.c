#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>

#include "http.h"

#define MODULE_NAME "vtfs"

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

static struct vtfs_file_info *__find_by_ino_nolock(ino_t ino)
{
    struct vtfs_file_info *fi;
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->ino == ino) return fi;
    }
    return NULL;
}

static struct vtfs_file_info *__find_by_name_parent_nolock(const char *name, ino_t parent_ino)
{
    struct vtfs_file_info *fi;
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->deleted) continue;
        if (fi->parent_ino == parent_ino && strcmp(fi->name, name) == 0) return fi;
    }
    return NULL;
}

static bool __dir_has_children_nolock(ino_t dir_ino)
{
    struct vtfs_file_info *fi;
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->deleted) continue;
        if (fi->parent_ino == dir_ino) return true;
    }
    return false;
}

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

static struct inode *vtfs_get_inode(struct super_block *sb, umode_t mode, int i_ino)
{
    struct inode *inode = new_inode(sb);
    if (!inode) return NULL;

    inode->i_ino = i_ino;
    inode->i_mode = mode;
    i_uid_write(inode, 0);
    i_gid_write(inode, 0);

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    return inode;
}

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi;
    ssize_t ret;

    mutex_lock(&vtfs_files_lock);
    fi = __find_by_ino_nolock(inode->i_ino);
    mutex_unlock(&vtfs_files_lock);

    if (!fi) return -ENOENT;
    if (fi->is_dir) return -EISDIR;

    mutex_lock(&fi->lock);

    if (*offset >= fi->content.size) {
        mutex_unlock(&fi->lock);
        return 0;
    }

    length = min(length, (size_t)(fi->content.size - *offset));

    if (fi->content.data == NULL) {
        mutex_unlock(&fi->lock);
        return 0;
    }

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
        if (ret_http < 0) {
            pr_err("HTTP read failed: %lld\n", ret_http);
        }
    }

    return ret;
}

static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi;
    char *tmp;
    ssize_t ret;

    mutex_lock(&vtfs_files_lock);
    fi = __find_by_ino_nolock(inode->i_ino);
    mutex_unlock(&vtfs_files_lock);

    if (!fi) return -ENOENT;
    if (fi->is_dir) return -EISDIR;

    tmp = kmalloc(length, GFP_KERNEL);
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
        size_t new_size = max(*offset + length, fi->content.allocated * 2);
        if (new_size == 0) new_size = PAGE_SIZE;

        {
            char *new_data = krealloc(fi->content.data, new_size, GFP_KERNEL);
            if (!new_data) {
                mutex_unlock(&fi->lock);
                kfree(tmp);
                return -ENOMEM;
            }

            if (new_size > fi->content.allocated) {
                memset(new_data + fi->content.allocated, 0, new_size - fi->content.allocated);
            }

            fi->content.data = new_data;
            fi->content.allocated = new_size;
        }
    }

    if (fi->content.data && length > 0) {
        memcpy(fi->content.data + *offset, tmp, length);
    }

    if (*offset + length > fi->content.size)
        fi->content.size = *offset + length;

    *offset += length;
    ret = (ssize_t)length;

    inode_set_mtime_to_ts(inode, current_time(inode));

    {
        int64_t ret_http;
        char response[512] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        size_t send_len = fi->content.size;
        if (send_len > 1024) send_len = 1024;

        {
            char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
            if (data_enc) {
                ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
                encode(fi->name, name_enc);
                encode_n(fi->content.data ? fi->content.data : "", send_len, data_enc);

                mutex_unlock(&fi->lock);

                ret_http = vtfs_http_call(VTFS_TOKEN, "write", response, sizeof(response),
                                          3,
                                          "parent_ino", parent_ino_str,
                                          "name", name_enc,
                                          "data", data_enc);
                if (ret_http < 0) {
                    pr_err("HTTP write failed: %lld\n", ret_http);
                }

                kfree(data_enc);
                kfree(tmp);
                return ret;
            }
        }
    }

    mutex_unlock(&fi->lock);
    kfree(tmp);
    return ret;
}

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t dir_ino = inode->i_ino;
    loff_t pos = ctx->pos;

    if (pos == 0) {
        if (!dir_emit(ctx, ".", 1, dir_ino, DT_DIR)) return 0;
        ctx->pos++;
        return 1;
    }

    if (pos == 1) {
        ino_t parent_ino = dir_ino;
        mutex_lock(&vtfs_files_lock);
        {
            struct vtfs_file_info *cur = __find_by_ino_nolock(dir_ino);
            if (cur) parent_ino = cur->parent_ino;
        }
        mutex_unlock(&vtfs_files_lock);

        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) return 0;
        ctx->pos++;
        return 1;
    }

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *fi;
        loff_t idx = 2;

        list_for_each_entry(fi, &vtfs_files, list) {
            if (fi->deleted) continue;
            if (fi->parent_ino != dir_ino) continue;

            if (idx == pos) {
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

static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    struct vtfs_file_info *fi;
    struct inode *inode;

    mutex_lock(&vtfs_files_lock);
    fi = __find_by_name_parent_nolock(child_dentry->d_name.name, parent_inode->i_ino);
    mutex_unlock(&vtfs_files_lock);

    if (!fi) return NULL;

    inode = vtfs_get_inode(parent_inode->i_sb,
                           fi->is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0777),
                           fi->ino);
    if (!inode) return NULL;

    if (fi->is_dir) {
        set_nlink(inode, 2);
        inode->i_op = parent_inode->i_op;
        inode->i_fop = parent_inode->i_fop;
    } else {
        set_nlink(inode, 1);
        inode->i_op = parent_inode->i_op;
        inode->i_fop = parent_inode->i_sb->s_root->d_inode->i_fop;
    }

    d_add(child_dentry, inode);
    return NULL;
}

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                       struct dentry *child_dentry, umode_t mode, bool excl)
{
    struct vtfs_file_info *fi;
    struct inode *inode;

    mutex_lock(&vtfs_files_lock);
    if (__find_by_name_parent_nolock(child_dentry->d_name.name, parent_inode->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }
    mutex_unlock(&vtfs_files_lock);

    fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = false;
    fi->deleted = false;
    fi->parent_ino = parent_inode->i_ino;
    strscpy(fi->name, child_dentry->d_name.name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    list_add_tail(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_get_inode(parent_inode->i_sb, S_IFREG | 0777, fi->ino);
    if (!inode) return -ENOMEM;

    set_nlink(inode, 1);

    inode->i_op = parent_inode->i_op;
    inode->i_fop = parent_inode->i_sb->s_root->d_inode->i_fop;

    d_instantiate(child_dentry, inode);
    dget(child_dentry);

    {
        int64_t ret_http;
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(fi->name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "create", response, sizeof(response),
                                  3,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc,
                                  "data", "");
        if (ret_http < 0) {
            pr_err("HTTP create failed: %lld\n", ret_http);
        }
    }

    return 0;
}

static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    fi = __find_by_name_parent_nolock(child_dentry->d_name.name, parent_inode->i_ino);
    if (fi) fi->deleted = true;
    mutex_unlock(&vtfs_files_lock);

    {
        int64_t ret_http;
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_inode->i_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(child_dentry->d_name.name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "unlink", response, sizeof(response),
                                  2,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc);
        if (ret_http < 0) {
            pr_err("HTTP unlink failed: %lld\n", ret_http);
        }
    }

    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
                      struct dentry *child_dentry, umode_t mode)
{
    struct vtfs_file_info *fi;
    struct inode *inode;

    mutex_lock(&vtfs_files_lock);
    if (__find_by_name_parent_nolock(child_dentry->d_name.name, parent_inode->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }
    mutex_unlock(&vtfs_files_lock);

    fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = true;
    fi->deleted = false;
    fi->parent_ino = parent_inode->i_ino;
    strscpy(fi->name, child_dentry->d_name.name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = next_ino++;
    list_add_tail(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_get_inode(parent_inode->i_sb, S_IFDIR | 0777, fi->ino);
    if (!inode) return -ENOMEM;

    set_nlink(inode, 2);
    inc_nlink(parent_inode);

    inode->i_op = parent_inode->i_op;
    inode->i_fop = parent_inode->i_fop;

    d_instantiate(child_dentry, inode);
    dget(child_dentry);

    {
        int64_t ret_http;
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_inode->i_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(child_dentry->d_name.name, name_enc);

        ret_http = vtfs_http_call(VTFS_TOKEN, "mkdir", response, sizeof(response),
                                  2,
                                  "parent_ino", parent_ino_str,
                                  "name", name_enc);
        if (ret_http < 0) {
            pr_err("HTTP mkdir failed: %lld\n", ret_http);
        }
    }

    return 0;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    ino_t dir_ino = d_inode(child_dentry)->i_ino;
    struct vtfs_file_info *fi;

    mutex_lock(&vtfs_files_lock);
    if (__dir_has_children_nolock(dir_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTEMPTY;
    }
    fi = __find_by_name_parent_nolock(child_dentry->d_name.name, parent_inode->i_ino);
    if (fi) fi->deleted = true;
    mutex_unlock(&vtfs_files_lock);

    return simple_rmdir(parent_inode, child_dentry);
}

static int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry)
{
    return -EPERM;
}

static const struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir  = vtfs_mkdir,
    .rmdir  = vtfs_rmdir,
    .link   = vtfs_link,
};

static const struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

static const struct file_operations vtfs_file_ops = {
    .read  = vtfs_read,
    .write = vtfs_write,
};

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *root = vtfs_get_inode(sb, S_IFDIR | 0777, 100);
    if (!root) return -ENOMEM;

    set_nlink(root, 2);
    root->i_op = &vtfs_inode_ops;
    root->i_fop = &vtfs_dir_ops;

    sb->s_root = d_make_root(root);
    if (!sb->s_root) return -ENOMEM;

    return 0;
}

static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
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

static struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

static int __init vtfs_init(void)
{
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0) LOG("VTFS joined the kernel\n");
    else LOG("Failed to register filesystem\n");
    return ret;
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
    LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);

static int vtfs_open_file_dummy(struct inode *inode, struct file *file) { return 0; }

static const struct file_operations vtfs_root_file_ops = {
    .read  = vtfs_read,
    .write = vtfs_write,
    .iterate_shared = vtfs_iterate,
    .open = vtfs_open_file_dummy,
};

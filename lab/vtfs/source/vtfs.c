#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/idr.h>
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
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data);
void vtfs_kill_sb(struct super_block* sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);
struct inode* vtfs_get_inode(struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);
struct dentry* vtfs_lookup(struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag);
int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool b);
int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);
int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);
int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry);

static struct vtfs_file_info *find_file_info(ino_t ino);
static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link,
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .read = vtfs_read,
    .write = vtfs_write,
};

struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *file_info = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if (!file_info) return ret;

    mutex_lock(&file_info->lock);

    if (*offset >= file_info->content.size) {
        mutex_unlock(&file_info->lock);
        return 0;
    }

    length = min(length, (size_t)(file_info->content.size - *offset));

    if (copy_to_user(buffer, file_info->content.data + *offset, length)) {
        mutex_unlock(&file_info->lock);
        return -EFAULT;
    }

    *offset += length;
    ret = (ssize_t)length;

    mutex_unlock(&file_info->lock);

    {
        int64_t ret_http;
        char response[512] = {0};

        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(file_info->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(file_info->name, name_enc);

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

ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *file_info = find_file_info(inode->i_ino);
    ssize_t ret = -ENOENT;

    if (!file_info) return ret;

    mutex_lock(&file_info->lock);

    if (*offset == 0) {
        file_info->content.size = 0;
        if (file_info->content.data)
            memset(file_info->content.data, 0, file_info->content.allocated);
    }

    if (*offset + length > file_info->content.allocated) {
        size_t new_size = max(*offset + length, file_info->content.allocated * 2);
        if (new_size == 0) new_size = PAGE_SIZE;

        char *new_data = krealloc(file_info->content.data, new_size, GFP_KERNEL);
        if (!new_data) {
            mutex_unlock(&file_info->lock);
            return -ENOMEM;
        }

        if (new_size > file_info->content.allocated) {
            memset(new_data + file_info->content.allocated, 0,
                   new_size - file_info->content.allocated);
        }

        file_info->content.data = new_data;
        file_info->content.allocated = new_size;
    }

    char *tmp_buffer = kmalloc(length, GFP_KERNEL);
    if (!tmp_buffer) {
        mutex_unlock(&file_info->lock);
        return -ENOMEM;
    }

    if (copy_from_user(tmp_buffer, buffer, length)) {
        kfree(tmp_buffer);
        mutex_unlock(&file_info->lock);
        return -EFAULT;
    }

    for (size_t i = 0; i < length; i++) {
        if ((unsigned char)tmp_buffer[i] > 127) {
            kfree(tmp_buffer);
            mutex_unlock(&file_info->lock);
            return -EINVAL;
        }
    }

    memcpy(file_info->content.data + *offset, tmp_buffer, length);

    if (*offset + length > file_info->content.size)
        file_info->content.size = *offset + length;

    *offset += length;
    ret = (ssize_t)length;

    inode_set_mtime_to_ts(inode, current_time(inode));

    {
        int64_t ret_http;
        char response[512] = {0};

        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        size_t send_len = file_info->content.size;
        if (send_len > 1024) send_len = 1024;

        char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
        if (data_enc) {
            ino_to_str(file_info->parent_ino, parent_ino_str, sizeof(parent_ino_str));
            encode(file_info->name, name_enc);
            encode_n(file_info->content.data ? file_info->content.data : "", send_len, data_enc);

            mutex_unlock(&file_info->lock);

            ret_http = vtfs_http_call(VTFS_TOKEN, "write", response, sizeof(response),
                                      3,
                                      "parent_ino", parent_ino_str,
                                      "name", name_enc,
                                      "data", data_enc);
            if (ret_http < 0) {
                pr_err("HTTP write failed: %lld\n", ret_http);
            }

            kfree(data_enc);
        } else {
            mutex_unlock(&file_info->lock);
        }
    }

    kfree(tmp_buffer);
    return ret;
}

struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data)
{
    struct dentry* ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
    if (ret == NULL) {
        pr_err("Can't mount file system\n");
    } else {
        pr_info("Mounted successfully\n");
    }
    return ret;
}

struct inode* vtfs_get_inode(struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino)
{
    struct inode *inode = new_inode(sb);
    if (inode != NULL) {
        inode->i_mode = mode;
        i_uid_write(inode, 0);
        i_gid_write(inode, 0);
        inode->i_ino = i_ino;

        inode_set_atime_to_ts(inode, current_time(inode));
        inode_set_mtime_to_ts(inode, current_time(inode));
        inode_set_ctime_to_ts(inode, current_time(inode));
    }
    return inode;
}

struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flag)
{
    const char *name = child_dentry->d_name.name;
    struct vtfs_file_info *file_info;

    file_info = find_file_in_dir(name, parent_inode->i_ino);
    if (file_info) {
        struct inode *inode = vtfs_get_inode(
            parent_inode->i_sb,
            NULL,
            file_info->is_dir ? (S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO)
                              : (S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO),
            file_info->ino
        );

        if (inode) {
            inode->i_op = &vtfs_inode_ops;
            inode->i_fop = file_info->is_dir ? &vtfs_dir_ops : &vtfs_file_ops;
            d_add(child_dentry, inode);
        }
    }
    return NULL;
}

static struct vtfs_file_info *find_file_info(ino_t ino)
{
    struct vtfs_file_info *file_info;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(file_info, &vtfs_files, list) {
        if (file_info->ino == ino) {
            mutex_unlock(&vtfs_files_lock);
            return file_info;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino)
{
    struct vtfs_file_info *file_info;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry(file_info, &vtfs_files, list) {
        if (file_info->parent_ino == parent_ino && strcmp(file_info->name, name) == 0) {
            mutex_unlock(&vtfs_files_lock);
            return file_info;
        }
    }
    mutex_unlock(&vtfs_files_lock);
    return NULL;
}

int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct dentry *dentry = filp->f_path.dentry;
    struct inode *inode = dentry->d_inode;
    ino_t current_ino = inode->i_ino;
    int pos = ctx->pos;

    if (pos < 0)
        return 0;

    if (pos == 0) {
        if (!dir_emit(ctx, ".", 1, current_ino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }

    if (pos == 1) {
        struct vtfs_file_info *current_dir = find_file_info(current_ino);
        ino_t parent_ino = current_dir ? current_dir->parent_ino : 100;
        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *file_info;
        int count = 2;

        list_for_each_entry(file_info, &vtfs_files, list) {
            if (file_info->parent_ino == current_ino) {
                if (count == pos) {
                    unsigned char type = file_info->is_dir ? DT_DIR : DT_REG;
                    int ok = dir_emit(ctx, file_info->name, strlen(file_info->name),
                                      file_info->ino, type);
                    if (ok) ctx->pos++;
                    mutex_unlock(&vtfs_files_lock);
                    return ok ? 1 : 0;
                }
                count++;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    return 0;
}

int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO, 100);
    if (inode == NULL) return -ENOMEM;

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;

    sb->s_root = d_make_root(inode);
    if (sb->s_root == NULL) return -ENOMEM;

    return 0;
}

void vtfs_kill_sb(struct super_block* sb)
{
    struct vtfs_file_info *file_info, *tmp;

    mutex_lock(&vtfs_files_lock);
    list_for_each_entry_safe(file_info, tmp, &vtfs_files, list) {
        if (file_info->content.data) kfree(file_info->content.data);
        list_del(&file_info->list);
        kfree(file_info);
    }
    mutex_unlock(&vtfs_files_lock);

    kill_litter_super(sb);
    pr_info("vtfs super block is destroyed. Unmount successfully.\n");
}

int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                struct dentry *child_dentry, umode_t mode, bool b)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino))
        return -EEXIST;

    struct vtfs_file_info *new_file_info = kmalloc(sizeof(*new_file_info), GFP_KERNEL);
    if (!new_file_info) return -ENOMEM;

    memset(new_file_info, 0, sizeof(*new_file_info));
    mutex_init(&new_file_info->lock);

    mutex_lock(&vtfs_files_lock);
    new_file_info->ino = next_ino++;
    new_file_info->is_dir = false;
    new_file_info->parent_ino = parent_ino;
    snprintf(new_file_info->name, sizeof(new_file_info->name), "%s", name);
    list_add(&new_file_info->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, NULL,
                                         S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO,
                                         new_file_info->ino);
    if (!inode) {
        mutex_lock(&vtfs_files_lock);
        list_del(&new_file_info->list);
        mutex_unlock(&vtfs_files_lock);
        kfree(new_file_info);
        return -ENOMEM;
    }

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_file_ops;
    d_add(child_dentry, inode);

    {
        int64_t ret_http;
        char response[512] = {0};

        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(new_file_info->parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(new_file_info->name, name_enc);

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

int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *file_info, *tmp;
        list_for_each_entry_safe(file_info, tmp, &vtfs_files, list) {
            if (file_info->parent_ino == parent_ino && !strcmp(name, file_info->name)) {
                if (file_info->content.data) kfree(file_info->content.data);
                list_del(&file_info->list);
                kfree(file_info);
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
        if (ret_http < 0) {
            pr_err("HTTP unlink failed: %lld\n", ret_http);
        }
    }

    return simple_unlink(parent_inode, child_dentry);
}

int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
               struct dentry *child_dentry, umode_t mode)
{
    ino_t parent_ino = parent_inode->i_ino;
    const char *name = child_dentry->d_name.name;

    if (find_file_in_dir(name, parent_ino))
        return -EEXIST;

    struct inode *inode;

    mutex_lock(&vtfs_files_lock);
    inode = vtfs_get_inode(parent_inode->i_sb, NULL, S_IFDIR | mode, next_ino++);
    if (!inode) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    struct vtfs_file_info *dir_info = kmalloc(sizeof(*dir_info), GFP_KERNEL);
    if (!dir_info) {
        iput(inode);
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    memset(dir_info, 0, sizeof(*dir_info));
    mutex_init(&dir_info->lock);

    strncpy(dir_info->name, name, sizeof(dir_info->name) - 1);
    dir_info->ino = inode->i_ino;
    dir_info->parent_ino = parent_ino;
    dir_info->is_dir = true;

    list_add(&dir_info->list, &vtfs_files);

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;
    d_add(child_dentry, inode);

    mutex_unlock(&vtfs_files_lock);

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
        if (ret_http < 0) {
            pr_err("HTTP mkdir failed: %lld\n", ret_http);
        }
    }

    return 0;
}

int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    struct inode *dir_inode = d_inode(child_dentry);

    if (!simple_empty(child_dentry))
        return -ENOTEMPTY;

    mutex_lock(&vtfs_files_lock);
    {
        struct vtfs_file_info *dir_info, *tmp;
        list_for_each_entry_safe(dir_info, tmp, &vtfs_files, list) {
            if (!strcmp(name, dir_info->name) && dir_info->ino == dir_inode->i_ino) {
                list_del(&dir_info->list);
                kfree(dir_info);
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    return simple_rmdir(parent_inode, child_dentry);
}

int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry)
{
    struct inode *old_inode = old_dentry->d_inode;
    struct vtfs_file_info *old_file_info;
    struct vtfs_file_info *new_file_info;

    if (!S_ISREG(old_inode->i_mode))
        return -EPERM;

    mutex_lock(&vtfs_files_lock);

    old_file_info = find_file_info(old_inode->i_ino);
    if (!old_file_info) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOENT;
    }

    if (find_file_in_dir(new_dentry->d_name.name, parent_dir->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }

    new_file_info = kzalloc(sizeof(*new_file_info), GFP_KERNEL);
    if (!new_file_info) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    strncpy(new_file_info->name, new_dentry->d_name.name, sizeof(new_file_info->name) - 1);
    new_file_info->ino = old_file_info->ino;
    new_file_info->parent_ino = parent_dir->i_ino;
    new_file_info->is_dir = false;
    new_file_info->content = old_file_info->content;
    mutex_init(&new_file_info->lock);

    list_add(&new_file_info->list, &vtfs_files);
    ihold(old_inode);

    mutex_unlock(&vtfs_files_lock);

    struct inode *new_inode = vtfs_get_inode(parent_dir->i_sb, NULL, old_inode->i_mode, new_file_info->ino);
    if (!new_inode)
        return -ENOMEM;

    d_instantiate(new_dentry, new_inode);
    return 0;
}

static int __init vtfs_init(void)
{
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0) {
        LOG("VTFS joined the kernel\n");
    } else {
        LOG("Failed to register filesystem\n");
    }
    return ret;
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
    LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);

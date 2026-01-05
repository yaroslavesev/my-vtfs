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
#include <linux/atomic.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/kernel.h>

#include "http.h"

#define MODULE_NAME "vtfs"
#define VTFS_ROOT_INO 100
#define VTFS_SERVER_ROOT_INO 0
#define VTFS_MAGIC 0x56544653

#define VTFS_INO_STR_MAX    32
#define VTFS_NAME_MAX       256
#define VTFS_NAME_ENC_MAX   (3 * VTFS_NAME_MAX + 1)
#define VTFS_RESP_BIG       4096

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("VTFS");

static char *token = "my_token";
module_param(token, charp, 0644);
MODULE_PARM_DESC(token, "VTFS auth token");

static atomic_t vtfs_unmounting = ATOMIC_INIT(0);

struct vtfs_file_content {
    char *data;
    size_t size;
    size_t allocated;
};

struct vtfs_file_info {
    char name[VTFS_NAME_MAX];
    ino_t ino;
    ino_t parent_ino;
    umode_t mode;
    bool is_dir;
    bool deleted;
    struct inode *inode;
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

static struct vtfs_file_info *find_file_info(ino_t ino);
static struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);

static int vtfs_fill_super(struct super_block *sb, void *data, int silent);
static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data);
static void vtfs_kill_sb(struct super_block *sb);

static struct inode *vtfs_get_inode(struct super_block *sb, umode_t mode, int i_ino, struct vtfs_file_info *fi);
static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);
static int vtfs_iterate(struct file *filp, struct dir_context *ctx);

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl);
static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);

static int vtfs_open(struct inode *inode, struct file *filp);
static int vtfs_release(struct inode *inode, struct file *filp);

static void vtfs_put_super(struct super_block *sb);
static void vtfs_evict_inode(struct inode *inode);

static const struct super_operations vtfs_sops = {
    .statfs      = simple_statfs,
    .drop_inode  = generic_delete_inode,
    .put_super   = vtfs_put_super,
    .evict_inode = vtfs_evict_inode,
};

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
    .open           = vtfs_open,
    .release        = vtfs_release,
};

static const struct file_operations vtfs_file_ops = {
    .read    = vtfs_read,
    .write   = vtfs_write,
    .open    = vtfs_open,
    .release = vtfs_release,
};

static struct file_system_type vtfs_fs_type = {
    .name    = "vtfs",
    .mount   = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

static ino_t vtfs_to_server_ino(ino_t local_ino)
{
    return (local_ino == VTFS_ROOT_INO) ? (ino_t)VTFS_SERVER_ROOT_INO : local_ino;
}

static bool vtfs_parse_created_ino(const char *json, ino_t *out_ino)
{
    const char *p = strstr(json, "\"ino\":");
    if (!p) return false;
    p += strlen("\"ino\":");
    {
        unsigned long long v = 0;
        if (sscanf(p, "%llu", &v) != 1) return false;
        *out_ino = (ino_t)v;
        return true;
    }
}

static int vtfs_parse_list_and_add_children(const char *json, ino_t parent_local_ino)
{
    const char *p = json;
    int added = 0;

    while (p && *p) {
        const char *ino_k = strstr(p, "\"ino\":");
        if (!ino_k) break;
        ino_k += strlen("\"ino\":");

        unsigned long long v = 0;
        int consumed = 0;
        if (sscanf(ino_k, "%llu%n", &v, &consumed) != 1) break;
        p = ino_k + consumed;

        const char *name_k = strstr(p, "\"name\":\"");
        if (!name_k) break;
        name_k += strlen("\"name\":\"");
        const char *name_end = strchr(name_k, '"');
        if (!name_end) break;

        char name[VTFS_NAME_MAX];
        size_t nlen = (size_t)(name_end - name_k);
        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
        memcpy(name, name_k, nlen);
        name[nlen] = '\0';

        const char *dir_k = strstr(name_end, "\"is_dir\":");
        if (!dir_k) break;
        dir_k += strlen("\"is_dir\":");

        bool is_dir = false;
        if (!strncmp(dir_k, "true", 4)) is_dir = true;
        else if (!strncmp(dir_k, "false", 5)) is_dir = false;
        else break;

        mutex_lock(&vtfs_files_lock);
        {
            struct vtfs_file_info *exists;
            list_for_each_entry(exists, &vtfs_files, list) {
                if (exists->deleted) continue;
                if (exists->parent_ino == parent_local_ino && strcmp(exists->name, name) == 0) {
                    mutex_unlock(&vtfs_files_lock);
                    goto next_item;
                }
            }
        }
        mutex_unlock(&vtfs_files_lock);

        {
            struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
            if (!fi) break;

            mutex_init(&fi->lock);
            fi->is_dir = is_dir;
            fi->deleted = false;
            fi->parent_ino = parent_local_ino;
            fi->ino = (ino_t)v;
            fi->mode = (is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0777));
            strscpy(fi->name, name, sizeof(fi->name));

            mutex_lock(&vtfs_files_lock);
            list_add(&fi->list, &vtfs_files);
            if ((int)fi->ino >= next_ino) next_ino = (int)fi->ino + 1;
            mutex_unlock(&vtfs_files_lock);

            added++;
        }

next_item:
        {
            const char *brace = strchr(p, '}');
            if (!brace) break;
            p = brace + 1;
        }
    }

    return added;
}

static int vtfs_sync_from_server_dir(ino_t parent_local_ino)
{
    const size_t resp_sz = 64 * 1024;
    char *resp = kmalloc(resp_sz, GFP_KERNEL);
    if (!resp)
        return -ENOMEM;

    memset(resp, 0, resp_sz);

    if (atomic_read(&vtfs_unmounting)) {
        kfree(resp);
        return 0;
    }

    char parent_ino_str[VTFS_INO_STR_MAX];
    ino_to_str(vtfs_to_server_ino(parent_local_ino), parent_ino_str, sizeof(parent_ino_str));

    (void)vtfs_http_call(token, "list", resp, resp_sz,
                         1, "parent_ino", parent_ino_str);

    resp[resp_sz - 1] = '\0';

    (void)vtfs_parse_list_and_add_children(resp, parent_local_ino);

    kfree(resp);
    return 0;
}

static int vtfs_fetch_file_from_server(struct vtfs_file_info *fi)
{
    if (!fi || fi->is_dir) return -EINVAL;
    if (atomic_read(&vtfs_unmounting)) return -EAGAIN;

    char parent_ino_str[VTFS_INO_STR_MAX];
    char name_enc[VTFS_NAME_ENC_MAX];

    ino_to_str(vtfs_to_server_ino(fi->parent_ino), parent_ino_str, sizeof(parent_ino_str));
    encode(fi->name, name_enc);

    size_t cap = 4096;
    for (int tries = 0; tries < 6; tries++) {
        char *resp = kmalloc(cap, GFP_KERNEL);
        if (!resp) return -ENOMEM;
        memset(resp, 0, cap);

        size_t payload_len = 0;
        int64_t rc = vtfs_http_call2(token, "read",
                                     resp, cap,
                                     &payload_len,
                                     2, "parent_ino", parent_ino_str, "name", name_enc);

        if (rc == 0 && payload_len <= cap) {
            mutex_lock(&fi->lock);

            if (payload_len > fi->content.allocated) {
                char *new_data = krealloc(fi->content.data, payload_len ? payload_len : 1, GFP_KERNEL);
                if (!new_data && payload_len > 0) {
                    mutex_unlock(&fi->lock);
                    kfree(resp);
                    return -ENOMEM;
                }
                fi->content.data = new_data;
                fi->content.allocated = payload_len ? payload_len : 1;
            }

            if (payload_len > 0 && fi->content.data)
                memcpy(fi->content.data, resp, payload_len);

            fi->content.size = payload_len;

            mutex_unlock(&fi->lock);
            kfree(resp);
            return 0;
        }

        kfree(resp);

        if (rc < 0)
            return -EIO;

        cap *= 2;
        if (cap > (256 * 1024))
            return -EFBIG;
    }

    return -EIO;
}

static struct inode *vtfs_get_inode(struct super_block *sb, umode_t mode, int i_ino, struct vtfs_file_info *fi)
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

    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &vtfs_dir_ops : &vtfs_file_ops;

    inode->i_private = fi;
    return inode;
}

static int vtfs_open(struct inode *inode, struct file *filp)
{
    struct vtfs_file_info *fi = (struct vtfs_file_info *)inode->i_private;
    filp->private_data = fi;
    return 0;
}

static int vtfs_release(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
    return 0;
}

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

static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    struct vtfs_file_info *fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);

    if (!fi && !atomic_read(&vtfs_unmounting)) {
        (void)vtfs_sync_from_server_dir(parent_inode->i_ino);
        fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);
    }

    if (!fi) {
        d_add(child_dentry, NULL);
        return NULL;
    }

    if (fi->inode) {
        struct inode *inode = igrab(fi->inode);
        if (inode) {
            d_add(child_dentry, inode);
            return NULL;
        }
    }

    {
        struct inode *inode = vtfs_get_inode(parent_inode->i_sb, fi->mode, fi->ino, fi);
        if (!inode) return ERR_PTR(-ENOMEM);

        mutex_lock(&vtfs_files_lock);
        fi->inode = inode;
        mutex_unlock(&vtfs_files_lock);

        d_add(child_dentry, inode);
    }

    return NULL;
}

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t current_ino = inode->i_ino;

    if (ctx->pos == 0 && !atomic_read(&vtfs_unmounting))
        (void)vtfs_sync_from_server_dir(current_ino);

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, current_ino, DT_DIR)) return 0;
        ctx->pos = 1;
    }
    if (ctx->pos == 1) {
        ino_t parent_ino = VTFS_ROOT_INO;
        struct vtfs_file_info *cur = find_file_info(current_ino);
        if (cur) parent_ino = cur->parent_ino;

        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR)) return 0;
        ctx->pos = 2;
    }

    while (1) {
        char name[VTFS_NAME_MAX];
        ino_t ino_out = 0;
        unsigned char type_out = DT_UNKNOWN;
        bool found = false;

        mutex_lock(&vtfs_files_lock);
        {
            struct vtfs_file_info *fi;
            int idx = 2;

            list_for_each_entry(fi, &vtfs_files, list) {
                if (fi->deleted) continue;
                if (fi->parent_ino != current_ino) continue;

                if (idx >= (int)ctx->pos) {
                    strscpy(name, fi->name, sizeof(name));
                    ino_out = fi->ino;
                    type_out = fi->is_dir ? DT_DIR : DT_REG;
                    found = true;
                    break;
                }
                idx++;
            }
        }
        mutex_unlock(&vtfs_files_lock);

        if (!found)
            break;

        if (!dir_emit(ctx, name, strlen(name), ino_out, type_out))
            return 0;

        ctx->pos++;
    }

    return 0;
}

static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = filp->private_data ? filp->private_data : find_file_info(inode->i_ino);
    if (!fi) return -ENOENT;

    mutex_lock(&fi->lock);
    bool need_fetch = (!fi->is_dir && (fi->content.size == 0) && (*offset == 0));
    mutex_unlock(&fi->lock);

    if (need_fetch && !atomic_read(&vtfs_unmounting))
        (void)vtfs_fetch_file_from_server(fi);

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

    *offset += (loff_t)length;
    mutex_unlock(&fi->lock);

    return (ssize_t)length;
}

static ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = filp->private_data ? filp->private_data : find_file_info(inode->i_ino);
    if (!fi) return -ENOENT;

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

    if ((size_t)(*offset) + length > fi->content.allocated) {
        size_t need = (size_t)(*offset) + length;
        size_t new_size = max(need, fi->content.allocated ? fi->content.allocated * 2 : 0UL);
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

    if ((size_t)(*offset) + length > fi->content.size)
        fi->content.size = (size_t)(*offset) + length;

    *offset += (loff_t)length;

    inode_set_mtime_to_ts(inode, current_time(inode));

    size_t send_len = fi->content.size;

    if (send_len > 60 * 1024) {
        mutex_unlock(&fi->lock);
        kfree(tmp);
        return -E2BIG;
    }

    char parent_ino_str[VTFS_INO_STR_MAX];
    char name_enc[VTFS_NAME_ENC_MAX];

    ino_to_str(vtfs_to_server_ino(fi->parent_ino), parent_ino_str, sizeof(parent_ino_str));
    encode(fi->name, name_enc);

    char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
    if (data_enc)
        encode_n(fi->content.data ? fi->content.data : "", send_len, data_enc);

    mutex_unlock(&fi->lock);

    if (!atomic_read(&vtfs_unmounting) && data_enc) {
        char response[256] = {0};
        (void)vtfs_http_call(token, "write", response, sizeof(response),
                             3, "parent_ino", parent_ino_str, "name", name_enc, "data", data_enc);
    }

    kfree(data_enc);
    kfree(tmp);
    return (ssize_t)length;
}

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry,
                       umode_t mode, bool excl)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;
    if (atomic_read(&vtfs_unmounting)) return -EAGAIN;

    char *response = kmalloc(VTFS_RESP_BIG, GFP_KERNEL);
    char *name_enc = kmalloc(VTFS_NAME_ENC_MAX, GFP_KERNEL);
    char parent_ino_str[VTFS_INO_STR_MAX];

    if (!response || !name_enc) {
        kfree(response);
        kfree(name_enc);
        return -ENOMEM;
    }
    memset(response, 0, VTFS_RESP_BIG);

    ino_to_str(vtfs_to_server_ino(parent_ino), parent_ino_str, sizeof(parent_ino_str));
    encode(name, name_enc);

    int64_t rc = vtfs_http_call(token, "create", response, VTFS_RESP_BIG,
                                3, "parent_ino", parent_ino_str, "name", name_enc, "data", "");
    kfree(name_enc);

    if (rc == -1) {
        kfree(response);
        return -EEXIST;
    }
    if (rc != 0) {
        kfree(response);
        return -EIO;
    }

    ino_t server_ino = 0;
    if (!vtfs_parse_created_ino(response, &server_ino) || server_ino == 0) {
        kfree(response);
        return -EIO;
    }
    kfree(response);

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = false;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->mode = S_IFREG | 0777;
    strscpy(fi->name, name, sizeof(fi->name));
    fi->ino = server_ino;

    mutex_lock(&vtfs_files_lock);
    list_add(&fi->list, &vtfs_files);
    if ((int)fi->ino >= next_ino) next_ino = (int)fi->ino + 1;
    mutex_unlock(&vtfs_files_lock);

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, fi->mode, fi->ino, fi);
    if (!inode) {
        mutex_lock(&vtfs_files_lock);
        list_del(&fi->list);
        mutex_unlock(&vtfs_files_lock);
        kfree(fi);
        return -ENOMEM;
    }

    mutex_lock(&vtfs_files_lock);
    fi->inode = inode;
    mutex_unlock(&vtfs_files_lock);

    d_add(child_dentry, inode);

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

    if (!atomic_read(&vtfs_unmounting)) {
        char response[256] = {0};
        char parent_ino_str[VTFS_INO_STR_MAX];
        char name_enc[VTFS_NAME_ENC_MAX];

        ino_to_str(vtfs_to_server_ino(parent_ino), parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(token, "unlink", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;
    if (atomic_read(&vtfs_unmounting)) return -EAGAIN;

    char *response = kmalloc(VTFS_RESP_BIG, GFP_KERNEL);
    char *name_enc = kmalloc(VTFS_NAME_ENC_MAX, GFP_KERNEL);
    char parent_ino_str[VTFS_INO_STR_MAX];

    if (!response || !name_enc) {
        kfree(response);
        kfree(name_enc);
        return -ENOMEM;
    }
    memset(response, 0, VTFS_RESP_BIG);

    ino_to_str(vtfs_to_server_ino(parent_ino), parent_ino_str, sizeof(parent_ino_str));
    encode(name, name_enc);

    int64_t rc = vtfs_http_call(token, "mkdir", response, VTFS_RESP_BIG,
                                2, "parent_ino", parent_ino_str, "name", name_enc);
    kfree(name_enc);

    if (rc == -1) {
        kfree(response);
        return -EEXIST;
    }
    if (rc != 0) {
        kfree(response);
        return -EIO;
    }

    ino_t server_ino = 0;
    if (!vtfs_parse_created_ino(response, &server_ino) || server_ino == 0) {
        kfree(response);
        return -EIO;
    }
    kfree(response);

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = true;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->ino = server_ino;
    fi->mode = S_IFDIR | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, fi->mode, fi->ino, fi);
    if (!inode) {
        kfree(fi);
        return -ENOMEM;
    }

    inc_nlink(parent_inode);

    mutex_lock(&vtfs_files_lock);
    fi->inode = inode;
    list_add(&fi->list, &vtfs_files);
    if ((int)fi->ino >= next_ino) next_ino = (int)fi->ino + 1;
    mutex_unlock(&vtfs_files_lock);

    d_add(child_dentry, inode);

    return 0;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (!simple_empty(child_dentry)) return -ENOTEMPTY;

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

    if (!atomic_read(&vtfs_unmounting)) {
        char response[256] = {0};
        char parent_ino_str[VTFS_INO_STR_MAX];
        char name_enc[VTFS_NAME_ENC_MAX];

        ino_to_str(vtfs_to_server_ino(parent_ino), parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(token, "rmdir", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    drop_nlink(parent_inode);
    return simple_rmdir(parent_inode, child_dentry);
}

static void vtfs_put_super(struct super_block *sb)
{
    atomic_set(&vtfs_unmounting, 1);
}

static void vtfs_evict_inode(struct inode *inode)
{
    struct vtfs_file_info *fi = (struct vtfs_file_info *)inode->i_private;

    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);

    if (fi) {
        mutex_lock(&vtfs_files_lock);
        if (fi->inode == inode) fi->inode = NULL;
        mutex_unlock(&vtfs_files_lock);
    }
}

static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
    atomic_set(&vtfs_unmounting, 0);
    return mount_nodev(fs_type, flags, data, vtfs_fill_super);
}

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    sb->s_magic = VTFS_MAGIC;
    sb->s_op = &vtfs_sops;
    sb->s_time_gran = 1;
    sb->s_maxbytes = MAX_LFS_FILESIZE;

    struct inode *inode = vtfs_get_inode(sb, S_IFDIR | 0777, VTFS_ROOT_INO, NULL);
    if (!inode) return -ENOMEM;

    sb->s_root = d_make_root(inode);
    if (!sb->s_root) return -ENOMEM;

    (void)vtfs_sync_from_server_dir(VTFS_ROOT_INO);

    return 0;
}

static void vtfs_kill_sb(struct super_block *sb)
{
    atomic_set(&vtfs_unmounting, 1);
    kill_litter_super(sb);
}

static int __init vtfs_init(void)
{
    return register_filesystem(&vtfs_fs_type);
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);

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
}

module_init(vtfs_init);
module_exit(vtfs_exit);
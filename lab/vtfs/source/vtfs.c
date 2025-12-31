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
#include <linux/ctype.h>

#include "http.h"

#define MODULE_NAME "vtfs"
#define VTFS_ROOT_INO 100
#define VTFS_MAGIC 0x56544653 /* 'VTFS' */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("VTFS");

/* ========= logging ========= */
static int debug = 1; /* 0=off, 1=info, 2=debug */
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "VTFS debug level (0=off,1=info,2=debug)");

#define vtfs_info(fmt, ...)  do { if (debug >= 1) pr_info("vtfs: " fmt "\n", ##__VA_ARGS__); } while (0)
#define vtfs_dbg(fmt, ...)   do { if (debug >= 2) pr_info("vtfs: [dbg] " fmt "\n", ##__VA_ARGS__); } while (0)
#define vtfs_warn(fmt, ...)  pr_warn("vtfs: [warn] " fmt "\n", ##__VA_ARGS__)
#define vtfs_err(fmt, ...)   pr_err ("vtfs: [err] " fmt "\n", ##__VA_ARGS__)

/* ========= module param: token ========= */
static char *token = "my_token";
module_param(token, charp, 0644);
MODULE_PARM_DESC(token, "VTFS auth token");

/* ========= state ========= */
static atomic_t vtfs_unmounting = ATOMIC_INIT(0);

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
    struct inode *inode;          // cache inode to avoid duplicates
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

static LIST_HEAD(vtfs_files);
static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

/* ---- forward decls ---- */
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

/* ---- super ops ---- */
static void vtfs_put_super(struct super_block *sb);
static void vtfs_evict_inode(struct inode *inode);
static void vtfs_umount_begin(struct super_block *sb);

static const struct super_operations vtfs_sops = {
    .statfs       = simple_statfs,
    .drop_inode   = generic_delete_inode,
    .put_super    = vtfs_put_super,
    .evict_inode  = vtfs_evict_inode,
    .umount_begin = vtfs_umount_begin,
};

/* ---- helpers ---- */
static inline bool vtfs_should_talk(void)
{
    return atomic_read(&vtfs_unmounting) == 0;
}

static void ino_to_str(ino_t ino, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)ino);
}

static void vtfs_dump_files_locked(void)
{
    struct vtfs_file_info *fi;
    int cnt = 0;
    list_for_each_entry(fi, &vtfs_files, list) {
        if (fi->deleted) continue;
        cnt++;
    }
    vtfs_info("live nodes=%d next_ino=%d unmounting=%d", cnt, next_ino, atomic_read(&vtfs_unmounting));
}

static void vtfs_mark_all_deleted_locked(void)
{
    struct vtfs_file_info *fi;
    list_for_each_entry(fi, &vtfs_files, list) {
        fi->deleted = true;
        fi->inode = NULL;
        if (fi->content.data) {
            kfree(fi->content.data);
            fi->content.data = NULL;
        }
        fi->content.size = 0;
        fi->content.allocated = 0;
    }
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

/* ---- inode ---- */
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

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = S_ISDIR(mode) ? &vtfs_dir_ops : &vtfs_file_ops;

    inode->i_private = fi; /* crucial for debugging */
    return inode;
}

/* ---- open/release ---- */
static int vtfs_open(struct inode *inode, struct file *filp)
{
    struct vtfs_file_info *fi = (struct vtfs_file_info *)inode->i_private;
    filp->private_data = fi;
    vtfs_dbg("open ino=%lu mode=%o fi=%p", inode->i_ino, inode->i_mode, fi);
    return 0;
}

static int vtfs_release(struct inode *inode, struct file *filp)
{
    vtfs_dbg("release ino=%lu", inode->i_ino);
    filp->private_data = NULL;
    return 0;
}

/* ---- finders ---- */
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

/* ---- server sync (LIST) ----
 * Expected payload: [{"ino":6,"name":"abc","is_dir":false},...]
 * We do a minimal parser for this exact shape.
 */
static int vtfs_sync_root_from_server(void)
{
    char parent_ino_str[32];
    /* make this big enough for a decent JSON list */
    size_t buf_sz = 64 * 1024;
    char *resp = kzalloc(buf_sz, GFP_KERNEL);
    int added = 0;

    if (!resp) return -ENOMEM;

    ino_to_str(VTFS_ROOT_INO, parent_ino_str, sizeof(parent_ino_str));

    if (!vtfs_should_talk()) {
        kfree(resp);
        return 0;
    }

    (void)vtfs_http_call(token, "list", resp, buf_sz - 1,
                         1, "parent_ino", parent_ino_str);

    /* resp is NUL-terminated by http.c when possible */
    if (resp[0] == '\0') {
        kfree(resp);
        return 0;
    }

    mutex_lock(&vtfs_files_lock);

    /* mark old state deleted; then revive/insert from server */
    vtfs_mark_all_deleted_locked();

    char *p = resp;
    while (1) {
        char *q_ino = strstr(p, "\"ino\":");
        if (!q_ino) break;
        q_ino += strlen("\"ino\":");

        while (*q_ino == ' ' || *q_ino == '\t') q_ino++;
        if (!isdigit(*q_ino)) { p = q_ino; continue; }

        unsigned long long ino_val = 0;
        while (isdigit(*q_ino)) {
            ino_val = ino_val * 10ULL + (unsigned long long)(*q_ino - '0');
            q_ino++;
        }

        char *q_name = strstr(q_ino, "\"name\":\"");
        if (!q_name) { p = q_ino; continue; }
        q_name += strlen("\"name\":\"");

        char name[256];
        size_t ni = 0;
        while (*q_name && *q_name != '"' && ni + 1 < sizeof(name)) {
            name[ni++] = *q_name++;
        }
        name[ni] = '\0';

        char *q_isdir = strstr(q_name, "\"is_dir\":");
        if (!q_isdir) { p = q_name; continue; }
        q_isdir += strlen("\"is_dir\":");

        while (*q_isdir == ' ' || *q_isdir == '\t') q_isdir++;

        bool is_dir = false;
        if (!strncmp(q_isdir, "true", 4)) is_dir = true;
        else if (!strncmp(q_isdir, "false", 5)) is_dir = false;
        else { p = q_isdir; continue; }

        /* upsert into vtfs_files */
        {
            struct vtfs_file_info *fi = NULL;

            list_for_each_entry(fi, &vtfs_files, list) {
                if (fi->parent_ino == VTFS_ROOT_INO && strcmp(fi->name, name) == 0) {
                    break;
                }
                fi = NULL;
            }

            if (!fi) {
                fi = kzalloc(sizeof(*fi), GFP_KERNEL);
                if (!fi) break;

                mutex_init(&fi->lock);
                INIT_LIST_HEAD(&fi->list);
                strscpy(fi->name, name, sizeof(fi->name));
                fi->parent_ino = VTFS_ROOT_INO;
                list_add_tail(&fi->list, &vtfs_files);
            }

            fi->deleted = false;
            fi->inode = NULL;
            fi->ino = (ino_t)ino_val;
            fi->is_dir = is_dir;
            fi->mode = (is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0777));

            if ((int)ino_val + 1 > next_ino)
                next_ino = (int)ino_val + 1;

            added++;
        }

        p = q_isdir;
    }

    mutex_unlock(&vtfs_files_lock);
    kfree(resp);

    vtfs_info("sync from server: entries=%d next_ino=%d", added, next_ino);
    return 0;
}

/* ---- lookup / readdir ---- */
static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    struct vtfs_file_info *fi = find_file_in_dir(child_dentry->d_name.name, parent_inode->i_ino);

    if (!fi) {
        d_add(child_dentry, NULL);
        return NULL;
    }

    /* reuse cached inode if possible */
    if (fi->inode) {
        struct inode *inode = igrab(fi->inode);
        if (inode) {
            d_add(child_dentry, inode);
            vtfs_dbg("lookup reuse name=%s parent=%lu ino=%lu",
                     child_dentry->d_name.name, parent_inode->i_ino, inode->i_ino);
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
        vtfs_dbg("lookup new name=%s parent=%lu ino=%lu",
                 child_dentry->d_name.name, parent_inode->i_ino, inode->i_ino);
    }

    return NULL;
}

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    ino_t current_ino = inode->i_ino;

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
        char name[256];
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

/* ---- read/write ---- */
static ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = filp->private_data ? filp->private_data : find_file_info(inode->i_ino);
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

    /* send up to 1024 bytes (GET query size guard) */
    size_t send_len = fi->content.size;
    if (send_len > 1024) send_len = 1024;

    char parent_ino_str[32];
    char name_enc[3 * 256 + 1];
    ino_to_str(fi->parent_ino, parent_ino_str, sizeof(parent_ino_str));
    encode(fi->name, name_enc);

    char *data_enc = kmalloc(3 * send_len + 1, GFP_KERNEL);
    if (data_enc) {
        encode_n(fi->content.data ? fi->content.data : "", send_len, data_enc);
    }

    mutex_unlock(&fi->lock);

    if (vtfs_should_talk() && data_enc) {
        char response[256] = {0};
        (void)vtfs_http_call(token, "write", response, sizeof(response),
                             3, "parent_ino", parent_ino_str, "name", name_enc, "data", data_enc);
    } else {
        vtfs_dbg("skip http write (unmounting=%d) ino=%lu",
                 atomic_read(&vtfs_unmounting), inode->i_ino);
    }

    kfree(data_enc);
    kfree(tmp);
    return (ssize_t)length;
}

/* ---- create/unlink/mkdir/rmdir ---- */
static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool excl)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    /* 1) ask server first -> stable ino across remounts */
    ino_t server_ino = 0;
    if (vtfs_should_talk()) {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        int64_t rc = vtfs_http_call(token, "create", response, sizeof(response),
                                    3, "parent_ino", parent_ino_str, "name", name_enc, "data", "");
        if (rc > 0) server_ino = (ino_t)rc;
    }

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = false;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->mode = S_IFREG | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = server_ino ? server_ino : (ino_t)next_ino++;
    if ((int)fi->ino + 1 > next_ino) next_ino = (int)fi->ino + 1;
    list_add_tail(&fi->list, &vtfs_files);
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

    vtfs_dbg("create name=%s parent=%lu ino=%lu", name, parent_ino, inode->i_ino);
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
                fi->inode = NULL;
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    if (vtfs_should_talk()) {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(token, "unlink", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    vtfs_dbg("unlink name=%s parent=%lu", name, parent_ino);
    return simple_unlink(parent_inode, child_dentry);
}

static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode)
{
    const char *name = child_dentry->d_name.name;
    ino_t parent_ino = parent_inode->i_ino;

    if (find_file_in_dir(name, parent_ino)) return -EEXIST;

    ino_t server_ino = 0;
    if (vtfs_should_talk()) {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        int64_t rc = vtfs_http_call(token, "mkdir", response, sizeof(response),
                                    2, "parent_ino", parent_ino_str, "name", name_enc);
        if (rc > 0) server_ino = (ino_t)rc;
    }

    struct vtfs_file_info *fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) return -ENOMEM;

    mutex_init(&fi->lock);
    fi->is_dir = true;
    fi->deleted = false;
    fi->parent_ino = parent_ino;
    fi->mode = S_IFDIR | 0777;
    strscpy(fi->name, name, sizeof(fi->name));

    mutex_lock(&vtfs_files_lock);
    fi->ino = server_ino ? server_ino : (ino_t)next_ino++;
    if ((int)fi->ino + 1 > next_ino) next_ino = (int)fi->ino + 1;
    list_add_tail(&fi->list, &vtfs_files);
    mutex_unlock(&vtfs_files_lock);

    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, fi->mode, fi->ino, fi);
    if (!inode) {
        mutex_lock(&vtfs_files_lock);
        list_del(&fi->list);
        mutex_unlock(&vtfs_files_lock);
        kfree(fi);
        return -ENOMEM;
    }

    inc_nlink(parent_inode);

    mutex_lock(&vtfs_files_lock);
    fi->inode = inode;
    mutex_unlock(&vtfs_files_lock);

    d_add(child_dentry, inode);

    vtfs_dbg("mkdir name=%s parent=%lu ino=%lu", name, parent_ino, inode->i_ino);
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
                fi->inode = NULL;
                break;
            }
        }
    }
    mutex_unlock(&vtfs_files_lock);

    if (vtfs_should_talk()) {
        char response[256] = {0};
        char parent_ino_str[32];
        char name_enc[3 * 256 + 1];

        ino_to_str(parent_ino, parent_ino_str, sizeof(parent_ino_str));
        encode(name, name_enc);

        (void)vtfs_http_call(token, "rmdir", response, sizeof(response),
                             2, "parent_ino", parent_ino_str, "name", name_enc);
    }

    drop_nlink(parent_inode);
    vtfs_dbg("rmdir name=%s parent=%lu", name, parent_ino);
    return simple_rmdir(parent_inode, child_dentry);
}

/* ---- super ---- */
static void vtfs_umount_begin(struct super_block *sb)
{
    /* called early during unmount -> prevent any new network activity */
    atomic_set(&vtfs_unmounting, 1);
    vtfs_info("umount_begin sb=%p", sb);
}

static void vtfs_put_super(struct super_block *sb)
{
    /* DO NOT take locks here -> can deadlock umount */
    atomic_set(&vtfs_unmounting, 1);
    vtfs_info("put_super sb=%p (unmounting=1)", sb);
}

static void vtfs_evict_inode(struct inode *inode)
{
    struct vtfs_file_info *fi = (struct vtfs_file_info *)inode->i_private;

    vtfs_dbg("evict_inode ino=%lu fi=%p", inode->i_ino, fi);

    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);

    if (fi) {
        mutex_lock(&vtfs_files_lock);
        if (fi->inode == inode) fi->inode = NULL;
        mutex_unlock(&vtfs_files_lock);
    }
}

/* ---- mount/super ---- */
static struct dentry *vtfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
    vtfs_info("mount flags=0x%x", flags);
    atomic_set(&vtfs_unmounting, 0);
    return mount_nodev(fs_type, flags, data, vtfs_fill_super);
}

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
    vtfs_info("fill_super sb=%p", sb);

    sb->s_magic = VTFS_MAGIC;
    sb->s_op = &vtfs_sops;
    sb->s_time_gran = 1;
    sb->s_maxbytes = MAX_LFS_FILESIZE;

    struct inode *inode = vtfs_get_inode(sb, S_IFDIR | 0777, VTFS_ROOT_INO, NULL);
    if (!inode) return -ENOMEM;

    sb->s_root = d_make_root(inode);
    if (!sb->s_root) return -ENOMEM;

    /* sync filenames from server so remount sees server state */
    (void)vtfs_sync_root_from_server();

    mutex_lock(&vtfs_files_lock);
    vtfs_dump_files_locked();
    mutex_unlock(&vtfs_files_lock);

    return 0;
}

static void vtfs_kill_sb(struct super_block *sb)
{
    vtfs_info("kill_sb sb=%p", sb);
    atomic_set(&vtfs_unmounting, 1);
    kill_litter_super(sb);
    vtfs_info("kill_sb done");
}

/* ---- module init/exit ---- */
static int __init vtfs_init(void)
{
    vtfs_info("init token=%s debug=%d", token, debug);
    return register_filesystem(&vtfs_fs_type);
}

static void __exit vtfs_exit(void)
{
    vtfs_info("exit: unregister fs");
    unregister_filesystem(&vtfs_fs_type);

    vtfs_info("exit: free nodes");
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

    vtfs_info("exit done");
}

module_init(vtfs_init);
module_exit(vtfs_exit);

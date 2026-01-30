#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/fs.h>      // struct inode 和 S_IMMUTABLE 都在这里
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/string.h>
// #include <linux/inode.h>  <-- 这一行删除了，它导致了报错

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ArchStudent");
MODULE_DESCRIPTION("Total Defense: Anti-Write, Anti-Truncate, Anti-Unlink");

#define TARGET_FILENAME "hosts" 
#define ALLOWED_COMM "dns_guard"

// === 钩子 1: 拦截打开操作 (防修改、防截断) ===
static struct kprobe kp_open = {
    .symbol_name = "do_dentry_open",
};

static int handler_open(struct kprobe *p, struct pt_regs *regs)
{
    struct file *f = (struct file *)regs->di;
    struct dentry *dentry;
    struct inode *inode;

    if (!f || !f->f_path.dentry) return 0;

    dentry = f->f_path.dentry;
    // d_inode 是 dentry 结构体的一部分，定义在 fs.h/dcache.h 中
    inode = dentry->d_inode;

    // 检查文件名
    if (strcmp(dentry->d_name.name, TARGET_FILENAME) == 0) {
        
        // --- 检查是否是白名单进程 ---
        if (strcmp(current->comm, ALLOWED_COMM) == 0) {
            // ✅ 如果是 dns_guard：
            // 移除 "不可变" 标志，确保脚本可以修改
            if (inode) {
                inode->i_flags &= ~S_IMMUTABLE;
            }
            return 0; // 放行
        }

        // --- 拦截逻辑 (Root/普通用户) ---
        
        // 1. 如果请求了写权限 (FMODE_WRITE) 或 截断 (O_TRUNC)
        if ((f->f_mode & FMODE_WRITE) || (f->f_flags & O_TRUNC)) {
            // 降级打击：移除写权限和截断标志
            f->f_flags &= ~O_TRUNC;
            f->f_flags &= ~O_APPEND;
            f->f_mode &= ~FMODE_WRITE;
            f->f_mode |= FMODE_READ;
            
            // 🔥 加强防御：给 inode 加上不可变标志
            if (inode) {
                inode->i_flags |= S_IMMUTABLE;
            }
        }
    }
    return 0;
}

// === 钩子 2: 拦截删除操作 (防 rm) ===
static struct kprobe kp_unlink = {
    .symbol_name = "vfs_unlink",
};

static int handler_unlink(struct kprobe *p, struct pt_regs *regs)
{
    // vfs_unlink 参数寄存器映射 (x86_64):
    // DI: 1st arg (idmap/ns)
    // SI: 2nd arg (dir inode)
    // DX: 3rd arg (target dentry) -> 我们需要这个
    
    struct dentry *dentry = (struct dentry *)regs->dx;
    struct inode *inode;

    if (!dentry || !dentry->d_inode) return 0;
    
    inode = dentry->d_inode;

    // 检查是否是 hosts 文件
    if (strcmp(dentry->d_name.name, TARGET_FILENAME) == 0) {
        
        // 检查白名单
        if (strcmp(current->comm, ALLOWED_COMM) != 0) {
            
            // 🛑 防删逻辑 🛑
            // 加上 S_IMMUTABLE 标志，内核会拒绝删除操作
            inode->i_flags |= S_IMMUTABLE;
        }
    }
    return 0;
}

static int __init dns_lock_init(void)
{
    int ret;

    // 注册 Open 钩子
    kp_open.pre_handler = handler_open;
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        pr_err("DNS_Guard: Failed to register open hook\n");
        return ret;
    }

    // 注册 Unlink 钩子
    kp_unlink.pre_handler = handler_unlink;
    ret = register_kprobe(&kp_unlink);
    if (ret < 0) {
        unregister_kprobe(&kp_open);
        pr_err("DNS_Guard: Failed to register unlink hook\n");
        return ret;
    }

    pr_info("DNS_Guard: Total Defense Loaded (No-Write, No-Delete).\n");
    
    // 🔥 建议测试成功后再取消注释
    try_module_get(THIS_MODULE); 

    return 0;
}

static void __exit dns_lock_exit(void)
{
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_unlink);
    pr_info("DNS_Guard: Unloaded.\n");
}

module_init(dns_lock_init);
module_exit(dns_lock_exit);

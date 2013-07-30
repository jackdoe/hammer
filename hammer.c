#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#define MODULE_NAME  "hammer"
#define CONTROL_NAME "__control"

// #define DEBUG
#ifdef DEBUG
#define D(fmt,arg...) printk(fmt " [%s():%s:%d]\n",##arg,__func__,__FILE__,__LINE__)
#else
#define D(fmt,arg...)
#endif
#define CONNECTED               1
#define DISCONNECTED            2

static struct proc_dir_entry *root;
static struct proc_dir_entry *control;
static spinlock_t giant;

struct connection {
    struct list_head list;
    struct socket *socket;
    void   *orig_sk_user_data;
    void   (*orig_sk_data_ready)(struct sock *sk, int bytes);
    int    state;
    char   procfs_name[128];
    struct proc_dir_entry *procfs_entry;
    char   *output;
    ssize_t output_len;
};

LIST_HEAD(connections);

static int inet_addr(char* ip, unsigned int *dest, unsigned short *port);
static struct connection *connect_to(char *host);
static void disconnect(struct connection *c);
static int hammer_tcp_data_recv(read_descriptor_t *desc, struct sk_buff *skb,unsigned int offset, size_t len);

struct proc_dir_entry *procify(char *name, void *data,
        int (*reader)(char *, char **, off_t, int, int *, void *),
        int (*writer)(struct file *, const char *, unsigned long, void *));


int control_read(char *buffer, char **buffer_location, off_t offset, int count, int *eof, void *data);
int control_write(struct file *file, const char *buffer, unsigned long count, void *data);

int tail(char *buffer, char **buffer_location, off_t offset, int count, int *eof, void *data);
int hammer(struct file *file, const char *buffer, unsigned long count, void *data);

// POC: just show the last 'count' bytes from the buffer
int tail(char *buffer, char **buffer_location, off_t offset, int count, int *eof, void *data) {
    struct connection *c = (struct connection *) data;
    if (!c || !c->output || c->output_len == 0)
        return -ENOENT;

    if (count > c->output_len) {
        count = c->output_len;
        offset = 0;
    } else {
        offset = c->output_len - count;
    }
    memcpy(buffer,(c->output + offset),count);
    return count;
}

// uses the fact that *buffer is in the user address space, that is why 
// copy_from_user and kernel_sendmsg are not used
int hammer(struct file *file, const char *buffer, unsigned long count, void *data) {
    struct connection *c = (struct connection *) data;
    struct msghdr msg;
    struct iovec iov;

    if (!c)
        return -ENOENT;

    iov.iov_base = (void *)buffer;
    iov.iov_len = (__kernel_size_t) count;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    return sock_sendmsg(c->socket, &msg, count);
}

int control_read(char *buffer, char **buffer_location, off_t offset, int count, int *eof, void *data) {
    return 0;
}

int control_write(struct file *file, const char *buffer, unsigned long count, void *data) {
    #define HAMMER__MAX_INPUT 512
    char parse_me[HAMMER__MAX_INPUT + 1];
    char *p;
    memset(parse_me,'\0',sizeof(parse_me));
    if (count > HAMMER__MAX_INPUT)
        count = HAMMER__MAX_INPUT;

    if (copy_from_user(parse_me,buffer,count) < 0)
        return -EFAULT;
     
    p = strchr(parse_me,'\n');
    if (p)
        *p = '\0';
    connect_to(parse_me);
    #undef HAMMER__MAX_INPUT
    return count;
}

static int inet_addr(char* ip_port, unsigned int *dest,unsigned short *port) {
    int a, b, c, d, e;
    char addr[4];
    if (sscanf(ip_port, "%d.%d.%d.%d:%d", &a, &b, &c, &d,&e) == 5) {
        addr[0] = a;
        addr[1] = b;
        addr[2] = c;
        addr[3] = d;
        *dest = *(unsigned int *)addr;
        *port = htons(e);
        return 0;
    }
    return -1;
}

void ___sk_data_ready (struct sock *sk, int bytes) {
    void (*ready)(struct sock *, int);
    struct connection *c = (struct connection *) sk->sk_user_data;
    read_descriptor_t desc;

    read_lock_bh(&sk->sk_callback_lock);

    ready = c->orig_sk_data_ready;
    desc.arg.data = c;
    desc.error = 0;
    desc.count = 1;
    tcp_read_sock(sk, &desc, hammer_tcp_data_recv);

    read_unlock_bh(&sk->sk_callback_lock);

    (*ready)(sk,bytes);
}

static int hammer_tcp_data_recv(read_descriptor_t *desc, struct sk_buff *skb,unsigned int offset, size_t len) {
    struct connection *c = (struct connection *) desc->arg.data;

    c->output = krealloc(c->output,c->output_len + len,GFP_ATOMIC);
    if (c->output) {
        skb_copy_bits(skb, offset,(c->output + c->output_len),len);
        c->output_len += len;
        c->procfs_entry->size = c->output_len;
    }
    return len;
}


void register_callbacks(struct connection *c) {
    struct sock *sk = c->socket->sk;

    write_lock_bh(&sk->sk_callback_lock);

    c->orig_sk_data_ready = sk->sk_data_ready;
    c->orig_sk_user_data  = sk->sk_user_data;
    sk->sk_data_ready  = ___sk_data_ready;
    sk->sk_user_data   = c;

    write_unlock_bh(&sk->sk_callback_lock);
};

void unregister_callbacks(struct connection *c) {
    struct sock *sk = c->socket->sk;

    write_lock_bh(&sk->sk_callback_lock);

    sk->sk_data_ready = c->orig_sk_data_ready;
    sk->sk_user_data  = c->orig_sk_user_data;

    write_unlock_bh(&sk->sk_callback_lock);
}

static struct connection * connect_to(char *host) {
    struct sockaddr_in si;
    int rc = 0;
    struct connection *c = kmalloc(sizeof(*c), GFP_KERNEL);
    if (!c)
        goto bad;
    c->socket = NULL;
    c->output_len = 0;
    c->output = NULL;
    snprintf(c->procfs_name,128,"c_%s_%p",host,c);

    c->procfs_entry = procify(c->procfs_name,(void *) c, tail, hammer);
    if (!c->procfs_entry)
        goto bad;

    if ((rc = sock_create(AF_INET,SOCK_STREAM,IPPROTO_TCP,&c->socket)) < 0)
        goto bad;
#ifdef SK_CAN_REUSE
    c->socket->sk->sk_reuse = SK_CAN_REUSE;
#endif
    memset(&si, 0, sizeof(si));
    si.sin_family = AF_INET;

    if (inet_addr(host,&si.sin_addr.s_addr,&si.sin_port) < 0)
        goto bad;
    
    if ((rc = kernel_connect(c->socket, (struct sockaddr *)&si, sizeof(si),0)) < 0)
        goto bad;

    spin_lock(&giant);

    list_add(&c->list,&connections);

    spin_unlock(&giant);

    c->state = CONNECTED;
    register_callbacks(c);
    D("connected to %s",host);
    return c;

bad:
    if (c) {
        if (c->socket)
            sock_release(c->socket);

        if (c->procfs_entry)
            remove_proc_entry(c->procfs_name, root);
        kfree(c);
    }
    D("error creating socket for %s rc: %d",host,rc);
    return NULL;
}

static void disconnect(struct connection *c) {
    if (c->state & DISCONNECTED)
        return;

    c->state = DISCONNECTED;
    unregister_callbacks(c);
   
#ifdef kernel_sock_shutdown
    kernel_sock_shutdown(c->socket, SHUT_RDWR);
#else
    c->socket->ops->shutdown(c->socket, SHUT_RDWR);
#endif
}

struct proc_dir_entry *procify(char *name, void *data,
        int (*reader)(char *, char **, off_t, int, int *, void *),
        int (*writer)(struct file *, const char *, unsigned long, void *)) {
    struct proc_dir_entry *p = create_proc_entry(name,0644,root);

    if (p != NULL) {
        p->read_proc = reader;
        p->write_proc = writer; 
        p->data = data;
        p->mode = S_IFREG | S_IRUGO;
        p->uid = 0;
        p->gid = 0;
        p->size = 0;
    }
    return p;
}

int init_module() {
    spin_lock_init(&giant);

    root = proc_mkdir(MODULE_NAME, NULL);
    if (root == NULL) 
        return -ENOMEM;

    control = procify(CONTROL_NAME,NULL,control_read,control_write);
    return 0;
}

void cleanup_module() {
    struct list_head *pos,*q;
    struct connection *c;
    D("cleaning up connections");

    spin_lock(&giant);

    list_for_each_safe(pos, q, &connections) {
        c = list_entry(pos, struct connection, list);
        list_del(&c->list);
        disconnect(c);
        if (c->output)
            kfree(c->output);
        if (c->procfs_entry)
            remove_proc_entry(c->procfs_name, root);
        kfree(c);
    }

    spin_unlock(&giant);

    if (control)
        remove_proc_entry(CONTROL_NAME,root);
    remove_proc_entry(MODULE_NAME, NULL);
}


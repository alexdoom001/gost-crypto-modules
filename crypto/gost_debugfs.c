/**
 * gostcrypt and gosthash debugfs interface
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include "gost.h"

#ifdef CONFIG_CRYPTO_GOST_DEBUGFS

#define GOSTHASH_DEBUGFS_FILES  4 /* Number of files in gosthash debugfs directory */
#define GOSTCRYPT_DEBUGFS_FILES 2 /* Number of files in gostcrypt debugfs directory */
#define GOST_DEBUGFS_ROOTNAME   "gost"
#define GOST_DEBUGFS_HASHNAME   "gosthash"
#define GOST_DEBUGFS_CRYPTNAME  "gostcrypt"
#define GOST_DEBUGFS_FILE_LIMIT (2048 * 1024) /* 2M */

/**
 * The structure describes single gosthash/gostcrypt file
 * in gost debugfs directory hierarchy.
 */
struct gost_debugfs_file {
	char			*name; /* File name */
	struct file_operations	 fops; /* File operations */
	struct dentry		*debugfs_dentry; /* A pointer to debugfs entry */
	mode_t                   mode; /* Access mode */
	int			 initialized; /* 1 if initialized, 0 otherwise */
	int (*init_fn)(void);    /* Initialization function (can be NULL) */
	void (*clear_fn)(void);  /* Clenup functoin (can be NULL) */
};

/* ghash file size: digest size * 2 + newline + '\0' */
#define GHASH_FILE_DEFAULT_SZ (GOST_HASH_DIGEST_SIZE * 2 + 2)

/* Max. length that can be written to ghash file by one write() syscall */
#define GHASH_BUFFER_SIZE PAGE_SIZE

/**
 * GOST debugfs hierarchy:
 * /gotst
 *       /gosthash
 *                blkid
 *                sblock
 *                ghash
 *                ghsah_ctrl
 *       /gostcrypt
 *                blkid
 *                sblock
 */
static struct dentry *gost_root = NULL;       /* Root of gost debugfs hierarchy */
static struct dentry *gosthash_root = NULL;   /* Root of gosthash-related files */
static struct dentry *gostcrypt_root = NULL;  /* Root of gostcrypt-related files */
static char *subst_blocks_desc[] = {
	"GostR3411_94_TestParamSet",
	"GostR3411_94_CryptoProParamSet",
	"Gost28147_TestParamSet",
	"Gost28147_CryptoProParamSetA",
	"Gost28147_CryptoProParamSetB",
	"Gost28147_CryptoProParamSetC",
	"Gost28147_CryptoProParamSetD",
	"GostCrypt_CustomBlock",
	"GostHash_CustomBlock",
};

/**
 * The structure describes ghash file.
 * @mutex - All ghash file operations must acquire this lock
 * @hdesc - Digest description
 * @buf   - Preallocated buffer to receive data from user-space
 * @has_data - A boolean variable identifying that ghash file has
 *             data received from user via write
 * @finished - A boolean variable identifying that ghash file
 *             has readable digest available via read.
 */
static struct {
	struct mutex		 mutex;
	struct hash_desc	 hdesc;
	u8			 digest[GHASH_FILE_DEFAULT_SZ];
	void			*buf;
	int			 has_data;
	int			 finished;
} ghash_data;

#define GHASH_LOCK()   mutex_lock(&ghash_data.mutex)
#define GHASH_UNLOCK() mutex_unlock(&ghash_data.mutex)

static enum gost_subst_block_type gostcrypt_subst_id, gosthash_subst_id;

static void clear_gost_debugfs_hierarchy(struct gost_debugfs_file *files,
					 int num_files)
{
	int i;
	struct gost_debugfs_file *gdf;

	for (i = 0; i < num_files; i++) {
		gdf = &files[i];
		if (gdf->initialized && gdf->clear_fn)
			gdf->clear_fn();

		gdf->initialized = 0;
	}
}

static int make_gost_debugfs_hierarchy(struct gost_debugfs_file *files,
				       int num_files, struct dentry *parent)
{
	int i, ret = 0;
	struct gost_debugfs_file *gdf;
	struct dentry *den;

	for (i = 0; i < num_files; i++) {
		gdf = &files[i];
		den = debugfs_create_file(gdf->name, gdf->mode, parent,
					  NULL, &gdf->fops);
		if (IS_ERR(den)) {
			ret = PTR_ERR(den);
			printk(KERN_ERR "Failed to create debugfs file "
			       "%s/%s/%s [ERR: %d]", GOST_DEBUGFS_ROOTNAME,
			       parent->d_name.name, gdf->name, ret);
			goto error;
		}
		if (gdf->init_fn) {
			ret = gdf->init_fn();
			if (ret)
				goto error;
		}

		gdf->initialized = 1;
	}

	return ret;

error:
	clear_gost_debugfs_hierarchy(files, i + 1);
	return ret;
}

/*******************************************************************************
 * blkid file:
 * blkid file contains an information about substitution block identifier
 * that is currently used by gosthash or gostcrypt(depending on blkid location:
 * gosthash/blkid -> gosthash
 * gostcrypt/blkid -> gostcrypt)
 * Read from this file gives a string in the following format:
 * <number>: <String>
 * where <number> is an identifier of substitution block and
 * <String> is its human-readable name.
 * For example:
 * 1: GostR3411_94_CryptoProParamSet
 */

static int blkid_show(struct seq_file *sf, void *v)
{
	enum gost_subst_block_type block_id;

	block_id = *(enum gost_subst_block_type *)(sf->private);
	seq_printf(sf, "%d: %s\n", block_id, subst_blocks_desc[block_id]);
	return 0;
}

static int blkid_file_open_gosthash(struct inode *inode, struct file *filp)
{
	return single_open(filp, blkid_show, &gosthash_subst_id);
}

static int blkid_file_open_gostcrypt(struct inode *inode, struct file *filp)
{
	return single_open(filp, blkid_show, &gostcrypt_subst_id);
}

/*******************************************************************************
 * sblock file:
 * sblock file contains substitution block itself that is currently used
 * by gosthash or gostcrypt(depending on sblock location):
 * gosthash/sblock -> gosthash substitution block
 * gostcrypt/sblock -> gostcrypt substitution block.
 * sblock file supports read operations which gives 8 16bytes lines of
 * of substitution block represented as 32byte hex strings. From k8 block line
 * to k1 block line(top -> down).
 */
static void *sblock_seq_start(struct seq_file *sf, loff_t *pos)
{
	u8 *ret;
	gost_subst_block_t *sblock = (gost_subst_block_t *)sf->private;

	switch (*pos) {
	case 0:
		ret = sblock->k8;
		break;
	case 1:
		ret = sblock->k7;
		break;
	case 2:
		ret = sblock->k6;
		break;
	case 3:
		ret = sblock->k5;
		break;
	case 4:
		ret = sblock->k4;
		break;
	case 5:
		ret = sblock->k3;
		break;
	case 6:
		ret = sblock->k2;
		break;
	case 7:
		ret = sblock->k1;
		break;
	default:
		ret = NULL;
		*pos = 0;
	}

	return ret;
}

static void *sblock_seq_next(struct seq_file *sf, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void sblock_seq_stop(struct seq_file *sf, void *v)
{
}

static int sblock_seq_show(struct seq_file *sf, void *v)
{
	u8 *line = (u8 *)v;
	int i;

	seq_printf(sf, "k%d: ", 8 - (int)sf->index);
	for (i = 0; i < 16; i++)
		seq_printf(sf, "%02x", line[i]);

	seq_putc(sf, '\n');
	return 0;
}

static struct seq_operations sblock_seq_ops = {
	.start = sblock_seq_start,
	.next = sblock_seq_next,
	.stop = sblock_seq_stop,
	.show = sblock_seq_show,
};

static int sblock_file_open_gosthash(struct inode *inode, struct file *filp)
{
	struct seq_file *sf;
	gost_subst_block_t *sblock = gost_get_subst_block(gosthash_subst_id);
	int ret;

	ret = seq_open(filp, &sblock_seq_ops);
	if (ret) {
		printk(KERN_ERR "seq_open failed on sblock(gosthash) file. "
		       "[ERR: %d]\n", ret);
		return ret;
	}

	sf = filp->private_data;
	sf->private = sblock;
	return 0;
}

static int sblock_file_open_gostcrypt(struct inode *inode, struct file *filp)
{
	struct seq_file *sf;
	gost_subst_block_t *sblock = gost_get_subst_block(gostcrypt_subst_id);
	int ret;

	ret = seq_open(filp, &sblock_seq_ops);
	if (ret) {
		printk(KERN_ERR "seq_open failed on sblock(gostcrypt) file. "
		       "[ERR: %d]\n", ret);
		return ret;
	}

	sf = filp->private_data;
	sf->private = sblock;
	return 0;
}

/*******************************************************************************
 * ghash file:
 * ghash file is gosthsah-specific file that receives user data and gives
 * gosthash as a hex-string on output. Position in a hierarchy:
 * gosthash/ghash
 * During write ghash receives data from user and updates digest(using
 * gost hash function). User may update digest with custom data as
 * many times as he wants. After "finish" command is written to ghash_ctrl
 * file, ghash file becomes readable. During the read operation it outputs
 * 32byte gost hash as a 64byte hex-string.
 */
static int ghash_file_init(void)
{
	memset(&ghash_data, 0, sizeof(ghash_data));
	mutex_init(&ghash_data.mutex);
	ghash_data.buf = kmalloc(GHASH_BUFFER_SIZE, GFP_KERNEL);
	if (!ghash_data.buf) {
		printk(KERN_ERR "Failed to allocated %zd bytes!\n",
			GHASH_BUFFER_SIZE);
		crypto_free_hash(ghash_data.hdesc.tfm);
		return -ENOMEM;
	}

	ghash_data.hdesc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	return 0;
}

static void ghash_file_clear(void)
{
	kfree(ghash_data.buf);
}

static int ghash_file_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int ghash_file_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t ghash_file_read(struct file *filp, char __user *ubuf,
			       size_t count, loff_t *f_pos)
{
	ssize_t ret = -ENODATA;
	char *p;
	size_t rest_len, copy_len;

	if (*f_pos > GHASH_FILE_DEFAULT_SZ)
		return 0;

	rest_len = GHASH_FILE_DEFAULT_SZ - *f_pos;
	copy_len = (count < rest_len) ? count : rest_len;

	GHASH_LOCK();
	if (!ghash_data.finished)
		goto out;

	p = ghash_data.digest + *f_pos;
	if (copy_to_user(ubuf, p, copy_len)) {
		ret = -EFAULT;
		printk(KERN_ERR "copy_to_user of %zd bytes from %p failed: "
		       "[ERR: EFAULT]\n", copy_len, p);
		goto out;
	}

	*f_pos += copy_len;
	ret = copy_len;
out:
	GHASH_UNLOCK();
	return ret;
}

static ssize_t ghash_file_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;
	struct scatterlist sg;

	if (count > GHASH_BUFFER_SIZE) {
		printk(KERN_ERR "ghash_file_write: MAX length(%ld) of writable "
		       "data exceeded(%ld)\n", GHASH_BUFFER_SIZE, count);
		ret = -EINVAL;
		goto out;
	}

	GHASH_LOCK();
	if (!ghash_data.has_data) {
		struct crypto_hash *tfm;

		tfm = crypto_alloc_hash("gosthash", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(tfm)) {
			printk(KERN_ERR "Failed to initialize gosthash context! [ERR: %ld]",
			       PTR_ERR(tfm));
			ret = PTR_ERR(tfm);
			goto out_unlock;
		}

		ghash_data.hdesc.tfm = tfm;
		ret = crypto_hash_init(&ghash_data.hdesc);
		if (ret) {
			printk(KERN_ERR "crypto_hash_init faield. [ERR: %ld]\n", ret);
			goto out_unlock;
		}
	}
	if (copy_from_user(ghash_data.buf, ubuf, count)) {
		printk(KERN_ERR "copy_from_user of %zd bytes from %p failed\n",
		       count, ubuf);
		ret = -EFAULT;
		goto out_unlock;
	}

	sg_init_one(&sg, ghash_data.buf, count);
	ret = crypto_hash_update(&ghash_data.hdesc, &sg, count);
	if (ret) {
		printk(KERN_ERR "crypto_hash_update() failed: [ERR: %ld]\n", ret);
		goto out_unlock;
	}

	ghash_data.has_data = 1;
	ret = count;

out_unlock:
	GHASH_UNLOCK();
out:
	return ret;
}

/*******************************************************************************
 * ghash_ctrl file:
 * ghash_ctrl is a gosthash-specific file that is used to control ghash file
 * behaviour. Position in a hierarchy:
 * gosthash/ghash_ctrl
 * ghash_ctrl receives two command strings: reset and finish.
 * reset command flushes all previously written into ghash data.
 * finish command makes digest from hashed earlier data. Digest can be
 * accessed via ghash file using read operation.
 */
static int ghash_ctrl_file_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t ghash_ctrl_file_write(struct file *filp, const char __user *ubuf,
				     size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	char ucmd[32];

	memset(ucmd, 0, sizeof(ucmd));
	if (count > sizeof(ucmd)) {
		printk(KERN_ERR "ghash_ctrl_file_write: count(%zd) exceeds "
		       "max size(%zd)!\n", count, sizeof(ucmd));
		return -EINVAL;
	}
	if (copy_from_user(ucmd, ubuf, count)) {
		printk(KERN_ERR "copy_from_user failed\n");
		return -EFAULT;
	}

	ucmd[31] = '\0';
	GHASH_LOCK();
	if (!strcmp(ucmd, "reset")) {
		ghash_data.has_data = 0;
		ghash_data.finished = 0;
	}
	else if (!strcmp(ucmd, "finish")) {
		if (ghash_data.has_data) {
			u8 ghash[GOST_HASH_DIGEST_SIZE];
			char *p;
			int i;

			ret = crypto_hash_final(&ghash_data.hdesc, ghash);
			crypto_free_hash(ghash_data.hdesc.tfm);
			ghash_data.hdesc.tfm = NULL;
			if (!ret) {
				ghash_data.finished = 1;
				ghash_data.has_data = 0;
				p = ghash_data.digest;
				for (i = 0; i < GOST_HASH_DIGEST_SIZE; i++) {
					sprintf(p, "%02x", ghash[i]);
					p += 2;
				}

				ghash_data.digest[GHASH_FILE_DEFAULT_SZ - 1] = '\0';
				ghash_data.digest[GHASH_FILE_DEFAULT_SZ - 2] = '\n';
			}
		}
	}
	else
		ret = -EINVAL;
	if (!ret)
		ret = count;

	GHASH_UNLOCK();
	return ret;
}

static int ghash_ctrl_file_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static struct gost_debugfs_file gosthash_files[GOSTHASH_DEBUGFS_FILES] = {
	{
		.name = "ghash_ctrl",
		.fops = {
			.owner	 = THIS_MODULE,
			.open	 = ghash_ctrl_file_open,
			.write	 = ghash_ctrl_file_write,
			.release = ghash_ctrl_file_release,
		},
		.mode = S_IRUGO,
		.debugfs_dentry = NULL,
		.init_fn	= NULL,
		.clear_fn	= NULL,
		.initialized	= 0,
	},
	{
		.name = "ghash",
		.fops = {
			.owner	 = THIS_MODULE,
			.open	 = ghash_file_open,
			.write	 = ghash_file_write,
			.read    = ghash_file_read,
			.release = ghash_file_release,
		},
		.mode = S_IRUGO,
		.debugfs_dentry = NULL,
		.init_fn	= ghash_file_init,
		.clear_fn	= ghash_file_clear,
		.initialized	= 0,
	},
	{
		.name = "blkid",
		.fops = {
			.owner = THIS_MODULE,
			.open = blkid_file_open_gosthash,
			.read = seq_read,
			.release = single_release,
		},
		.mode = S_IRUGO,
		.debugfs_dentry = NULL,
		.init_fn = NULL,
		.clear_fn = NULL,
		.initialized = 0,
	},
	{
		.name = "sblock",
		.fops = {
			.owner = THIS_MODULE,
			.open = sblock_file_open_gosthash,
			.read = seq_read,
			.llseek = seq_lseek,
			.release = seq_release,
		},
		.mode = S_IRUGO,
		.debugfs_dentry = NULL,
		.init_fn = NULL,
		.clear_fn = NULL,
		.initialized = 0,
	},
};

static struct gost_debugfs_file gostcrypt_files[GOSTCRYPT_DEBUGFS_FILES] = {
	{
		.name = "blkid",
		.fops = {
			.owner = THIS_MODULE,
			.open = blkid_file_open_gostcrypt,
			.read = seq_read,
			.release = single_release,
		},
		.debugfs_dentry = NULL,
		.init_fn = NULL,
		.clear_fn = NULL,
		.initialized = 0,
	},
	{
		.name = "sblock",
		.fops = {
			.owner = THIS_MODULE,
			.open = sblock_file_open_gostcrypt,
			.read = seq_read,
			.llseek = seq_lseek,
			.release = seq_release,
		},
		.mode = S_IRUGO,
		.debugfs_dentry = NULL,
		.init_fn = NULL,
		.clear_fn = NULL,
		.initialized = 0,
	},
};

int gost_debugfs_gosthash_init(int subst_id)
{
	int ret = 0;

	if (gosthash_root)
		return ret;

	BUG_ON(gost_root == NULL);
	gosthash_root = debugfs_create_dir(GOST_DEBUGFS_HASHNAME, gost_root);
	if (IS_ERR(gosthash_root)) {
		ret = PTR_ERR(gosthash_root);
		gosthash_root = NULL;
		printk(KERN_ERR "Failed to create debugfs directory "
		       "%s/%s [ERR: %d]\n", GOST_DEBUGFS_ROOTNAME,
		       GOST_DEBUGFS_HASHNAME, ret);
		goto error;
	}

	ret = make_gost_debugfs_hierarchy(gosthash_files, GOSTHASH_DEBUGFS_FILES,
					  gosthash_root);
	if (ret)
		goto error;

	printk("GOSTHASH debugfs interface was successfully initialized\n");
	gosthash_subst_id = subst_id;
	return ret;
error:
	if (gosthash_root) {
		clear_gost_debugfs_hierarchy(gosthash_files, GOSTHASH_DEBUGFS_FILES);
		debugfs_remove_recursive(gosthash_root);
		gosthash_root = NULL;
	}

	return ret;
}

int gost_debugfs_gostcrypt_init(int subst_id)
{
	int ret = 0;

	if (gostcrypt_root)
		return ret;

	BUG_ON(gost_root == NULL);
	gostcrypt_root = debugfs_create_dir(GOST_DEBUGFS_CRYPTNAME, gost_root);
	if (IS_ERR(gostcrypt_root)) {
		ret = PTR_ERR(gostcrypt_root);
		gostcrypt_root = NULL;
		printk(KERN_ERR "Failed to create debugfs directory "
		       "%s/%s [ERR: %d]\n", GOST_DEBUGFS_ROOTNAME,
		       GOST_DEBUGFS_CRYPTNAME, ret);
		goto error;
	}

	ret = make_gost_debugfs_hierarchy(gostcrypt_files, GOSTCRYPT_DEBUGFS_FILES,
					  gostcrypt_root);
	if (ret)
		goto error;

	printk("GOSTCRYPT debugfs interface was successfully initialized\n");
	gostcrypt_subst_id = subst_id;
	return ret;
error:
	if (gostcrypt_root) {
		clear_gost_debugfs_hierarchy(gostcrypt_files, GOSTCRYPT_DEBUGFS_FILES);
		debugfs_remove_recursive(gostcrypt_root);
		gostcrypt_root = NULL;
	}


	return ret;
}

void gost_debugfs_gosthash_fini(void)
{
	if (!gosthash_root)
		return;

	clear_gost_debugfs_hierarchy(gosthash_files, GOSTHASH_DEBUGFS_FILES);
	debugfs_remove_recursive(gosthash_root);
	gosthash_root = NULL;
	printk("GOSTHASH debugfs interface deinitialized\n");
}

void gost_debugfs_gostcrypt_fini(void)
{
	if (!gostcrypt_root)
		return;

	clear_gost_debugfs_hierarchy(gostcrypt_files, GOSTCRYPT_DEBUGFS_FILES);
	debugfs_remove_recursive(gostcrypt_root);
	gostcrypt_root = NULL;
	printk("GOSTCRYPT debugfs interface deinitialized\n");
}

void gost_debugfs_fini(void)
{
	if (gosthash_root)
		gost_debugfs_gosthash_fini();
	if (gostcrypt_root)
		gost_debugfs_gostcrypt_fini();

	debugfs_remove(gost_root);
	gost_root = NULL;
	printk("GOST debugfs interface deinitialized\n");
}

int gost_debugfs_init(void)
{
	gost_root = debugfs_create_dir(GOST_DEBUGFS_ROOTNAME, NULL);
	if (IS_ERR(gost_root)) {
		int ret = PTR_ERR(gost_root);
		gost_root = NULL;
		printk("Failed to create %s debugfs directory! [ERR: %d]\n",
		       GOST_DEBUGFS_ROOTNAME, ret);
		return ret;
	}

	printk("GOST debugfs interface was successfully initialized\n");
	return 0;
}

#else /* CONFIG_CRYPTO_GOST_DEBUGFS */

int gost_debugfs_init(void)
{
	return 0;
}

void gost_debugfs_fini(void)
{
}

int gost_debugfs_gosthash_init(int subst_id)
{
	return 0;
}

void gost_debugfs_gosthash_fini(void)
{
}

int gost_debugfs_gostcrypt_init(int subst_id)
{
	return 0;
}

void gost_debugfs_gostcrypt_fini(void)
{
}

#endif /* !CONFIG_CRYPTO_GOST_DEBUGFS */

EXPORT_SYMBOL(gost_debugfs_init);
EXPORT_SYMBOL(gost_debugfs_fini);
EXPORT_SYMBOL(gost_debugfs_gosthash_init);
EXPORT_SYMBOL(gost_debugfs_gosthash_fini);
EXPORT_SYMBOL(gost_debugfs_gostcrypt_init);
EXPORT_SYMBOL(gost_debugfs_gostcrypt_fini);

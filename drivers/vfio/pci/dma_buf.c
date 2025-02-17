// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES.
 */
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>

#include "vfio_pci_priv.h"

MODULE_IMPORT_NS("DMA_BUF");

struct vfio_pci_dma_buf {
	struct dma_buf *dmabuf;
	struct vfio_pci_core_device *vdev;
	struct list_head dmabufs_elm;
	unsigned int nr_ranges;
	struct vfio_region_dma_range *dma_ranges;
	bool revoked;
};

static void vfio_pci_dma_buf_unpin(struct dma_buf_attachment *attachment)
{
}

static int vfio_pci_dma_buf_pin(struct dma_buf_attachment *attachment)
{
	/*
	 * Uses the dynamic interface but must always allow for
	 * dma_buf_move_notify() to do revoke
	 */
	return -EINVAL;
}

static int vfio_pci_dma_buf_get_pfn(struct dma_buf_attachment *attachment,
				    pgoff_t pgoff, u64 *pfn, int *max_order)
{
	/* TODO */
	return -EOPNOTSUPP;
}

static void vfio_pci_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	/*
	 * Either this or vfio_pci_dma_buf_cleanup() will remove from the list.
	 * The refcount prevents both.
	 */
	if (priv->vdev) {
		down_write(&priv->vdev->memory_lock);
		list_del_init(&priv->dmabufs_elm);
		up_write(&priv->vdev->memory_lock);
		vfio_device_put_registration(&priv->vdev->vdev);
	}
	kfree(priv);
}

static const struct dma_buf_ops vfio_pci_dmabuf_ops = {
	.pin = vfio_pci_dma_buf_pin,
	.unpin = vfio_pci_dma_buf_unpin,
	.get_pfn = vfio_pci_dma_buf_get_pfn,
	.release = vfio_pci_dma_buf_release,
};

static int check_dma_ranges(struct vfio_pci_dma_buf *priv, u64 *dmabuf_size)
{
	struct vfio_region_dma_range *dma_ranges = priv->dma_ranges;
	struct pci_dev *pdev = priv->vdev->pdev;
	resource_size_t bar_size;
	int i;

	for (i = 0; i < priv->nr_ranges; i++) {
		/*
		 * For PCI the region_index is the BAR number like
		 * everything else.
		 */
		if (dma_ranges[i].region_index >= VFIO_PCI_ROM_REGION_INDEX)
			return -EINVAL;

		bar_size = pci_resource_len(pdev, dma_ranges[i].region_index);
		if (!bar_size)
			return -EINVAL;

		if (!dma_ranges[i].offset && !dma_ranges[i].length)
			dma_ranges[i].length = bar_size;

		if (!IS_ALIGNED(dma_ranges[i].offset, PAGE_SIZE) ||
		    !IS_ALIGNED(dma_ranges[i].length, PAGE_SIZE) ||
		    dma_ranges[i].length > bar_size ||
		    dma_ranges[i].offset >= bar_size ||
		    dma_ranges[i].offset + dma_ranges[i].length > bar_size)
			return -EINVAL;

		*dmabuf_size += dma_ranges[i].length;
	}

	return 0;
}

int vfio_pci_core_feature_dma_buf(struct vfio_pci_core_device *vdev, u32 flags,
				  struct vfio_device_feature_dma_buf __user *arg,
				  size_t argsz)
{
	struct vfio_device_feature_dma_buf get_dma_buf;
	struct vfio_region_dma_range *dma_ranges;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vfio_pci_dma_buf *priv;
	u64 dmabuf_size = 0;
	int ret;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_GET,
				 sizeof(get_dma_buf));
	if (ret != 1)
		return ret;

	if (copy_from_user(&get_dma_buf, arg, sizeof(get_dma_buf)))
		return -EFAULT;

	dma_ranges = memdup_array_user(&arg->dma_ranges,
				       get_dma_buf.nr_ranges,
				       sizeof(*dma_ranges));
	if (IS_ERR(dma_ranges))
		return PTR_ERR(dma_ranges);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		kfree(dma_ranges);
		return -ENOMEM;
	}

	priv->vdev = vdev;
	priv->nr_ranges = get_dma_buf.nr_ranges;
	priv->dma_ranges = dma_ranges;

	ret = check_dma_ranges(priv, &dmabuf_size);
	if (ret)
		goto err_free_priv;

	if (!vfio_device_try_get_registration(&vdev->vdev)) {
		ret = -ENODEV;
		goto err_free_priv;
	}

	exp_info.ops = &vfio_pci_dmabuf_ops;
	exp_info.size = dmabuf_size;
	exp_info.flags = get_dma_buf.open_flags;
	exp_info.priv = priv;

	priv->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(priv->dmabuf)) {
		ret = PTR_ERR(priv->dmabuf);
		goto err_dev_put;
	}

	/* dma_buf_put() now frees priv */
	INIT_LIST_HEAD(&priv->dmabufs_elm);
	down_write(&vdev->memory_lock);
	dma_resv_lock(priv->dmabuf->resv, NULL);
	priv->revoked = !__vfio_pci_memory_enabled(vdev);
	list_add_tail(&priv->dmabufs_elm, &vdev->dmabufs);
	dma_resv_unlock(priv->dmabuf->resv);
	up_write(&vdev->memory_lock);

	/*
	 * dma_buf_fd() consumes the reference, when the file closes the dmabuf
	 * will be released.
	 */
	return dma_buf_fd(priv->dmabuf, get_dma_buf.open_flags);

err_dev_put:
	vfio_device_put_registration(&vdev->vdev);
err_free_priv:
	kfree(dma_ranges);
	kfree(priv);
	return ret;
}

void vfio_pci_dma_buf_move(struct vfio_pci_core_device *vdev, bool revoked)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	lockdep_assert_held_write(&vdev->memory_lock);

	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		/*
		 * Returns true if a reference was successfully obtained.
		 * The caller must interlock with the dmabuf's release
		 * function in some way, such as RCU, to ensure that this
		 * is not called on freed memory.
		 */
		if (!get_file_rcu(&priv->dmabuf->file))
			continue;

		if (priv->revoked != revoked) {
			dma_resv_lock(priv->dmabuf->resv, NULL);
			priv->revoked = revoked;
			dma_buf_move_notify(priv->dmabuf);
			dma_resv_unlock(priv->dmabuf->resv);
		}
		dma_buf_put(priv->dmabuf);
	}
}

void vfio_pci_dma_buf_cleanup(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	down_write(&vdev->memory_lock);
	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_rcu(&priv->dmabuf->file))
			continue;
		dma_resv_lock(priv->dmabuf->resv, NULL);
		list_del_init(&priv->dmabufs_elm);
		priv->vdev = NULL;
		priv->revoked = true;
		dma_buf_move_notify(priv->dmabuf);
		dma_resv_unlock(priv->dmabuf->resv);
		vfio_device_put_registration(&vdev->vdev);
		dma_buf_put(priv->dmabuf);
	}
	up_write(&vdev->memory_lock);
}

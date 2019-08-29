#include <libaio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

// ***** aio intercept ****

#if 0
struct iocb {
    void *data;
    unsigned key;
    short aio_lio_opcode;
    short aio_reqprio;
    int aio_fildes;
};

static inline void io_prep_pread(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PREAD;
	iocb->aio_reqprio = 0;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
}

static inline void io_prep_pwrite(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PWRITE;
	iocb->aio_reqprio = 0;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
}

#endif
static struct iocb *pending_iocb = NULL;

struct io_context {
    int context_num;
};
static struct io_context our_io_context = {.context_num = 1};

int io_setup(int nr_events, io_context_t *ctx_idp)
{
    if (nr_events == 0) {
        return EINVAL;
    }
    if (nr_events > 1) {
        return EAGAIN;
    }
    if (ctx_idp == NULL) {
        return EFAULT;
    }
    *ctx_idp = &our_io_context;
    return 0;
}


int io_submit(io_context_t ctx_id, long nr, struct iocb *ios[])
{
    if ((pending_iocb != NULL) ||
        (nr > 1)) {
        return EAGAIN;
    }
    if ((nr == 1) && ((ios == NULL) || (ios[0] == NULL))) {
        return EFAULT;
    }
    if ((ctx_id != &our_io_context) ||
        (nr < 0) ||
        ((nr == 1) &&
         (ios[0]->aio_lio_opcode != IO_CMD_PREAD) &&
         (ios[0]->aio_lio_opcode != IO_CMD_PWRITE))) {
        return EINVAL;
    }
    if ((fcntl(ios[0]->aio_fildes, F_GETFD) == -1) && (errno == EBADF)) {
        return EBADF;
    }
    if (nr == 1) {
        pending_iocb = ios[0];
    }
    return nr;
}

int io_getevents(io_context_t ctx_id, long min_nr, long nr,
                        struct io_event *events, struct timespec *timeout)
{
    if ((ctx_id != &our_io_context) ||
        (min_nr != 1) ||
        (nr != 1)) {
        return EINVAL;
    }
    if (pending_iocb == NULL) {
        return 0;
    }

	switch (pending_iocb->aio_lio_opcode) {
		case IO_CMD_PWRITE:
			events->res = pwrite(pending_iocb->aio_fildes,
								pending_iocb->u.c.buf,
								pending_iocb->u.c.nbytes,
								pending_iocb->u.c.offset);
			break;
		case IO_CMD_PREAD:
			events->res = pread(pending_iocb->aio_fildes,
								pending_iocb->u.c.buf,
								pending_iocb->u.c.nbytes,
								pending_iocb->u.c.offset);
			break;
		default:
			events->res = 0;
	}

    events->data = pending_iocb->data;
    events->obj  = pending_iocb;

    events->res2  = 0;
    pending_iocb = NULL;
    return 1;
}


int io_cancel(io_context_t ctx_id, struct iocb *iocb,
                     struct io_event *result)
{
    if (ctx_id != &our_io_context) {
        return EINVAL;
    }
    if ((iocb == NULL) || (result == NULL)) {
        return EFAULT;
    }
    if (pending_iocb != iocb) {
        return EAGAIN;
    }
    result->data = iocb->data;
    result->obj  = iocb;
    result->res  = 0;
    result->res2  = 0;
    pending_iocb = NULL;
    return 0;
}

// ***** end - aio intercept ****

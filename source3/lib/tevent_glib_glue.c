/*
   Unix SMB/CIFS implementation.
   Integration of a glib g_main_context into a tevent_context
   Copyright (C) Stefan Metzmacher 2016
   Copyright (C) Ralph Boehme 2016

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "tevent_glib_glue.h"
#include "system/filesys.h"
#include "system/select.h"
#include "lib/util/debug.h"
#include <tevent.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_TEVENT

#ifdef HAVE_GLIB

#include <glib.h>

struct tevent_fd_map {
	int fd;
	struct tevent_fd *fd_event;
};

struct tevent_glib_glue {
	struct tevent_context *ev;
	GMainContext *gmain_ctx;
	bool quit;

	struct tevent_timer *retry_timer;
	gint gtimeout;
	gint gpriority;
	GPollFD *gpollfds;
	gint num_gpollfds;
	GPollFD *prev_gpollfds;
	gint num_prev_gpollfds;

	struct tevent_fd_map *fd_map;
	size_t num_maps;
	struct tevent_timer *timer;
	struct tevent_immediate *im;
	bool scheduled_im;
	struct pollfd *pollfds;
};

static bool tevent_glib_prepare(struct tevent_glib_glue *glue);
static bool tevent_glib_process(struct tevent_glib_glue *glue);
static void tevent_glib_glue_cleanup(struct tevent_glib_glue *glue);
static void tevent_glib_fd_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data);

typedef int (*gfds_cmp_cb)(const void *fd1, const void *fd2);
typedef bool (*gfds_found_cb)(struct tevent_glib_glue *glue,
			      const GPollFD *new, const GPollFD *old);
typedef bool (*gfds_new_cb)(struct tevent_glib_glue *glue, const GPollFD *fd);
typedef bool (*gfds_removed_cb)(struct tevent_glib_glue *glue, const GPollFD *fd);

/**
 * Compare two GPollFD arrays
 *
 * For every element that exists in gfds and prev_gfds found_fn() is called.
 * For every element in gfds but not in prev_gfds, new_fn() is called.
 * For every element in prev_gfds but not in gfds removed_fn() is called.
 **/
static bool cmp_gfds(struct tevent_glib_glue *glue,
		     GPollFD *gfds, GPollFD *prev_gfds,
		     size_t num_gfds, size_t num_prev_gfds,
		     gfds_cmp_cb cmp_cb,
		     gfds_found_cb found_cb,
		     gfds_new_cb new_cb,
		     gfds_removed_cb removed_cb)
{
	bool ok;
	size_t i = 0, j = 0;
	int cmp;

	while (i < num_gfds && j < num_prev_gfds) {
		cmp = cmp_cb(&gfds[i], &prev_gfds[j]);
		if (cmp == 0) {
			ok = found_cb(glue, &gfds[i], &prev_gfds[j]);
			if (!ok) {
				return false;
			}
			i++;
			j++;
		} else if (cmp < 0) {
			ok = new_cb(glue, &gfds[i]);
			if (!ok) {
				return false;
			}
			i++;
		} else {
			ok = removed_cb(glue, &prev_gfds[j]);
			if (!ok) {
				return false;
			}
			j++;
		}
	}

	while (i < num_gfds) {
		ok = new_cb(glue, &gfds[i++]);
		if (!ok) {
			return false;
		}
	}

	while (j < num_prev_gfds) {
		ok = removed_cb(glue, &prev_gfds[j++]);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static int glib_fd_cmp_func(const void *p1, const void *p2)
{
	const GPollFD *lhs = p1;
	const GPollFD *rhs = p2;

	if (lhs->fd < rhs->fd) {
		return -1;
	} else if (lhs->fd > rhs->fd) {
		return 1;
	}

	return 0;
}

static bool match_gfd_cb(struct tevent_glib_glue *glue,
			 const GPollFD *new_gfd,
			 const GPollFD *old_gfd)
{
	size_t i;
	struct tevent_fd *fd_event = NULL;

	if (new_gfd->events == old_gfd->events) {
		return true;
	}

	for (i = 0; i < glue->num_maps; i++) {
		if (glue->fd_map[i].fd == new_gfd->fd) {
			break;
		}
	}

 	if (i == glue->num_maps) {
		DBG_ERR("match_gfd_cb: glib fd %d not in map\n", new_gfd->fd);
		return false;
	}

	fd_event = glue->fd_map[i].fd_event;
	if (fd_event == NULL) {
		DBG_ERR("fd_event for fd %d is NULL\n", new_gfd->fd);
		return false;
	}

	tevent_fd_set_flags(fd_event, 0);

	if (new_gfd->events & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
		TEVENT_FD_READABLE(fd_event);
	}
	if (new_gfd->events & G_IO_OUT) {
		TEVENT_FD_WRITEABLE(fd_event);
	}

	return true;
}

static bool add_gfd_cb(struct tevent_glib_glue *glue, const GPollFD *gfd)
{
	struct tevent_fd *fd_event = NULL;
	uint16_t events;

	events = (gfd->events & (G_IO_IN | G_IO_HUP | G_IO_ERR)) ?
		TEVENT_FD_READ : 0;
	events |= (gfd->events & G_IO_OUT) ? TEVENT_FD_WRITE : 0;

	fd_event = tevent_add_fd(glue->ev, glue->fd_map,
				 gfd->fd,
				 events,
				 tevent_glib_fd_handler,
				 glue);
	if (fd_event == NULL) {
		DBG_ERR("tevent_add_fd failed\n");
		return false;
	}

	glue->fd_map = talloc_realloc(glue, glue->fd_map,
				      struct tevent_fd_map,
				      glue->num_maps + 1);
	if (glue->fd_map == NULL) {
		DBG_ERR("talloc_realloc failed\n");
		return false;
	}

	glue->fd_map[glue->num_maps].fd = gfd->fd;
	glue->fd_map[glue->num_maps].fd_event = fd_event;
	glue->num_maps++;

	DBG_DEBUG("added tevent_fd for glib fd %d\n", gfd->fd);

	return true;
}

static bool remove_gfd_cb(struct tevent_glib_glue *glue, const GPollFD *gfd)
{
	size_t i;

	for (i = 0; i < glue->num_maps; i++) {
		if (glue->fd_map[i].fd == gfd->fd) {
			break;
		}
	}

 	if (i == glue->num_maps) {
		DBG_ERR("remove_gfd_cb: glib fd %d not in map\n", gfd->fd);
		return false;
	}

	TALLOC_FREE(glue->fd_map[i].fd_event);

	if (i + 1 < glue->num_maps) {
		memmove(&glue->fd_map[i], &glue->fd_map[i+1],
			(glue->num_maps - (i + 1)) * sizeof(struct tevent_fd_map));
	}

	glue->num_maps--;

	glue->fd_map = talloc_realloc(glue, glue->fd_map,
				      struct tevent_fd_map,
				      glue->num_maps);
	if (glue->num_maps > 0 && glue->fd_map == NULL) {
		DBG_ERR("talloc_realloc failed\n");
		return false;
	}

	return true;
}

static void tevent_glib_fd_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	tevent_glib_process(glue);

	return;
}

static void tevent_glib_timer_handler(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval current_time,
				      void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->timer = NULL;
	tevent_glib_process(glue);

	return;
}

static void tevent_glib_im_handler(struct tevent_context *ev,
				   struct tevent_immediate *im,
				   void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->scheduled_im = false;
	tevent_glib_process(glue);

	return;
}

static bool save_current_fdset(struct tevent_glib_glue *glue)
{
	/* Save old glib fds, we only grow the prev array */
	if (glue->num_prev_gpollfds < glue->num_gpollfds) {
		glue->prev_gpollfds = talloc_realloc(glue,
						     glue->prev_gpollfds,
						     GPollFD,
						     glue->num_gpollfds);
		if (glue->prev_gpollfds == NULL) {
			DBG_ERR("talloc_realloc failed\n");
			return false;
		}
	}
	glue->num_prev_gpollfds = glue->num_gpollfds;
	if (glue->num_gpollfds > 0) {
		memcpy(glue->prev_gpollfds, glue->gpollfds,
		       sizeof(GPollFD) * glue->num_gpollfds);
		memset(glue->gpollfds, 0, sizeof(GPollFD) * glue->num_gpollfds);
	}

	return true;
}

static bool get_glib_fds_and_timeout(struct tevent_glib_glue *glue)
{
	bool ok;
	gint num_fds;

	ok = save_current_fdset(glue);
	if (!ok) {
		return false;
	}

	while (true) {
		num_fds = g_main_context_query(glue->gmain_ctx,
					       glue->gpriority,
					       &glue->gtimeout,
					       glue->gpollfds,
					       glue->num_gpollfds);
		if (num_fds == glue->num_gpollfds) {
			break;
		}
		glue->gpollfds = talloc_realloc(glue,
						glue->gpollfds,
						GPollFD,
						num_fds);
		if (num_fds > 0 && glue->gpollfds == NULL) {
			DBG_ERR("talloc_realloc failed\n");
			return false;
		}
		glue->num_gpollfds = num_fds;
	};

	if (glue->num_gpollfds > 0) {
		qsort(glue->gpollfds, num_fds, sizeof(GPollFD), glib_fd_cmp_func);
	}

	DBG_DEBUG("get_glib_fds_and_timeout: num fds: %d, timeout: %d ms\n",
		num_fds, glue->gtimeout);

	return true;
}

static bool tevent_glib_update_events(struct tevent_glib_glue *glue)
{
	bool ok;

	ok = cmp_gfds(glue,
		      glue->gpollfds,
		      glue->prev_gpollfds,
		      glue->num_gpollfds,
		      glue->num_prev_gpollfds,
		      glib_fd_cmp_func,
		      match_gfd_cb,
		      add_gfd_cb,
		      remove_gfd_cb);
	if (!ok) {
		return false;
	}

	TALLOC_FREE(glue->timer);
	if ((glue->gtimeout == 0) && (!glue->scheduled_im)) {
		/*
		 * Schedule an immediate event. We use a immediate event and not
		 * an immediate timer event, because the former can be reused.
		 *
		 * We may be called in a loop in tevent_glib_process() and only
		 * want to schedule this once, so we remember the fact.
		 *
		 * Doing this here means we occasionally schedule an unneeded
		 * immediate event, but it avoids leaking abstraction into upper
		 * layers.
		 */
		tevent_schedule_immediate(glue->im, glue->ev,
					  tevent_glib_im_handler,
					  glue);
		glue->scheduled_im = true;
	} else if (glue->gtimeout > 0) {
		uint64_t microsec = glue->gtimeout * 1000;
		struct timeval tv = tevent_timeval_current_ofs(microsec / 1000000,
							       microsec % 1000000);

		glue->timer = tevent_add_timer(glue->ev, glue,
					       tv,
					       tevent_glib_timer_handler,
					       glue);
		if (glue->timer == NULL) {
			DBG_ERR("tevent_add_timer failed\n");
			return false;
		}
	}

	return true;
}

static void tevent_glib_retry_timer(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *private_data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(
		private_data, struct tevent_glib_glue);

	glue->retry_timer = NULL;
	(void)tevent_glib_prepare(glue);
}

static bool tevent_glib_prepare(struct tevent_glib_glue *glue)
{
	bool ok;
	gboolean gok, source_ready;

	gok = g_main_context_acquire(glue->gmain_ctx);
	if (!gok) {
		DBG_ERR("couldn't acquire g_main_context\n");

		tevent_glib_glue_cleanup(glue);

		glue->retry_timer = tevent_add_timer(
			glue->ev, glue,
			tevent_timeval_current_ofs(0, 1000),
			tevent_glib_retry_timer,
			glue);
		if (glue->retry_timer == NULL) {
			DBG_ERR("tevent_add_timer failed\n");
			return false;
		}
		return true;
	}

	source_ready = g_main_context_prepare(glue->gmain_ctx, &glue->gpriority);
	if (source_ready) {
		g_main_context_dispatch(glue->gmain_ctx);
	}

	ok = get_glib_fds_and_timeout(glue);
	if (!ok) {
		DBG_ERR("get_glib_fds_and_timeout failed\n");
		samba_tevent_glib_glue_quit(glue);
		return false;
	}

	tevent_glib_update_events(glue);

	return true;
}

static short gpoll_to_poll_event(gushort gevent)
{
	short pevent = 0;

	if (gevent & G_IO_IN) {
		pevent |= POLLIN;
	}
	if (gevent & G_IO_OUT) {
		pevent |= POLLOUT;
	}
	if (gevent & G_IO_HUP) {
		pevent |= POLLHUP;
	}
	if (gevent & G_IO_ERR) {
		pevent |= POLLERR;
	}

	return pevent;
}

static gushort poll_to_gpoll_event(short pevent)
{
	gushort gevent = 0;

	if (pevent & POLLIN) {
		gevent |= G_IO_IN;
	}
	if (pevent & POLLOUT) {
		gevent |= G_IO_OUT;
	}
	if (pevent & POLLHUP) {
		gevent |= G_IO_HUP;
	}
	if (pevent & POLLERR) {
		gevent |= G_IO_ERR;
	}

	return gevent;
}

static bool gpoll_to_poll_fds(struct tevent_glib_glue *glue)
{
	size_t i;

	TALLOC_FREE(glue->pollfds);

	glue->pollfds = talloc_zero_array(glue, struct pollfd,
					  glue->num_gpollfds);
	if (glue->pollfds == NULL) {
		DBG_ERR("talloc_zero_array failed\n");
		return false;
	}

	for (i = 0; i < glue->num_gpollfds; i++) {
		glue->pollfds[i].fd = glue->gpollfds[i].fd;
		glue->pollfds[i].events = gpoll_to_poll_event(
			glue->gpollfds[i].events);
	}

	return true;
}

static void poll_to_gpoll_revents(struct tevent_glib_glue *glue)
{
	size_t i;

	for (i = 0; i < glue->num_gpollfds; i++) {
		glue->gpollfds[i].revents = poll_to_gpoll_event(
			glue->pollfds[i].revents);
	}
}

static bool tevent_glib_process(struct tevent_glib_glue *glue)
{
	bool ok;
	int num_ready;

	ok = gpoll_to_poll_fds(glue);
	if (!ok) {
		DBG_ERR("gpoll_to_poll_fds failed\n");
		samba_tevent_glib_glue_quit(glue);
		return false;
	}

	num_ready = poll(glue->pollfds, glue->num_gpollfds, 0);
	if (num_ready == -1) {
		DBG_ERR("poll: %s\n", strerror(errno));
	}

	if (num_ready > 0) {
		poll_to_gpoll_revents(glue);
	}

	DBG_DEBUG("tevent_glib_process: num_ready: %d\n", num_ready);

	do {
		bool sources_ready;

		sources_ready = g_main_context_check(glue->gmain_ctx,
						     glue->gpriority,
						     glue->gpollfds,
						     glue->num_gpollfds);
		if (!sources_ready) {
			break;
		}

		g_main_context_dispatch(glue->gmain_ctx);

		if (glue->quit) {
			/* Set via tevent_glib_glue_quit() */
			g_main_context_release(glue->gmain_ctx);
			return true;
		}

		/*
		 * This is an optimisation for the following case:
		 *
		 * If g_main_context_query() returns a timeout value of 0 this
		 * implicates that there may be more glib event sources ready.
		 * This avoids sheduling an immediate event and going through
		 * tevent_loop_once().
		 */
		if (glue->gtimeout != 0) {
			break;
		}

		/*
		 * Give other glib threads a chance to grab the context,
		 * tevent_glib_prepare() will then re-acquire it
		 */
		g_main_context_release(glue->gmain_ctx);

		ok = tevent_glib_prepare(glue);
		if (!ok) {
			samba_tevent_glib_glue_quit(glue);
			return false;
		}
	} while (true);

	/*
	 * Give other glib threads a chance to grab the context,
	 * tevent_glib_prepare() will then re-acquire it
	 */
	g_main_context_release(glue->gmain_ctx);

	ok = tevent_glib_prepare(glue);
	if (!ok) {
		samba_tevent_glib_glue_quit(glue);
		return false;
	}

	return true;
}

static void tevent_glib_glue_cleanup(struct tevent_glib_glue *glue)
{
	size_t n = talloc_array_length(glue->fd_map);
	size_t i;

	for (i = 0; i < n; i++) {
		TALLOC_FREE(glue->fd_map[i].fd_event);
	}

	TALLOC_FREE(glue->fd_map);
	TALLOC_FREE(glue->gpollfds);
	TALLOC_FREE(glue->prev_gpollfds);
	TALLOC_FREE(glue->timer);
	TALLOC_FREE(glue->retry_timer);
	TALLOC_FREE(glue->im);
	glue->num_gpollfds = 0;
	glue->num_prev_gpollfds = 0;
}

void samba_tevent_glib_glue_quit(struct tevent_glib_glue *glue)
{
	tevent_glib_glue_cleanup(glue);
	glue->quit = true;
	return;
}

struct tevent_glib_glue *samba_tevent_glib_glue_create(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       GMainContext *gmain_ctx)
{
	bool ok;
	struct tevent_glib_glue *glue = NULL;

	glue = talloc_zero(mem_ctx, struct tevent_glib_glue);
	if (glue == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return NULL;
	}

	*glue = (struct tevent_glib_glue) {
		.ev = ev,
		.gmain_ctx = gmain_ctx,
	};

	glue->im = tevent_create_immediate(glue);

	ok = tevent_glib_prepare(glue);
	if (!ok) {
		TALLOC_FREE(glue);
		return NULL;
	}

	return glue;
}

#else /* HAVE_GLIB */

struct tevent_glib_glue *samba_tevent_glib_glue_create(TALLOC_CTX *mem_ctx,
						       struct tevent_context *ev,
						       GMainContext *gmain_ctx)
{
	errno = ENOSYS;
	return NULL;
}

void samba_tevent_glib_glue_quit(struct tevent_glib_glue *glue)
{
	return;
}
#endif /* HAVE_GLIB */

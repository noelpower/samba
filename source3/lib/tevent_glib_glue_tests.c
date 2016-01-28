/*
   Unix SMB/CIFS implementation.

   testing of the tevent glib glue subsystem

   Copyright (C) Ralph Boehme      2016

   glib tests adapted from glib2 glib/tests/mainloop.c
   Copyright (C) 2011 Red Hat Inc., Matthias Clasen

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
#include "lib/tevent_glib_glue.h"
#include <glib.h>
#include <glib-unix.h>

/*
 * Unfortunately the glib test suite runner doesn't pass args to tests
 * so we must keep a few globals here.
 */
static struct tevent_context *ev;

static gboolean cb (gpointer data)
{
	return FALSE;
}

static gboolean prepare (GSource *source, gint *time)
{
	return FALSE;
}
static gboolean check (GSource *source)
{
	return FALSE;
}
static gboolean dispatch (GSource *source, GSourceFunc cb_in, gpointer date)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	prepare,
	check,
	dispatch,
	NULL
};

static void test_maincontext_basic(void)
{
	GMainContext *ctx;
	struct tevent_glib_glue *glue;
	GSource *source;
	guint id;
	gpointer data = &funcs;

	ctx = g_main_context_new ();
	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert (glue != NULL);

	g_assert (!g_main_context_pending (ctx));
	g_assert (!g_main_context_iteration (ctx, FALSE));

	source = g_source_new (&funcs, sizeof (GSource));
	g_assert_cmpint (g_source_get_priority (source), ==, G_PRIORITY_DEFAULT);
	g_assert (!g_source_is_destroyed (source));

	g_assert (!g_source_get_can_recurse (source));
	g_assert (g_source_get_name (source) == NULL);

	g_source_set_can_recurse (source, TRUE);
	g_source_set_name (source, "d");

	g_assert (g_source_get_can_recurse (source));
	g_assert_cmpstr (g_source_get_name (source), ==, "d");

	g_assert (g_main_context_find_source_by_user_data (ctx, NULL) == NULL);
	g_assert (g_main_context_find_source_by_funcs_user_data (ctx, &funcs, NULL) == NULL);

	id = g_source_attach (source, ctx);
	g_assert_cmpint (g_source_get_id (source), ==, id);
	g_assert (g_main_context_find_source_by_id (ctx, id) == source);

	g_source_set_priority (source, G_PRIORITY_HIGH);
	g_assert_cmpint (g_source_get_priority (source), ==, G_PRIORITY_HIGH);

	g_source_destroy (source);
	g_assert (g_source_get_context (source) == ctx);
	g_assert (g_main_context_find_source_by_id (ctx, id) == NULL);

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);
	g_main_context_unref (ctx);

	if (g_test_undefined ())
	{
		g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
				       "*assertion*source->context != NULL*failed*");
		g_assert (g_source_get_context (source) == NULL);
		g_test_assert_expected_messages ();
	}

	g_source_unref (source);

	ctx = g_main_context_default ();

	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert (glue != NULL);

	source = g_source_new (&funcs, sizeof (GSource));
	g_source_set_funcs (source, &funcs);
	g_source_set_callback (source, cb, data, NULL);
	id = g_source_attach (source, ctx);
	g_source_unref (source);
	g_source_set_name_by_id (id, "e");
	g_assert_cmpstr (g_source_get_name (source), ==, "e");
	g_assert (g_source_get_context (source) == ctx);
	g_assert (g_source_remove_by_funcs_user_data (&funcs, data));

	source = g_source_new (&funcs, sizeof (GSource));
	g_source_set_funcs (source, &funcs);
	g_source_set_callback (source, cb, data, NULL);
	id = g_source_attach (source, ctx);
	g_source_unref (source);
	g_assert (g_source_remove_by_user_data (data));
	g_assert (!g_source_remove_by_user_data ((gpointer)0x1234));

	g_idle_add (cb, data);
	g_assert (g_idle_remove_by_data (data));

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);
}

static gboolean count_calls (gpointer data)
{
	gint *i = data;

	(*i)++;

	return TRUE;
}

static gboolean quit_loop (gpointer data)
{
	struct tevent_glib_glue *glue = talloc_get_type_abort(data, struct tevent_glib_glue);

	samba_tevent_glib_glue_quit(glue);

	return G_SOURCE_REMOVE;
}

static void test_timeouts (void)
{
	GMainContext *ctx;
	struct tevent_glib_glue *glue;
	GSource *source;
	static gint a;
	static gint b;
	static gint c;

	a = b = c = 0;

	ctx = g_main_context_new ();
	glue = samba_tevent_glib_glue_create(ev, ev, ctx);
	g_assert (glue != NULL);

	source = g_timeout_source_new (100);
	g_source_set_callback (source, count_calls, &a, NULL);
	g_source_attach (source, ctx);
	g_source_unref (source);

	source = g_timeout_source_new (250);
	g_source_set_callback (source, count_calls, &b, NULL);
	g_source_attach (source, ctx);
	g_source_unref (source);

	source = g_timeout_source_new (330);
	g_source_set_callback (source, count_calls, &c, NULL);
	g_source_attach (source, ctx);
	g_source_unref (source);

	source = g_timeout_source_new (1050);
	g_source_set_callback (source, quit_loop, glue, NULL);
	g_source_attach (source, ctx);
	g_source_unref (source);

	g_assert (tevent_loop_wait(ev) == 0);

	/* We may be delayed for an arbitrary amount of time - for example,
	 * it's possible for all timeouts to fire exactly once.
	 */
	g_assert_cmpint (a, >, 0);
	g_assert_cmpint (a, >=, b);
	g_assert_cmpint (b, >=, c);

	g_assert_cmpint (a, <=, 10);
	g_assert_cmpint (b, <=, 4);
	g_assert_cmpint (c, <=, 3);

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);
	g_main_context_unref (ctx);
}


static gchar zeros[1024];

static gsize fill_a_pipe (gint fd)
{
	gsize written = 0;
	GPollFD pfd;

	pfd.fd = fd;
	pfd.events = G_IO_OUT;
	while (g_poll (&pfd, 1, 0) == 1)
		/* we should never see -1 here */
		written += write (fd, zeros, sizeof zeros);

	return written;
}

static gboolean write_bytes (gint	  fd,
			     GIOCondition condition,
			     gpointer	  user_data)
{
	gssize *to_write = user_data;
	gint limit;

	if (*to_write == 0)
		return FALSE;

	/* Detect if we run before we should */
	g_assert (*to_write >= 0);

	limit = MIN (*to_write, sizeof zeros);
	*to_write -= write (fd, zeros, limit);

	return TRUE;
}

static gboolean read_bytes (gint	 fd,
			    GIOCondition condition,
			    gpointer	 user_data)
{
	static gchar buffer[1024];
	gssize *to_read = user_data;

	*to_read -= read (fd, buffer, sizeof buffer);

	/* The loop will exit when there is nothing else to read, then we will
	 * use g_source_remove() to destroy this source.
	 */
	return TRUE;
}

static void test_unix_fd(void)
{
	gssize to_write = -1;
	gssize to_read;
	gint fds[2];
	gint a, b;
	gint s;
	GSource *source_a;
	GSource *source_b;
	struct tevent_glib_glue *glue;

	glue = samba_tevent_glib_glue_create(ev, ev, g_main_context_default());
	g_assert (glue != NULL);

	s = pipe (fds);
	g_assert (s == 0);

	to_read = fill_a_pipe (fds[1]);
	/* write at higher priority to keep the pipe full... */
	a = g_unix_fd_add_full (G_PRIORITY_HIGH, fds[1], G_IO_OUT, write_bytes, &to_write, NULL);
	source_a = g_source_ref (g_main_context_find_source_by_id (NULL, a));
	/* make sure no 'writes' get dispatched yet */
	while (tevent_loop_once(ev));

	to_read += 128 * 1024 * 1024;
	to_write = 128 * 1024 * 1024;
	b = g_unix_fd_add (fds[0], G_IO_IN, read_bytes, &to_read);
	source_b = g_source_ref (g_main_context_find_source_by_id (NULL, b));

	/* Assuming the kernel isn't internally 'laggy' then there will always
	 * be either data to read or room in which to write.  That will keep
	 * the loop running until all data has been read and written.
	 */
	while (to_write > 0 || to_read > 0)
	{
		gssize to_write_was = to_write;
		gssize to_read_was = to_read;

		if (tevent_loop_once(ev) != 0)
			break;

		/* Since the sources are at different priority, only one of them
		 * should possibly have run.
		 */
		g_assert (to_write == to_write_was || to_read == to_read_was);
	}

	g_assert (to_write == 0);
	g_assert (to_read == 0);

	/* 'a' is already removed by itself */
	g_assert (g_source_is_destroyed (source_a));
	g_source_unref (source_a);
	g_source_remove (b);
	g_assert (g_source_is_destroyed (source_b));
	g_source_unref (source_b);

	samba_tevent_glib_glue_quit(glue);
	TALLOC_FREE(glue);

	close (fds[1]);
	close (fds[0]);
}

int main(int argc, const char *argv[])
{
	int test_argc = 3;
	char *test_argv[] = {
		discard_const("test_glib_glue"),
		discard_const("-m"),
		discard_const("no-undefined")
	};
	char **argvp = test_argv;

	g_test_init(&test_argc, &argvp, NULL);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		exit(1);
	}

	g_test_add_func ("/maincontext/basic", test_maincontext_basic);
	g_test_add_func ("/mainloop/timeouts", test_timeouts);
	g_test_add_func ("/mainloop/unix-fd", test_unix_fd);

	return g_test_run();
}

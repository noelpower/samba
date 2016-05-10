/*
 *  Unix SMB/CIFS implementation.
 *
 *  RawPipe server loop
 *
 *  Copyright (c)  2016 Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __RAWPIPE__
#define __RAWPIPE__


struct named_pipe_client;
struct messaging_context;

/* returns a context that is passed to the handler and close functions */
typedef void* (*rawpipe_init)(struct named_pipe_client *npc,
			    void *private_data);
/* called when pipe is destoyed */
typedef void (*rawpipe_close)(void *init_ctx);
/* called when a message to respond to on the pipe is available */
typedef struct tevent_req *(*rawpipe_fn)(TALLOC_CTX *ctx,
					 struct named_pipe_client *npc,
					 void *init_ctx);

void common_rawpipe_register(const char* pipename,
			     uint16_t msg_mode,
			     rawpipe_init init,
			     rawpipe_close dtor,
			     rawpipe_fn handler,
			     void *private_data);
#ifdef DEVELOPER
void init_rawipe_echo(struct tevent_context *ev_ctx,
		      struct messaging_context *msg_ctx);
#endif

#endif /* __RAWPIPE__ */

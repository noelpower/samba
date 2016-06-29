#ifndef __DCERPC_RAW_H__
#define __DCERPC_RAW_H__
struct dcerpc_pipe;
struct dcerpc_binding_handle;
struct dcerpc_binding_handle *create_rawpipe_handle(struct dcerpc_pipe *p);
#endif /* __DCERPC_RAW_H__ */

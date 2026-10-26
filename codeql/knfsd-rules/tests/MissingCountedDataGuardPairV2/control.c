typedef unsigned int u32;

struct xdr_stream {};

int xdr_stream_decode_u32(struct xdr_stream *xdr, u32 *value);
void *xdr_inline_decode(struct xdr_stream *xdr, u32 length);
void *svcxdr_tmpalloc(struct xdr_stream *xdr, u32 length);

void *unsafe_decode(struct xdr_stream *xdr)
{
	u32 length;

	if (xdr_stream_decode_u32(xdr, &length) < 0)
		return 0;
	return svcxdr_tmpalloc(xdr, length);
}

void *safe_decode(struct xdr_stream *xdr)
{
	u32 length;
	void *bytes;

	if (xdr_stream_decode_u32(xdr, &length) < 0)
		return 0;
	if (length > 1024)
		return 0;
	bytes = xdr_inline_decode(xdr, length);
	if (!bytes)
		return 0;
	return svcxdr_tmpalloc(xdr, length);
}

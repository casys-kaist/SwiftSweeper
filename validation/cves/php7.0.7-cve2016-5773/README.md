# CVE2016-5773

[related Document](https://vuldb.com/?id.90639)

## Use After Free (UAF)
UAF occurs at `zend_gc.c:391`
UAF occurs at gc_scan_black(). 

```c
static void gc_scan_black(zend_refcounted *ref)
{
    // ...
	while (p != end) {
		zv = &p->val;
		if (Z_TYPE_P(zv) == IS_INDIRECT) {
			zv = Z_INDIRECT_P(zv);
		}
		if (Z_REFCOUNTED_P(zv)) {
			ref = Z_COUNTED_P(zv);
			GC_REFCOUNT(ref)++; // This point!
			if (GC_REF_GET_COLOR(ref) != GC_BLACK) {
				gc_scan_black(ref);
			}
		}
		p++;
	}
    // ...
}

```
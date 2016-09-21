#include <linux/linkage.h>

		.code64

ENTRY(shadow_process_fpu_used)
		fnop	/* x87 floating-point instruction */
		ret
END(shadow_process_fpu_used)

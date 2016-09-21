/*
 * This script is used for cappsule.ko and cappsule-guest.ko. It would be
 * cleaner to have 2 separate scripts, because cappsule-guest.ko doesn't need
 * __start_* and __stop_* symbols.
 */

SECTIONS {
    /* allow kernel module to know .text section address and size */
    PROVIDE(__start_erase_text = .);
    .text : {
        /* write .text section from every objects */
        *(.text)

        /* Write .keep.common section from common/channel.o to the .text
         * section. It mustn't erased by the hypervisor.*/
        PROVIDE(__start_keep_common = .);
        */common/channel.o (.keep.common)
        PROVIDE(__stop_keep_common = .);
    }
    PROVIDE(__stop_erase_text = .);
}

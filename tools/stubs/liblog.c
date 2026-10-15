/* Link-time stub for liblog.so (never shipped). The NDK stub leaves
 * __android_log_print unversioned; the device library and the shipped HAL bind
 * it at LIBLOG, so this keeps the build byte-identical to the shipped binary. */
void __android_log_print(void) {}

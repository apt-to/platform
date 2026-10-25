/* Exercise the installed libarchive API using the upstream RAR5 loop fixture. */
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct archive *a;
    struct archive_entry *entry;
    const void *data;
    size_t size;
    la_int64_t offset;
    int result;
    if (argc != 2) return 2;
    a = archive_read_new();
    if (!a) return 3;
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    if (archive_read_open_filename(a, argv[1], 10240) != ARCHIVE_OK) return 4;
    if (archive_read_next_header(a, &entry) != ARCHIVE_OK) return 5;
    while ((result = archive_read_data_block(a, &data, &size, &offset)) == ARCHIVE_OK) {}
    const char *error = archive_error_string(a);
    int rejected = result == ARCHIVE_FATAL && error && strstr(error, "Invalid filter encountered");
    fprintf(stderr, "read result=%d error=%s\n", result, error ? error : "none");
    archive_read_free(a);
    return rejected ? 0 : 6;
}

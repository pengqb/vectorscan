/*
 * sec_vs.c (v3)
 *
 * - Matches patterns against different parts of a simulated HTTP request.
 * - Adds a 'pos' field to the pattern file to target specific HTTP parts.
 * - Compiles, serializes, and deserializes separate databases for each HTTP part.
 *
 * 编译命令:
 * gcc -o sec_vs sec_vs.c $(pkg-config --cflags --libs libhs)
 *
 * 使用方法:
 * ./sec_vs <pattern_file>
 *
 * 规则文件格式 (pattern_file):
 * id:pos:/pattern/flags
 *
 * 示例:
 * 1:0000000000000001:/index\.php/i
 * 2:0000000000001000:/evil/
 *
 * 'pos' is a 16-bit binary string, where each bit corresponds to an HTTP part.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <hs.h>

#define MAX_LINE_LEN 2048
#define MAX_PATTERNS 1024
#define DB_SERIALIZATION_SUFFIX ".db"

// HTTP Request Parts Bitmasks (as per user specification)
#define HTTP_PART_URI               (1 << 0)
#define HTTP_PART_RESERVED_1        (1 << 1)
#define HTTP_PART_ARGS_KEY          (1 << 2)
#define HTTP_PART_ARGS_VALUE        (1 << 3)
#define HTTP_PART_HEADERS_KEY       (1 << 4)
#define HTTP_PART_HEADERS_VALUE     (1 << 5)
#define HTTP_PART_COOKIES_KEY       (1 << 6)
#define HTTP_PART_COOKIES_VALUE     (1 << 7)
#define HTTP_PART_RESERVED_8        (1 << 8)
#define HTTP_PART_RESERVED_9        (1 << 9)
#define HTTP_PART_UPLOAD_NAME       (1 << 10)
#define HTTP_PART_UPLOAD_FNAME      (1 << 11)
#define HTTP_PART_UPLOAD_CTYPE      (1 << 12)
#define HTTP_PART_RAW_BODY          (1 << 13)
#define HTTP_PART_RESERVED_14       (1 << 14)
#define HTTP_PART_RESERVED_15       (1 << 15)

#define NUM_HTTP_PARTS 16

// Names for each part, used for database file naming
const char *http_part_names[NUM_HTTP_PARTS] = {
    "uri", "reserved1", "args_key", "args_value",
    "headers_key", "headers_value", "cookies_key", "cookies_value",
    "reserved8", "reserved9", "upload_name", "upload_filename",
    "upload_content_type", "raw_body", "reserved14", "reserved15"
};

// Context for the match event handler
typedef struct {
    const char *current_input;
    const char *part_name;
} MatchContext;

// Simple structures to represent a simulated HTTP request
typedef struct {
    const char *key;
    const char *value;
} KeyValue;

typedef struct {
    const char *uri;
    KeyValue args[10];
    size_t args_count;
    KeyValue headers[20];
    size_t headers_count;
    KeyValue cookies[10];
    size_t cookies_count;
    const char *upload_filename;
    const char *raw_body;
} HttpRequest;

// Match event handler callback
static int event_handler(unsigned int id, unsigned long long from,
                         unsigned long long to, unsigned int flags, void *ctx) {
    MatchContext *context = (MatchContext *)ctx;
    size_t match_len = to - from;
    char *matched_string = malloc(match_len + 1);
    if (!matched_string) {
        fprintf(stderr, "Failed to allocate memory for matched string.\n");
        return 1; // Stop scanning on error
    }

    memcpy(matched_string, context->current_input + from, match_len);
    matched_string[match_len] = '\0';

    printf("Match Found!\n");
    printf("  Part: %s\n", context->part_name);
    printf("  ID: %u\n", id);
    printf("  Matched Content: '%s'\n", matched_string);

    free(matched_string);
    return 1; // Stop after first match for this input
}

// Parses flag characters (e.g., 'i', 'm', 's') into HS_FLAG constants
static unsigned int parse_flags(const char *flags_str) {
    unsigned int flags = 0;
    if (!flags_str) return flags;
    for (; *flags_str; flags_str++) {
        switch (*flags_str) {
            case 'i': flags |= HS_FLAG_CASELESS; break;
            case 'm': flags |= HS_FLAG_MULTILINE; break;
            case 's': flags |= HS_FLAG_DOTALL; break;
            case 'H': flags |= HS_FLAG_SINGLEMATCH; break;
            case 'V': flags |= HS_FLAG_ALLOWEMPTY; break;
            case '8': flags |= HS_FLAG_UTF8; break;
            case 'W': flags |= HS_FLAG_UCP; break;
        }
    }
    return flags;
}

// Reads and parses the pattern file
static int read_patterns(const char *filename, const char **expressions,
                         unsigned int *flags, unsigned int *ids,
                         uint16_t *poses, size_t *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "ERROR: Opening file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    char line[MAX_LINE_LEN];
    size_t idx = 0;
    while (fgets(line, sizeof(line), fp) && idx < MAX_PATTERNS) {
        if (line[0] == '#' || line[0] == '\n') continue;

        // Format: id:pos:/pattern/flags
        char *id_str = line;
        char *pos_str = strchr(id_str, ':');
        if (!pos_str) continue;
        *pos_str++ = '\0';

        char *pattern_part = strchr(pos_str, ':');
        if (!pattern_part) continue;
        *pattern_part++ = '\0';

        char *first_slash = strchr(pattern_part, '/');
        if (!first_slash) continue;
        char *last_slash = strrchr(first_slash + 1, '/');
        if (!last_slash) continue;

        *last_slash = '\0';
        char *pattern = first_slash + 1;
        char *flag_str = last_slash + 1;

        expressions[idx] = strdup(pattern);
        flags[idx] = parse_flags(flag_str);
        ids[idx] = (unsigned int)strtoul(id_str, NULL, 10);
        poses[idx] = (uint16_t)strtoul(pos_str, NULL, 2); // Base 2 for binary string

        idx++;
    }

    *count = idx;
    fclose(fp);
    return 0;
}

// Helper function to scan a single piece of data
void scan_part(const char *data, const char *part_name, hs_database_t *db, hs_scratch_t *scratch) {
    if (!db || !data) return;

    printf("\n--- Scanning %s ---\n", part_name);
    printf("Data: \"%s\"\n", data);

    MatchContext ctx = { .current_input = data, .part_name = part_name };
    hs_error_t err = hs_scan(db, data, strlen(data), 0, scratch, event_handler, &ctx);

    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        fprintf(stderr, "ERROR: hs_scan failed for %s with error %d\n", part_name, err);
    } else if (err != HS_SCAN_TERMINATED) {
        printf("No match found.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pattern_file>\n", argv[0]);
        return -1;
    }
    const char *pattern_file = argv[1];

    // Read all patterns from the rule file first
    const char *expressions[MAX_PATTERNS];
    unsigned int flags[MAX_PATTERNS];
    unsigned int ids[MAX_PATTERNS];
    uint16_t poses[MAX_PATTERNS];
    size_t total_pattern_count = 0;

    if (read_patterns(pattern_file, expressions, flags, ids, poses, &total_pattern_count) != 0) {
        return -1;
    }
    if (total_pattern_count == 0) {
        fprintf(stderr, "No valid patterns found in %s.\n", pattern_file);
        return 0;
    }
    printf("Read %zu total patterns from %s.\n", total_pattern_count, pattern_file);

    hs_database_t *databases[NUM_HTTP_PARTS] = {0};
    hs_scratch_t *scratches[NUM_HTTP_PARTS] = {0};

    // Compile or deserialize a separate database for each HTTP part
    for (int i = 0; i < NUM_HTTP_PARTS; i++) {
        char db_filename[MAX_LINE_LEN];
        snprintf(db_filename, sizeof(db_filename), "%s.%s%s", pattern_file, http_part_names[i], DB_SERIALIZATION_SUFFIX);

        FILE *db_file = fopen(db_filename, "rb");
        if (db_file) {
            fseek(db_file, 0, SEEK_END);
            long db_size = ftell(db_file);
            fseek(db_file, 0, SEEK_SET);
            char *db_bytes = malloc(db_size);
            if (db_bytes && fread(db_bytes, db_size, 1, db_file) == 1) {
                hs_error_t err = hs_deserialize_database(db_bytes, db_size, &databases[i]);
                if (err != HS_SUCCESS) {
                    fprintf(stderr, "WARNING: Failed to deserialize %s, will re-compile.\n", db_filename);
                    databases[i] = NULL;
                } else {
                    printf("Successfully loaded database for '%s' from %s.\n", http_part_names[i], db_filename);
                }
            }
            free(db_bytes);
            fclose(db_file);
        }

        if (databases[i] == NULL) {
            const char *part_expressions[MAX_PATTERNS];
            unsigned int part_flags[MAX_PATTERNS];
            unsigned int part_ids[MAX_PATTERNS];
            size_t part_count = 0;

            for (size_t j = 0; j < total_pattern_count; j++) {
                if ((poses[j] >> i) & 1) {
                    part_expressions[part_count] = expressions[j];
                    part_flags[part_count] = flags[j];
                    part_ids[part_count] = ids[j];
                    part_count++;
                }
            }

            if (part_count > 0) {
                printf("Compiling %zu patterns for '%s'...\n", part_count, http_part_names[i]);
                hs_compile_error_t *compile_err;
                hs_error_t err = hs_compile_multi(part_expressions, part_flags, part_ids, part_count,
                                                  HS_MODE_BLOCK, NULL, &databases[i], &compile_err);

                if (err != HS_SUCCESS) {
                    fprintf(stderr, "ERROR: Compiling for %s failed: %s\n", http_part_names[i], compile_err->message);
                    hs_free_compile_error(compile_err);
                } else {
                    char *serialized_bytes = NULL;
                    size_t serialized_len = 0;
                    if (hs_serialize_database(databases[i], &serialized_bytes, &serialized_len) == HS_SUCCESS) {
                        FILE *out_file = fopen(db_filename, "wb");
                        if (out_file) {
                            fwrite(serialized_bytes, serialized_len, 1, out_file);
                            fclose(out_file);
                            printf("Serialized database for '%s' to %s\n", http_part_names[i], db_filename);
                        }
                        free(serialized_bytes);
                    }
                }
            }
        }

        if (databases[i]) {
            if (hs_alloc_scratch(databases[i], &scratches[i]) != HS_SUCCESS) {
                fprintf(stderr, "ERROR: Unable to allocate scratch for %s database.\n", http_part_names[i]);
            }
        }
    }

    // Free original pattern strings
    for (size_t i = 0; i < total_pattern_count; i++) {
        free((void*)expressions[i]);
    }

    // --- Create a sample HTTP request and scan it ---
    printf("\n=============================================================\n");
    printf("           Simulating and Scanning HTTP Request\n");
    printf("=============================================================\n");

    HttpRequest req = {
        .uri = "/search.php",
        .args = { {"q", "<script>alert(1)</script>"}, {"lang", "en"} },
        .args_count = 2,
        .headers = { {"Host", "example.com"}, {"User-Agent", "EvilBrowser/1.0"}, {"Accept", "*/*"} },
        .headers_count = 3,
        .cookies = { {"user", "admin"}, {"session", "deadbeef"} },
        .cookies_count = 2,
        .upload_filename = "/etc/upload/shell.php.jpg",
        .raw_body = "{\"username\":\"<script>\",\"password\":\"password\"}"
    };

    scan_part(req.uri, http_part_names[0], databases[0], scratches[0]); // URI

    for (size_t i = 0; i < req.args_count; i++) {
        scan_part(req.args[i].key, http_part_names[2], databases[2], scratches[2]); // Arg Key
        scan_part(req.args[i].value, http_part_names[3], databases[3], scratches[3]); // Arg Value
    }
    for (size_t i = 0; i < req.headers_count; i++) {
        scan_part(req.headers[i].key, http_part_names[4], databases[4], scratches[4]); // Header Key
        scan_part(req.headers[i].value, http_part_names[5], databases[5], scratches[5]); // Header Value
    }
    for (size_t i = 0; i < req.cookies_count; i++) {
        scan_part(req.cookies[i].key, http_part_names[6], databases[6], scratches[6]); // Cookie Key
        scan_part(req.cookies[i].value, http_part_names[7], databases[7], scratches[7]); // Cookie Value
    }
    scan_part(req.upload_filename, http_part_names[11], databases[11], scratches[11]); // upload filename
    scan_part(req.raw_body, http_part_names[13], databases[13], scratches[13]); // Raw Body

    // Cleanup
    for (int i = 0; i < NUM_HTTP_PARTS; i++) {
        if (databases[i]) hs_free_database(databases[i]);
        if (scratches[i]) hs_free_scratch(scratches[i]);
    }

    printf("\nExiting.\n");
    return 0;
}

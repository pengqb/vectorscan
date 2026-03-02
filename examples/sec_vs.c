/*
 * sec_vs.c (v2)
 *
 * - Prints matched content instead of pattern.
 * - Supports serialization/deserialization of the database.
 *
 * 编译命令:
 * gcc -o sec_vs sec_vs.c $(pkg-config --cflags --libs libhs)
 *
 * 使用方法:
 * ./sec_vs <pattern_file>
 *
 * 规则文件格式 (pattern_file):
 * 1:/test/i
 * 2:/abc/
 * 3:/[0-9]+/
 *
 * 首次运行会从 pattern_file 编译并生成 <pattern_file>.db。
 * 后续运行会直接加载 .db 文件，速度更快。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <hs/hs.h>

#define MAX_LINE_LEN 2048
#define MAX_PATTERNS 1024
#define DB_SERIALIZATION_SUFFIX ".db"

// 上下文结构，传递给回调函数
typedef struct {
    const char *current_input; // 指向当前被扫描的数据
} MatchContext;

// 辅助函数：解析标志位字符串 (e.g., "im")
static unsigned int parse_flags(const char *flags_str) {
    unsigned int flags = 0;
    if (!flags_str) return flags;

    while (*flags_str) {
        switch (*flags_str) {
            case 'i': flags |= HS_FLAG_CASELESS; break;
            case 'm': flags |= HS_FLAG_MULTILINE; break;
            case 's': flags |= HS_FLAG_DOTALL; break;
            case 'H': flags |= HS_FLAG_SINGLEMATCH; break;
            case 'V': flags |= HS_FLAG_ALLOWEMPTY; break;
            case '8': flags |= HS_FLAG_UTF8; break;
            case 'W': flags |= HS_FLAG_UCP; break;
            case '\r': case '\n': break; // 忽略换行
            default:
                fprintf(stderr, "Warning: Unsupported flag '%c'\n", *flags_str);
                break;
        }
        flags_str++;
    }
    return flags;
}

// 匹配回调函数
// 返回 0 表示继续匹配，返回 非0 表示停止匹配
static int event_handler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags,
                        void *ctx) {
    MatchContext *context = (MatchContext *)ctx;

    // 1. 只打印ID和匹配到的内容
    size_t match_len = to - from;
    char *matched_string = malloc(match_len + 1);
    if (!matched_string) {
        fprintf(stderr, "Failed to allocate memory for matched string.\n");
        return 1; // 出错时停止扫描
    }

    // 从输入缓存中复制匹配到的内容
    memcpy(matched_string, context->current_input + from, match_len);
    matched_string[match_len] = '\0';

    printf("Match Found!\n");
    printf("  ID: %u\n", id);
    printf("  Matched Content: %s\n", matched_string);

    free(matched_string);

    // 匹配上后，结束该字符串匹配
    return 1;
}

// 读取并解析规则文件
static int read_patterns(const char *filename,
                         const char **expressions,
                         unsigned int *flags,
                         unsigned int *ids,
                         size_t *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    char line[MAX_LINE_LEN];
    size_t idx = 0;

    while (fgets(line, sizeof(line), fp) && idx < MAX_PATTERNS) {
        if (line[0] == '#' || line[0] == '\n' || strlen(line) < 3) continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        unsigned int id = (unsigned int)strtoul(line, NULL, 10);

        char *last_slash = strrchr(colon + 1, '/');
        if (!last_slash) continue;

        char *first_slash = strchr(colon + 1, '/');
        if (!first_slash || first_slash >= last_slash) continue;

        *last_slash = '\0';
        char *pattern = first_slash + 1;
        char *flag_str = last_slash + 1;

        expressions[idx] = strdup(pattern);
        flags[idx] = parse_flags(flag_str);
        ids[idx] = id;
        idx++;
    }

    *count = idx;
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pattern_file>\n", argv[0]);
        return -1;
    }

    const char *pattern_file = argv[1];
    char db_filename[MAX_LINE_LEN];
    snprintf(db_filename, sizeof(db_filename), "%s%s", pattern_file, DB_SERIALIZATION_SUFFIX);

    hs_database_t *database = NULL;
    hs_error_t err;

    // 2. 增加反序列化操作
    FILE *db_file = fopen(db_filename, "rb");
    if (db_file) {
        printf("Found serialized database: %s. Attempting to load.\n", db_filename);
        fseek(db_file, 0, SEEK_END);
        long db_size = ftell(db_file);
        fseek(db_file, 0, SEEK_SET);

        char *db_bytes = malloc(db_size);
        if (db_bytes && fread(db_bytes, db_size, 1, db_file) == 1) {
            err = hs_deserialize_database(db_bytes, db_size, &database);
            if (err != HS_SUCCESS) {
                fprintf(stderr, "ERROR: Failed to deserialize database. Re-compiling from source.\n");
                database = NULL;
            } else {
                printf("Database successfully deserialized.\n");
            }
        } else {
            fprintf(stderr, "ERROR: Could not read serialized database file. Re-compiling from source.\n");
        }
        free(db_bytes);
        fclose(db_file);
    }

    // 如果反序列化失败或文件不存在，则从文件编译
    if (database == NULL) {
        printf("Compiling patterns from %s...\n", pattern_file);

        const char *expressions[MAX_PATTERNS];
        unsigned int flags[MAX_PATTERNS];
        unsigned int ids[MAX_PATTERNS];
        size_t pattern_count = 0;

        if (read_patterns(pattern_file, expressions, flags, ids, &pattern_count) != 0) {
            return -1;
        }
        if (pattern_count == 0) {
            fprintf(stderr, "No valid patterns found.\n");
            return -1;
        }

        hs_compile_error_t *compile_err;
        err = hs_compile_multi(expressions, flags, ids, pattern_count,
                               HS_MODE_STREAM, NULL, &database, &compile_err);

        for (size_t i = 0; i < pattern_count; i++) {
            free((void*)expressions[i]);
        }

        if (err != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to compile patterns. %s\n", compile_err->message);
            hs_free_compile_error(compile_err);
            return -1;
        }

        // 2. 增加序列化操作
        char *serialized_bytes = NULL;
        size_t serialized_len = 0;
        err = hs_serialize_database(database, &serialized_bytes, &serialized_len);
        if (err == HS_SUCCESS) {
            FILE *out_file = fopen(db_filename, "wb");
            if (out_file) {
                if (fwrite(serialized_bytes, serialized_len, 1, out_file) == 1) {
                    printf("Successfully serialized database to %s\n", db_filename);
                } else {
                    fprintf(stderr, "ERROR: Failed to write serialized database to file.\n");
                }
                fclose(out_file);
            } else {
                fprintf(stderr, "ERROR: Unable to open %s for writing.\n", db_filename);
            }
            hs_free_serialized_database(serialized_bytes);
        } else {
            fprintf(stderr, "ERROR: Unable to serialize database.\n");
        }
    }

    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space.\n");
        hs_free_database(database);
        return -1;
    }

    hs_stream_t *stream;
    if (hs_open_stream(database, 0, &stream) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to open stream.\n");
        hs_free_scratch(scratch);
        hs_free_database(database);
        return -1;
    }

    printf("\nReady for input. Type strings and press Enter (Ctrl+C to exit).\n");
    printf("-------------------------------------------------------------\n");

    MatchContext ctx;
    char input_buffer[MAX_LINE_LEN];
    while (1) {
        printf("> ");
        if (!fgets(input_buffer, sizeof(input_buffer), stdin)) break;

        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len-1] == '\n') {
            input_buffer[len-1] = '\0';
            len--;
        }
        if (len == 0) continue;

        // 更新上下文，指向当前输入
        ctx.current_input = input_buffer;

        err = hs_scan_stream(stream, input_buffer, len, 0, scratch, event_handler, &ctx);

        if (err == HS_SCAN_TERMINATED) {
            printf("Scan terminated by match (as requested).\n");
            // 重置流，以便下次输入是全新的匹配
            hs_close_stream(stream, scratch, NULL, NULL);
            hs_open_stream(database, 0, &stream);
        } else if (err != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to scan stream. Error code: %d\n", err);
            break;
        } else {
            printf("No match found in this chunk.\n");
        }
    }

    hs_close_stream(stream, scratch, NULL, NULL);
    hs_free_scratch(scratch);
    hs_free_database(database);

    printf("\nExiting.\n");
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>

#define MAX_THREADS 16
#define MAX_PATH_LEN 4096
#define MAX_LINE_LEN 1048576  // 1MB per line
#define QUEUE_SIZE 10000

// Base64 decoding table
static const unsigned char base64_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

typedef struct {
    char path[MAX_PATH_LEN];
} FileTask;

typedef struct {
    FileTask tasks[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} TaskQueue;

typedef struct {
    const char *search_string;
    int min_length;
    int case_sensitive;
    int verbose;
    TaskQueue *queue;
    int *match_count;
    pthread_mutex_t *print_mutex;
} ThreadArgs;

TaskQueue task_queue;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
int total_matches = 0;

// Helper to print hex string
void print_hex(const unsigned char *data, int len, int max_display) {
    int display_len = len < max_display ? len : max_display;
    for (int i = 0; i < display_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > max_display) printf("...");
}

// Helper to print string with escape sequences for non-printable chars
void print_escaped(const unsigned char *data, int len, int max_display) {
    int display_len = len < max_display ? len : max_display;
    for (int i = 0; i < display_len; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            putchar(data[i]);
        } else if (data[i] == '\n') {
            printf("\\n");
        } else if (data[i] == '\r') {
            printf("\\r");
        } else if (data[i] == '\t') {
            printf("\\t");
        } else {
            printf("\\x%02x", data[i]);
        }
    }
    if (len > max_display) printf("...");
}

// Check if character is valid base64 (without padding)
int is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || 
           (c >= 'a' && c <= 'z') || 
           (c >= '0' && c <= '9') || 
           c == '+' || c == '/';
}

// Check if character is base64 padding
int is_base64_padding(char c) {
    return c == '=';
}

// Check if character is valid hex
int is_hex_char(char c) {
    return (c >= '0' && c <= '9') || 
           (c >= 'A' && c <= 'F') || 
           (c >= 'a' && c <= 'f');
}

// Decode base64 string
int base64_decode(const char *input, int input_len, unsigned char *output, int max_output_len) {
    int i, j = 0;
    unsigned char quad[4];
    int quad_pos = 0;
    
    for (i = 0; i < input_len && j < max_output_len - 3; i++) {
        unsigned char c = base64_table[(unsigned char)input[i]];
        if (c == 64) {
            if (input[i] == '=') {
                break;  // Padding reached
            }
            continue;  // Skip invalid characters
        }
        
        quad[quad_pos++] = c;
        
        if (quad_pos == 4) {
            if (j + 3 > max_output_len) break;
            output[j++] = (quad[0] << 2) | (quad[1] >> 4);
            output[j++] = (quad[1] << 4) | (quad[2] >> 2);
            output[j++] = (quad[2] << 6) | quad[3];
            quad_pos = 0;
        }
    }
    
    // Handle remaining bytes
    if (quad_pos >= 2 && j < max_output_len) {
        output[j++] = (quad[0] << 2) | (quad[1] >> 4);
        if (quad_pos >= 3 && j < max_output_len) {
            output[j++] = (quad[1] << 4) | (quad[2] >> 2);
        }
    }
    
    return j;
}

// Decode hex string
int hex_decode(const char *input, int input_len, unsigned char *output, int max_output_len) {
    int j = 0;
    for (int i = 0; i < input_len - 1 && j < max_output_len; i += 2) {
        unsigned char high = input[i];
        unsigned char low = input[i + 1];
        
        if (!is_hex_char(high) || !is_hex_char(low)) {
            continue;
        }
        
        high = (high >= '0' && high <= '9') ? high - '0' : 
               (high >= 'A' && high <= 'F') ? high - 'A' + 10 : 
               high - 'a' + 10;
        low = (low >= '0' && low <= '9') ? low - '0' : 
              (low >= 'A' && low <= 'F') ? low - 'A' + 10 : 
              low - 'a' + 10;
        
        output[j++] = (high << 4) | low;
    }
    return j;
}

// XOR decode with a single byte key
void xor_decode(const unsigned char *input, int input_len, unsigned char *output, unsigned char key) {
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key;
    }
}

// Case-insensitive string search
const char* stristr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    
    for (; *haystack; haystack++) {
        if (tolower(*haystack) == tolower(*needle)) {
            const char* h = haystack;
            const char* n = needle;
            while (*h && *n && tolower(*h) == tolower(*n)) {
                h++;
                n++;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}

// Check if decoded content is valid (mostly printable)
int is_valid_decoded(const unsigned char *data, int len) {
    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || 
            data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            printable_count++;
        }
    }
    // At least 70% should be printable for text data
    return (printable_count * 100 / len) >= 70;
}

// Search for plaintext
int search_plaintext(const char *line, const char *search_string, int case_sensitive,
                     const char *filepath, pthread_mutex_t *print_mutex, int *file_matches) {
    int found = 0;
    if (case_sensitive) {
        found = (strstr(line, search_string) != NULL);
    } else {
        found = (stristr(line, search_string) != NULL);
    }
    
    if (found) {
        pthread_mutex_lock(print_mutex);
        if (*file_matches == 0) {
            printf("\n📄 %s\n", filepath);
        }
        (*file_matches)++;
        printf("   [PLAINTEXT] Found: '%s'\n", search_string);
        printf("      Context: %.*s\n", 100, line);
        pthread_mutex_unlock(print_mutex);
        return 1;
    }
    return 0;
}

// Search for base64 encoded strings
int search_base64(const char *line, const char *search_string, int min_length,
                  int case_sensitive, const char *filepath, pthread_mutex_t *print_mutex,
                  int *file_matches) {
    const char *p = line;
    unsigned char decoded[MAX_LINE_LEN];
    char b64_candidate[MAX_LINE_LEN];
    int matches = 0;
    
    while (*p) {
        // Skip non-base64 characters
        while (*p && !is_base64_char(*p)) p++;
        if (!*p) break;
        
        // Extract potential base64 string (only valid base64 chars, no padding yet)
        int len = 0;
        const char *start = p;
        while (*p && is_base64_char(*p) && len < MAX_LINE_LEN - 3) {
            b64_candidate[len++] = *p++;
        }
        
        // Now check for optional padding (up to 2 '=' chars)
        int padding = 0;
        while (*p && is_base64_padding(*p) && padding < 2 && len < MAX_LINE_LEN - 1) {
            b64_candidate[len++] = *p++;
            padding++;
        }
        
        b64_candidate[len] = '\0';
        
        // Check minimum length
        if (len < min_length) continue;
        
        // Try to decode
        int decoded_len = base64_decode(b64_candidate, len, decoded, MAX_LINE_LEN - 1);
        if (decoded_len > 0 && is_valid_decoded(decoded, decoded_len)) {
            decoded[decoded_len] = '\0';
            
            // Search for the target string in decoded content
            const char *found_pos = NULL;
            if (case_sensitive) {
                found_pos = strstr((char*)decoded, search_string);
            } else {
                found_pos = stristr((char*)decoded, search_string);
            }
            
            if (found_pos) {
                pthread_mutex_lock(print_mutex);
                if (*file_matches == 0) {
                    printf("\n📄 %s\n", filepath);
                }
                (*file_matches)++;
                matches++;
                
                // Calculate offset of match in decoded content
                int offset = found_pos - (char*)decoded;
                
                printf("   [BASE64] Found '%s' in decoded content\n", search_string);
                printf("      Encoded:  ");
                print_escaped((unsigned char*)b64_candidate, len, 80);
                printf("\n");
                printf("      Decoded (from match): ");
                print_escaped((unsigned char*)found_pos, decoded_len - offset, 150);
                printf("\n");
                pthread_mutex_unlock(print_mutex);
            }
        }
    }
    
    return matches;
}

// Search for hex encoded strings
int search_hex(const char *line, const char *search_string, int min_length,
               int case_sensitive, const char *filepath, pthread_mutex_t *print_mutex,
               int *file_matches) {
    const char *p = line;
    unsigned char decoded[MAX_LINE_LEN];
    char hex_candidate[MAX_LINE_LEN];
    int matches = 0;
    
    while (*p) {
        // Skip non-hex characters
        while (*p && !is_hex_char(*p)) p++;
        if (!*p) break;
        
        // Extract potential hex string (must be even length)
        int len = 0;
        const char *start = p;
        while (*p && is_hex_char(*p) && len < MAX_LINE_LEN - 1) {
            hex_candidate[len++] = *p++;
        }
        hex_candidate[len] = '\0';
        
        // Hex strings must be even length and meet minimum
        if (len < min_length || len % 2 != 0) continue;
        
        // Try to decode
        int decoded_len = hex_decode(hex_candidate, len, decoded, MAX_LINE_LEN - 1);
        if (decoded_len > 0 && is_valid_decoded(decoded, decoded_len)) {
            decoded[decoded_len] = '\0';
            
            // Search for the target string in decoded content
            const char *found_pos = NULL;
            if (case_sensitive) {
                found_pos = strstr((char*)decoded, search_string);
            } else {
                found_pos = stristr((char*)decoded, search_string);
            }
            
            if (found_pos) {
                pthread_mutex_lock(print_mutex);
                if (*file_matches == 0) {
                    printf("\n📄 %s\n", filepath);
                }
                (*file_matches)++;
                matches++;
                
                // Calculate offset of match in decoded content
                int offset = found_pos - (char*)decoded;
                
                printf("   [HEX] Found '%s' in decoded content\n", search_string);
                printf("      Encoded:  ");
                print_hex((unsigned char*)hex_candidate, len, 160);
                printf("\n");
                printf("      Decoded (from match): ");
                print_escaped((unsigned char*)found_pos, decoded_len - offset, 150);
                printf("\n");
                pthread_mutex_unlock(print_mutex);
            }
        }
    }
    
    return matches;
}

// Search for XOR encoded strings (try all 256 possible keys)
int search_xor(const char *line, const char *search_string, int min_length,
               int case_sensitive, const char *filepath, pthread_mutex_t *print_mutex,
               int *file_matches) {
    int line_len = strlen(line);
    if (line_len < min_length) return 0;
    
    unsigned char decoded[MAX_LINE_LEN];
    int matches = 0;
    
    // Try all possible XOR keys (0-255)
    for (int key = 1; key < 256; key++) {  // Skip key=0 (plaintext)
        xor_decode((unsigned char*)line, line_len, decoded, key);
        decoded[line_len] = '\0';
        
        // Only check if result looks like valid text
        if (!is_valid_decoded(decoded, line_len)) continue;
        
        // Search for the target string in decoded content
        const char *found_pos = NULL;
        if (case_sensitive) {
            found_pos = strstr((char*)decoded, search_string);
        } else {
            found_pos = stristr((char*)decoded, search_string);
        }
        
        if (found_pos) {
            pthread_mutex_lock(print_mutex);
            if (*file_matches == 0) {
                printf("\n📄 %s\n", filepath);
            }
            (*file_matches)++;
            matches++;
            
            // Calculate offset of match in decoded content
            int offset = found_pos - (char*)decoded;
            
            printf("   [XOR] Found '%s' with XOR key 0x%02x (%d)\n", search_string, key, key);
            printf("      Encoded:  ");
            print_escaped((unsigned char*)line, line_len, 80);
            printf("\n");
            printf("      Decoded (from match): ");
            print_escaped((unsigned char*)found_pos, line_len - offset, 150);
            printf("\n");
            pthread_mutex_unlock(print_mutex);
        }
    }
    
    return matches;
}

// Search all encoding types in a line
int search_line_all_encodings(const char *line, const char *search_string, int min_length,
                               int case_sensitive, const char *filepath, 
                               pthread_mutex_t *print_mutex, int *file_matches) {
    int matches = 0;
    
    // Search plaintext
    matches += search_plaintext(line, search_string, case_sensitive, filepath, print_mutex, file_matches);
    
    // Search base64
    matches += search_base64(line, search_string, min_length, case_sensitive, filepath, print_mutex, file_matches);
    
    // Search hex
    matches += search_hex(line, search_string, min_length, case_sensitive, filepath, print_mutex, file_matches);
    
    // Search XOR (only if line is long enough and not too long to avoid performance issues)
    if (strlen(line) >= min_length && strlen(line) < 10000) {
        matches += search_xor(line, search_string, min_length, case_sensitive, filepath, print_mutex, file_matches);
    }
    
    return matches;
}

// Process a single file
int process_file(const char *filepath, const char *search_string, int min_length,
                 int case_sensitive, pthread_mutex_t *print_mutex) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return 0;
    
    int file_matches = 0;
    char *line = malloc(MAX_LINE_LEN);
    if (!line) {
        fclose(fp);
        return 0;
    }
    
    while (fgets(line, MAX_LINE_LEN, fp)) {
        search_line_all_encodings(line, search_string, min_length, case_sensitive,
                                 filepath, print_mutex, &file_matches);
    }
    
    if (file_matches > 0) {
        pthread_mutex_lock(print_mutex);
        printf("   Total matches in file: %d\n", file_matches);
        pthread_mutex_unlock(print_mutex);
    }
    
    free(line);
    fclose(fp);
    return file_matches;
}

// Check if file should be skipped
int should_skip_file(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    
    const char *skip_exts[] = {
        ".pyc", ".exe", ".dll", ".so", ".dylib",
        ".jpg", ".jpeg", ".png", ".gif", ".pdf",
        ".zip", ".tar", ".gz", ".bz2", ".xz",
        ".mp3", ".mp4", ".avi", ".mov", ".bin",
        NULL
    };
    
    for (int i = 0; skip_exts[i]; i++) {
        if (strcasecmp(ext, skip_exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Queue operations
void queue_init(TaskQueue *q) {
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->done = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void queue_push(TaskQueue *q, const char *path) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count >= QUEUE_SIZE) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }
    
    strncpy(q->tasks[q->tail].path, path, MAX_PATH_LEN - 1);
    q->tasks[q->tail].path[MAX_PATH_LEN - 1] = '\0';
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

int queue_pop(TaskQueue *q, FileTask *task) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count == 0 && !q->done) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    
    if (q->count == 0 && q->done) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    
    *task = q->tasks[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

void queue_finish(TaskQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->done = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

// Worker thread function
void* worker_thread(void *arg) {
    ThreadArgs *args = (ThreadArgs*)arg;
    FileTask task;
    int local_matches = 0;
    
    while (queue_pop(args->queue, &task)) {
        int matches = process_file(task.path, args->search_string, args->min_length,
                                   args->case_sensitive, args->print_mutex);
        local_matches += (matches > 0 ? 1 : 0);  // Count files with matches
    }
    
    pthread_mutex_lock(args->print_mutex);
    *args->match_count += local_matches;
    pthread_mutex_unlock(args->print_mutex);
    
    return NULL;
}

// Recursively scan directory and add files to queue
void scan_directory(const char *dirpath, TaskQueue *queue) {
    DIR *dir = opendir(dirpath);
    if (!dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        
        struct stat st;
        if (stat(fullpath, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            scan_directory(fullpath, queue);
        } else if (S_ISREG(st.st_mode)) {
            // if (!should_skip_file(fullpath)) {
                queue_push(queue, fullpath);
            // }
        }
    }
    
    closedir(dir);
}

void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] <directory> <search_string>\n\n", progname);
    printf("Search for a string in multiple encodings: plaintext, base64, hex, and XOR.\n\n");
    printf("Options:\n");
    printf("  -m <length>     Minimum encoded string length (default: 8)\n");
    printf("  -i              Case-insensitive search\n");
    printf("  -t <threads>    Number of threads (default: CPU cores, max: %d)\n", MAX_THREADS);
    printf("  -h              Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s /path/to/search \"password\"\n", progname);
    printf("  %s -i -m 4 . \"api_key\"\n", progname);
    printf("  %s -t 8 /var/log \"secret\"\n", progname);
}

int main(int argc, char *argv[]) {
    int min_length = 8;
    int case_sensitive = 1;
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (num_threads < 1) num_threads = 1;
    
    // Parse options
    int opt;
    while ((opt = getopt(argc, argv, "m:it:h")) != -1) {
        switch (opt) {
            case 'm':
                min_length = atoi(optarg);
                if (min_length < 4) min_length = 4;
                break;
            case 'i':
                case_sensitive = 0;
                break;
            case 't':
                num_threads = atoi(optarg);
                if (num_threads < 1) num_threads = 1;
                if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind + 2 != argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *directory = argv[optind];
    const char *search_string = argv[optind + 1];
    
    printf("Multi-Encoding Search Tool\n");
    printf("Searching for: '%s'\n", search_string);
    printf("Directory: %s\n", directory);
    printf("Encodings: PLAINTEXT, BASE64, HEX, XOR (1-byte)\n");
    printf("Minimum encoded length: %d\n", min_length);
    printf("Case sensitive: %s\n", case_sensitive ? "Yes" : "No");
    printf("Threads: %d\n", num_threads);
    printf("================================================================================\n");
    
    // Initialize task queue
    queue_init(&task_queue);
    
    // Create worker threads
    pthread_t threads[MAX_THREADS];
    ThreadArgs thread_args = {
        .search_string = search_string,
        .min_length = min_length,
        .case_sensitive = case_sensitive,
        .verbose = 1,
        .queue = &task_queue,
        .match_count = &total_matches,
        .print_mutex = &print_mutex
    };
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &thread_args);
    }
    
    // Scan directory and populate queue
    scan_directory(directory, &task_queue);
    queue_finish(&task_queue);
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n");
    printf("================================================================================\n");
    if (total_matches == 0) {
        printf("No matches found.\n");
    } else {
        printf("Search complete. Files with matches: %d\n", total_matches);
    }
    
    return 0;
}

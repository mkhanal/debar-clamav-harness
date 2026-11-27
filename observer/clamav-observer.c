#include <clamav.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REPORT_SCHEMA_VERSION 1
#define DEFAULT_DATABASE_DIRECTORY "/var/lib/clamav"
#define CLAMSCAN_DEFAULT_CERTIFICATE_DIRECTORY "/etc/clamav/certs"
#define SCANNER_NAME "ClamAV"
#define SHA256_ALGORITHM "sha2-256"
#define EXIT_OBSERVATION_FAILED 2

#define CLAMSCAN_DEFAULT_PARSERS                                                                \
    (CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_SWF |       \
     CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_OLE2 |    \
     CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE | CL_SCAN_PARSE_ONENOTE | CL_SCAN_PARSE_IMAGE |     \
     CL_SCAN_PARSE_IMAGE_FUZZY_HASH)

struct name_list {
    const char **names;
    size_t count;
    size_t capacity;
};

struct observed_object {
    bool reached;
    uint64_t id;
    bool has_parent;
    uint64_t parent_id;
    uint32_t depth;
    char *type;
    size_t size;
    char *sha256;
    struct name_list detections;
    const char *last_alert_when_scanned;
};

struct id_list {
    uint64_t *ids;
    size_t count;
    size_t capacity;
};

struct scan_observation {
    struct observed_object *objects_by_id;
    size_t object_slots;
    struct id_list reached_order;
    struct id_list scanned_order;
    struct name_list alerts_awaiting_layer;
    bool out_of_memory;
};

struct database_version {
    char *name;
    unsigned int version;
};

struct database_versions {
    struct database_version *databases;
    size_t count;
};

static bool grow_to_hold(void **items, size_t *capacity, size_t needed, size_t item_size)
{
    if (needed <= *capacity) {
        return true;
    }
    size_t grown = *capacity == 0 ? 16 : *capacity;
    while (grown < needed) {
        grown *= 2;
    }
    void *moved = realloc(*items, grown * item_size);
    if (moved == NULL) {
        return false;
    }
    memset((char *)moved + (*capacity * item_size), 0, (grown - *capacity) * item_size);
    *items    = moved;
    *capacity = grown;
    return true;
}

static bool append_name(struct name_list *list, const char *name)
{
    if (!grow_to_hold((void **)&list->names, &list->capacity, list->count + 1, sizeof(*list->names))) {
        return false;
    }
    list->names[list->count++] = name;
    return true;
}

static bool append_id(struct id_list *list, uint64_t id)
{
    if (!grow_to_hold((void **)&list->ids, &list->capacity, list->count + 1, sizeof(*list->ids))) {
        return false;
    }
    list->ids[list->count++] = id;
    return true;
}

static struct observed_object *object_slot(struct scan_observation *observation, uint64_t id)
{
    if (id >= SIZE_MAX) {
        return NULL;
    }
    if (!grow_to_hold((void **)&observation->objects_by_id, &observation->object_slots, (size_t)id + 1,
                      sizeof(*observation->objects_by_id))) {
        return NULL;
    }
    return &observation->objects_by_id[id];
}

static struct observed_object *reached_object(struct scan_observation *observation, uint64_t id)
{
    if (id >= observation->object_slots || !observation->objects_by_id[id].reached) {
        return NULL;
    }
    return &observation->objects_by_id[id];
}

static struct observed_object *nearest_reached_layer(struct scan_observation *observation, cl_scan_layer_t *layer)
{
    while (layer != NULL) {
        uint64_t id = 0;
        if (cl_scan_layer_get_object_id(layer, &id) == CL_SUCCESS) {
            struct observed_object *object = reached_object(observation, id);
            if (object != NULL) {
                return object;
            }
        }
        cl_scan_layer_t *parent = NULL;
        if (cl_scan_layer_get_parent_layer(layer, &parent) != CL_SUCCESS) {
            return NULL;
        }
        layer = parent;
    }
    return NULL;
}

static bool replace_type(struct observed_object *object, cl_scan_layer_t *layer)
{
    const char *type = NULL;
    if (cl_scan_layer_get_type(layer, &type) != CL_SUCCESS || type == NULL) {
        return true;
    }
    char *copy = strdup(type);
    if (copy == NULL) {
        return false;
    }
    free(object->type);
    object->type = copy;
    return true;
}

static bool record_reached_layer(struct scan_observation *observation, cl_scan_layer_t *layer, uint64_t id)
{
    cl_scan_layer_t *parent_layer = NULL;
    if (cl_scan_layer_get_parent_layer(layer, &parent_layer) != CL_SUCCESS) {
        return false;
    }
    struct observed_object *parent = nearest_reached_layer(observation, parent_layer);
    bool has_parent                = parent != NULL;
    uint64_t parent_id             = has_parent ? parent->id : 0;

    struct observed_object *object = object_slot(observation, id);
    if (object == NULL) {
        return false;
    }
    object->id         = id;
    object->has_parent = has_parent;
    object->parent_id  = parent_id;

    cl_fmap_t *map = NULL;
    if (cl_scan_layer_get_recursion_level(layer, &object->depth) != CL_SUCCESS ||
        cl_scan_layer_get_fmap(layer, &map) != CL_SUCCESS ||
        cl_fmap_get_size(map, &object->size) != CL_SUCCESS ||
        cl_fmap_get_hash(map, SHA256_ALGORITHM, &object->sha256) != CL_SUCCESS) {
        return false;
    }
    object->reached = true;
    return append_id(&observation->reached_order, id);
}

static cl_error_t on_file_type(cl_scan_layer_t *layer, void *context)
{
    struct scan_observation *observation = context;
    uint64_t id                          = 0;
    if (cl_scan_layer_get_object_id(layer, &id) != CL_SUCCESS) {
        observation->out_of_memory = true;
        return CL_BREAK;
    }
    if (reached_object(observation, id) == NULL && !record_reached_layer(observation, layer, id)) {
        observation->out_of_memory = true;
        return CL_BREAK;
    }
    if (!replace_type(reached_object(observation, id), layer)) {
        observation->out_of_memory = true;
        return CL_BREAK;
    }
    return CL_SUCCESS;
}

static cl_error_t on_post_scan(cl_scan_layer_t *layer, void *context)
{
    struct scan_observation *observation = context;
    uint64_t id                          = 0;
    if (cl_scan_layer_get_object_id(layer, &id) != CL_SUCCESS) {
        return CL_SUCCESS;
    }
    struct observed_object *object = reached_object(observation, id);
    if (object == NULL) {
        return CL_SUCCESS;
    }
    if (!replace_type(object, layer) || !append_id(&observation->scanned_order, id)) {
        observation->out_of_memory = true;
        return CL_BREAK;
    }
    (void)cl_scan_layer_get_last_alert(layer, &object->last_alert_when_scanned);
    return CL_SUCCESS;
}

static void on_signature_found(int descriptor, const char *signature_name, void *context)
{
    (void)descriptor;
    struct scan_observation *observation = context;
    if (!append_name(&observation->alerts_awaiting_layer, signature_name)) {
        observation->out_of_memory = true;
    }
}

static cl_error_t on_alert(cl_scan_layer_t *layer, void *context)
{
    struct scan_observation *observation = context;
    struct name_list *awaiting           = &observation->alerts_awaiting_layer;
    const char *signature_name           = NULL;
    if (awaiting->count > 0) {
        signature_name = awaiting->names[--awaiting->count];
    } else {
        (void)cl_scan_layer_get_last_alert(layer, &signature_name);
    }
    struct observed_object *object = nearest_reached_layer(observation, layer);
    if (signature_name != NULL && object != NULL && !append_name(&object->detections, signature_name)) {
        observation->out_of_memory = true;
    }
    return CL_VIRUS;
}

static struct observed_object *top_level_object(struct scan_observation *observation)
{
    if (observation->reached_order.count == 0) {
        return NULL;
    }
    return reached_object(observation, observation->reached_order.ids[0]);
}

static struct observed_object *deepest_object_last_alerting(struct scan_observation *observation, const char *name)
{
    for (size_t index = 0; index < observation->scanned_order.count; index++) {
        struct observed_object *object = reached_object(observation, observation->scanned_order.ids[index]);
        if (object != NULL && object->last_alert_when_scanned != NULL &&
            strcmp(object->last_alert_when_scanned, name) == 0) {
            return object;
        }
    }
    return NULL;
}

static bool attribute_alerts_reported_after_scan(struct scan_observation *observation)
{
    struct observed_object *top_level = top_level_object(observation);
    for (size_t index = 0; index < observation->alerts_awaiting_layer.count; index++) {
        const char *name               = observation->alerts_awaiting_layer.names[index];
        struct observed_object *object = deepest_object_last_alerting(observation, name);
        if (object == NULL) {
            object = top_level;
        }
        if (object != NULL && !append_name(&object->detections, name)) {
            return false;
        }
    }
    observation->alerts_awaiting_layer.count = 0;
    return true;
}

static char *sha256_of_descriptor(int descriptor)
{
    if (lseek(descriptor, 0, SEEK_SET) != 0) {
        return NULL;
    }
    unsigned int digest_length = 0;
    unsigned char *digest      = cl_hash_file_fd(descriptor, "sha256", &digest_length);
    if (digest == NULL) {
        return NULL;
    }
    char *hex = malloc((size_t)digest_length * 2 + 1);
    if (hex != NULL) {
        for (unsigned int index = 0; index < digest_length; index++) {
            snprintf(hex + index * 2, 3, "%02x", digest[index]);
        }
    }
    free(digest);
    return hex;
}

static bool record_unreached_top_level(struct scan_observation *observation, int descriptor, const char *type)
{
    struct stat status;
    if (fstat(descriptor, &status) != 0) {
        return false;
    }
    struct observed_object *object = object_slot(observation, 0);
    if (object == NULL) {
        return false;
    }
    object->id         = 0;
    object->has_parent = false;
    object->depth      = 0;
    object->size       = (size_t)status.st_size;
    object->type       = type != NULL ? strdup(type) : NULL;
    object->sha256     = sha256_of_descriptor(descriptor);
    if (object->sha256 == NULL || (type != NULL && object->type == NULL)) {
        return false;
    }
    object->reached = true;
    return append_id(&observation->reached_order, 0);
}

static void write_json_string(FILE *report, const char *text)
{
    fputc('"', report);
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; cursor++) {
        if (*cursor == '"' || *cursor == '\\') {
            fprintf(report, "\\%c", *cursor);
        } else if (*cursor < 0x20) {
            fprintf(report, "\\u%04x", *cursor);
        } else {
            fputc(*cursor, report);
        }
    }
    fputc('"', report);
}

static const char *verdict_name(cl_verdict_t verdict)
{
    switch (verdict) {
        case CL_VERDICT_NOTHING_FOUND:
            return "nothing_found";
        case CL_VERDICT_TRUSTED:
            return "trusted";
        case CL_VERDICT_STRONG_INDICATOR:
            return "strong_indicator";
        case CL_VERDICT_POTENTIALLY_UNWANTED:
            return "potentially_unwanted";
    }
    return NULL;
}

static void write_scanner(FILE *report, const struct database_versions *databases)
{
    fputs(",\"scanner\":{\"name\":", report);
    write_json_string(report, SCANNER_NAME);
    fputs(",\"version\":", report);
    write_json_string(report, cl_retver());
    fputs(",\"databases\":[", report);
    for (size_t index = 0; index < databases->count; index++) {
        fputs(index == 0 ? "{\"name\":" : ",{\"name\":", report);
        write_json_string(report, databases->databases[index].name);
        fprintf(report, ",\"version\":%u}", databases->databases[index].version);
    }
    fputs("]}", report);
}

static void write_object(FILE *report, const struct observed_object *object, const char *verdict,
                         const struct database_versions *databases)
{
    fprintf(report, "{\"schema\":%d,\"id\":%" PRIu64 ",\"parent\":", REPORT_SCHEMA_VERSION, object->id);
    if (object->has_parent) {
        fprintf(report, "%" PRIu64, object->parent_id);
    } else {
        fputs("null", report);
    }
    fprintf(report, ",\"depth\":%" PRIu32 ",\"type\":", object->depth);
    if (object->type != NULL) {
        write_json_string(report, object->type);
    } else {
        fputs("null", report);
    }
    fprintf(report, ",\"size\":%zu,\"sha256\":", object->size);
    write_json_string(report, object->sha256);
    fputs(",\"detections\":[", report);
    for (size_t index = 0; index < object->detections.count; index++) {
        if (index > 0) {
            fputc(',', report);
        }
        write_json_string(report, object->detections.names[index]);
    }
    fputc(']', report);
    if (verdict != NULL) {
        fputs(",\"verdict\":", report);
        write_json_string(report, verdict);
        write_scanner(report, databases);
    }
    fputs("}\n", report);
}

static bool write_report(const char *report_path, struct scan_observation *observation, cl_verdict_t verdict,
                         const struct database_versions *databases)
{
    const char *verdict_text = verdict_name(verdict);
    FILE *report             = fopen(report_path, "w");
    if (report == NULL || verdict_text == NULL) {
        fprintf(stderr, "clamav-observer: cannot write %s: %s\n", report_path, strerror(errno));
        if (report != NULL) {
            fclose(report);
        }
        return false;
    }
    for (size_t index = 0; index < observation->reached_order.count; index++) {
        const struct observed_object *object = reached_object(observation, observation->reached_order.ids[index]);
        write_object(report, object, index == 0 ? verdict_text : NULL, databases);
    }
    bool written = !ferror(report);
    return fclose(report) == 0 && written;
}

static void release_observation(struct scan_observation *observation)
{
    for (size_t index = 0; index < observation->object_slots; index++) {
        free(observation->objects_by_id[index].type);
        free(observation->objects_by_id[index].sha256);
        free(observation->objects_by_id[index].detections.names);
    }
    free(observation->objects_by_id);
    free(observation->reached_order.ids);
    free(observation->scanned_order.ids);
    free(observation->alerts_awaiting_layer.names);
    memset(observation, 0, sizeof(*observation));
}

static bool observe_one_input(struct cl_engine *engine, const char *input_path, const char *report_path,
                              const struct database_versions *databases, bool every_match)
{
    struct cl_scan_options clamscan_defaults = {
        .general   = (every_match ? CL_SCAN_GENERAL_ALLMATCHES : 0) | CL_SCAN_GENERAL_HEURISTICS,
        .parse     = CLAMSCAN_DEFAULT_PARSERS,
        .heuristic = 0,
        .mail      = 0,
        .dev       = 0,
    };
    struct scan_observation observation = {0};
    cl_verdict_t verdict                = CL_VERDICT_NOTHING_FOUND;
    const char *last_alert              = NULL;
    uint64_t bytes_scanned              = 0;
    char *top_level_type                = NULL;
    bool observed                       = false;

    int descriptor = open(input_path, O_RDONLY);
    if (descriptor < 0) {
        fprintf(stderr, "clamav-observer: cannot open %s: %s\n", input_path, strerror(errno));
        return false;
    }
    cl_error_t scan_result = cl_scandesc_ex(descriptor, input_path, &verdict, &last_alert, &bytes_scanned, engine,
                                            &clamscan_defaults, &observation, NULL, NULL, NULL, NULL,
                                            &top_level_type);
    bool scanned = scan_result == CL_SUCCESS || (scan_result == CL_VIRUS && verdict != CL_VERDICT_NOTHING_FOUND);
    if (!scanned) {
        fprintf(stderr, "clamav-observer: scanning %s failed: %s\n", input_path, cl_strerror(scan_result));
    } else if (observation.out_of_memory) {
        fprintf(stderr, "clamav-observer: ran out of memory recording %s\n", input_path);
    } else if (top_level_object(&observation) == NULL &&
               !record_unreached_top_level(&observation, descriptor, top_level_type)) {
        fprintf(stderr, "clamav-observer: cannot record the unscanned top-level object of %s\n", input_path);
    } else if (!attribute_alerts_reported_after_scan(&observation)) {
        fprintf(stderr, "clamav-observer: ran out of memory recording %s\n", input_path);
    } else {
        observed = write_report(report_path, &observation, verdict, databases);
    }
    free(top_level_type);
    close(descriptor);
    release_observation(&observation);
    return observed;
}

static bool is_signed_database_container(const char *file_name)
{
    size_t length = strlen(file_name);
    return length > 4 && (strcmp(file_name + length - 4, ".cvd") == 0 || strcmp(file_name + length - 4, ".cld") == 0);
}

static int by_database_name(const void *left, const void *right)
{
    return strcmp(((const struct database_version *)left)->name, ((const struct database_version *)right)->name);
}

static bool read_database_versions(const char *directory_path, struct database_versions *versions)
{
    DIR *directory = opendir(directory_path);
    if (directory == NULL) {
        fprintf(stderr, "clamav-observer: cannot list %s: %s\n", directory_path, strerror(errno));
        return false;
    }
    size_t capacity = 0;
    bool complete   = true;
    for (struct dirent *entry = readdir(directory); entry != NULL && complete; entry = readdir(directory)) {
        if (!is_signed_database_container(entry->d_name)) {
            continue;
        }
        char path[4096];
        int length = snprintf(path, sizeof(path), "%s/%s", directory_path, entry->d_name);
        struct cl_cvd *header = length > 0 && (size_t)length < sizeof(path) ? cl_cvdhead(path) : NULL;
        if (header == NULL ||
            !grow_to_hold((void **)&versions->databases, &capacity, versions->count + 1, sizeof(*versions->databases))) {
            fprintf(stderr, "clamav-observer: cannot read the header of %s/%s\n", directory_path, entry->d_name);
            complete = false;
        } else {
            struct database_version *database = &versions->databases[versions->count++];
            database->name    = strndup(entry->d_name, strlen(entry->d_name) - 4);
            database->version = header->version;
            complete          = database->name != NULL;
        }
        if (header != NULL) {
            cl_cvdfree(header);
        }
    }
    closedir(directory);
    qsort(versions->databases, versions->count, sizeof(*versions->databases), by_database_name);
    return complete;
}

static struct cl_engine *engine_with_official_databases(const char *database_directory)
{
    struct cl_engine *engine = cl_engine_new();
    unsigned int signatures  = 0;
    cl_error_t result        = CL_EMEM;
    if (engine == NULL ||
        (result = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, CLAMSCAN_DEFAULT_CERTIFICATE_DIRECTORY)) != CL_SUCCESS ||
        (result = cl_load(database_directory, engine, &signatures, CL_DB_STDOPT)) != CL_SUCCESS ||
        (result = cl_engine_compile(engine)) != CL_SUCCESS) {
        fprintf(stderr, "clamav-observer: cannot load %s: %s\n", database_directory, cl_strerror(result));
        if (engine != NULL) {
            cl_engine_free(engine);
        }
        return NULL;
    }
    cl_engine_set_scan_callback(engine, on_file_type, CL_SCAN_CALLBACK_FILE_TYPE);
    cl_engine_set_scan_callback(engine, on_post_scan, CL_SCAN_CALLBACK_POST_SCAN);
    cl_engine_set_scan_callback(engine, on_alert, CL_SCAN_CALLBACK_ALERT);
    cl_engine_set_clcb_virus_found(engine, on_signature_found);
    return engine;
}

static int usage(void)
{
    fputs("usage: clamav-observer [--databases DIRECTORY] [--first-match] INPUT REPORT [INPUT REPORT]...\n", stderr);
    return EXIT_OBSERVATION_FAILED;
}

int main(int argument_count, char **arguments)
{
    const char *database_directory = DEFAULT_DATABASE_DIRECTORY;
    int first_pair                 = 1;
    if (argument_count > 2 && strcmp(arguments[1], "--databases") == 0) {
        database_directory = arguments[2];
        first_pair         = 3;
    }
    bool every_match = true;
    if (argument_count > first_pair && strcmp(arguments[first_pair], "--first-match") == 0) {
        every_match = false;
        first_pair++;
    }
    int remaining = argument_count - first_pair;
    if (remaining < 2 || remaining % 2 != 0) {
        return usage();
    }

    cl_error_t initialised = cl_init(CL_INIT_DEFAULT);
    if (initialised != CL_SUCCESS) {
        fprintf(stderr, "clamav-observer: cannot initialise libclamav: %s\n", cl_strerror(initialised));
        return EXIT_OBSERVATION_FAILED;
    }
    struct database_versions databases = {0};
    if (!read_database_versions(database_directory, &databases)) {
        return EXIT_OBSERVATION_FAILED;
    }
    struct cl_engine *engine = engine_with_official_databases(database_directory);
    if (engine == NULL) {
        return EXIT_OBSERVATION_FAILED;
    }

    bool every_input_observed = true;
    for (int index = first_pair; index + 1 < argument_count; index += 2) {
        every_input_observed = observe_one_input(engine, arguments[index], arguments[index + 1], &databases, every_match) &&
                               every_input_observed;
    }
    cl_engine_free(engine);
    return every_input_observed ? EXIT_SUCCESS : EXIT_OBSERVATION_FAILED;
}

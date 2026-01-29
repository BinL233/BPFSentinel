/* Minimal cJSON implementation (subset) placed in utils/ */
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *skip_ws(const char *p) { while (p && *p && isspace((unsigned char)*p)) p++; return p; }
static cJSON *cjson_new_item(void) { return (cJSON*)calloc(1, sizeof(cJSON)); }
static const char *parse_value(cJSON *item, const char *p);
static const char *parse_string(cJSON *item, const char *p);
static const char *parse_number(cJSON *item, const char *p);
static const char *parse_array(cJSON *item, const char *p);
static const char *parse_object(cJSON *item, const char *p);

static void cjson_free_chain(cJSON *item) {
    while (item) {
        cJSON *next = item->next;
        if (item->child) cjson_free_chain(item->child);
        free(item->valuestring);
        free(item->string);
        free(item);
        item = next;
    }
}

void cJSON_Delete(cJSON *c) { cjson_free_chain(c); }

cJSON *cJSON_Parse(const char *value) {
    const char *p = skip_ws(value);
    if (!p) return NULL;
    cJSON *root = cjson_new_item();
    if (!root) return NULL;
    p = parse_value(root, p);
    if (!p) { cJSON_Delete(root); return NULL; }
    return root;
}

static const char *parse_value(cJSON *item, const char *p) {
    p = skip_ws(p);
    if (!p || !*p) return NULL;
    if (*p == '"') return parse_string(item, p);
    if (*p == '-' || (*p >= '0' && *p <= '9')) return parse_number(item, p);
    if (*p == '{') return parse_object(item, p);
    if (*p == '[') return parse_array(item, p);
    if (!strncmp(p, "true", 4)) { item->type = cJSON_True; return p+4; }
    if (!strncmp(p, "false", 5)) { item->type = cJSON_False; return p+5; }
    if (!strncmp(p, "null", 4)) { item->type = cJSON_NULL; return p+4; }
    return NULL;
}

static char *strdup_range(const char *start, const char *end) {
    size_t n = (size_t)(end - start);
    char *s = (char*)malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, start, n);
    s[n] = '\0';
    return s;
}

static const char *parse_string(cJSON *item, const char *p) {
    if (*p != '"') return NULL;
    const char *start = ++p;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        p++;
    }
    if (*p != '"') return NULL;
    item->type = cJSON_String;
    item->valuestring = strdup_range(start, p);
    return p+1;
}

static const char *parse_number(cJSON *item, const char *p) {
    char *endptr;
    item->valuedouble = strtod(p, &endptr);
    item->valueint = (int)item->valuedouble;
    item->type = cJSON_Number;
    return endptr;
}

static void add_item_to_array(cJSON *array, cJSON *item) {
    if (!array->child) {
        array->child = item;
    } else {
        cJSON *c = array->child;
        while (c->next) c = c->next;
        c->next = item;
        item->prev = c;
    }
}

static const char *parse_array(cJSON *item, const char *p) {
    if (*p != '[') return NULL;
    item->type = cJSON_Array;
    p = skip_ws(p+1);
    if (*p == ']') return p+1; /* empty */
    do {
        cJSON *child = cjson_new_item();
        if (!child) return NULL;
        p = parse_value(child, p);
        if (!p) return NULL;
        add_item_to_array(item, child);
        p = skip_ws(p);
        if (*p == ']') return p+1;
        if (*p != ',') return NULL;
        p = skip_ws(p+1);
    } while (*p);
    return NULL;
}

static void add_item_to_object(cJSON *object, cJSON *item) {
    if (!object->child) {
        object->child = item;
    } else {
        cJSON *c = object->child;
        while (c->next) c = c->next;
        c->next = item;
        item->prev = c;
    }
}

static const char *parse_object(cJSON *item, const char *p) {
    if (*p != '{') return NULL;
    item->type = cJSON_Object;
    p = skip_ws(p+1);
    if (*p == '}') return p+1; /* empty */
    do {
        cJSON *key = cjson_new_item();
        if (!key) return NULL;
        p = parse_string(key, p);
        if (!p) return NULL;
        p = skip_ws(p);
        if (*p != ':') return NULL;
        p = skip_ws(p+1);
        cJSON *value = cjson_new_item();
        if (!value) return NULL;
        value->string = key->valuestring; /* steal string */
        key->valuestring = NULL;
        p = parse_value(value, p);
        if (!p) return NULL;
        add_item_to_object(item, value);
        cJSON_Delete(key);
        p = skip_ws(p);
        if (*p == '}') return p+1;
        if (*p != ',') return NULL;
        p = skip_ws(p+1);
    } while (*p);
    return NULL;
}

int cJSON_IsArray(const cJSON * const item) { return item && (item->type & cJSON_Array); }
int cJSON_IsObject(const cJSON * const item) { return item && (item->type & cJSON_Object); }
int cJSON_IsString(const cJSON * const item) { return item && (item->type & cJSON_String); }

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) {
    if (!object || !cJSON_IsObject(object)) return NULL;
    cJSON *c = object->child;
    while (c) {
        if (c->string && string && strcmp(c->string, string) == 0) return c;
        c = c->next;
    }
    return NULL;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index) {
    if (!array || !cJSON_IsArray(array)) return NULL;
    cJSON *c = array->child;
    while (c && index > 0) { c = c->next; index--; }
    return c;
}

int cJSON_GetArraySize(const cJSON *array) {
    if (!array || !cJSON_IsArray(array)) return 0;
    int n = 0; cJSON *c = array->child; while (c) { n++; c = c->next; }
    return n;
}

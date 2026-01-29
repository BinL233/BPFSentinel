/* Minimal cJSON header (subset) placed in utils/ */
#ifndef CJSON__H
#define CJSON__H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct cJSON {
    struct cJSON *next;
    struct cJSON *prev;
    struct cJSON *child;
    int type;
    char *valuestring;
    int valueint;
    double valuedouble;
    char *string;
} cJSON;

/* cJSON Types: */
#define cJSON_False  (1 << 0)
#define cJSON_True   (1 << 1)
#define cJSON_NULL   (1 << 2)
#define cJSON_Number (1 << 3)
#define cJSON_String (1 << 4)
#define cJSON_Array  (1 << 5)
#define cJSON_Object (1 << 6)

/* Basic API */
extern cJSON *cJSON_Parse(const char *value);
extern void cJSON_Delete(cJSON *c);
extern int cJSON_IsArray(const cJSON * const item);
extern int cJSON_IsObject(const cJSON * const item);
extern cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string);
extern cJSON *cJSON_GetArrayItem(const cJSON *array, int index);
extern int cJSON_GetArraySize(const cJSON *array);
extern int cJSON_IsString(const cJSON * const item);

#ifdef __cplusplus
}
#endif

#endif /* CJSON__H */

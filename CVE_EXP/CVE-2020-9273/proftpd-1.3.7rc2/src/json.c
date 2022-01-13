/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017-2018 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* JSON implementation (pool-based wrapper around CCAN JSON) */

#include "json.h"
#include "ccan-json.h"

struct json_list_st {
  pool *pool;
  JsonNode *array;
  unsigned int item_count;
};

struct json_obj_st {
  pool *pool;
  JsonNode *object;
  unsigned int member_count;
};

static const char *trace_channel = "json";

static pr_json_array_t *alloc_array(pool *p) {
  pool *sub_pool;
  pr_json_array_t *json;

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "JSON Array Pool");

  json = pcalloc(sub_pool, sizeof(pr_json_array_t));
  json->pool = sub_pool;

  return json;
}

static pr_json_object_t *alloc_object(pool *p) {
  pool *sub_pool;
  pr_json_object_t *json;

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "JSON Object Pool");

  json = pcalloc(sub_pool, sizeof(pr_json_object_t));
  json->pool = sub_pool;

  return json;
}

static unsigned int get_count(JsonNode *json) {
  unsigned int count;
  JsonNode *node;

  for (count = 0, node = json_first_child(json);
       node != NULL;
       node = node->next) {
    count++;
  }

  return count;
}

static char *get_text(pool *p, JsonNode *json, const char *indent) {
  char *str, *text = NULL;

  if (p == NULL ||
      indent == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* An interesting gotcha: if you use "" as the indent, then json_stringify()
   * WILL include newlines in its text.  But if you use NULL, then it will
   * not include newlines.  This is not the behavior we expect.
   */
  if (*indent == '\0') {
    indent = NULL;
  }

  str = json_stringify(json, indent);
  if (str != NULL) {
    text = pstrdup(p, str);
    free(str);
  }

  return text;
}

/* JSON Objects */

pr_json_object_t *pr_json_object_alloc(pool *p) {
  pr_json_object_t *json;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  json = alloc_object(p); 
  json->object = json_mkobject();

  return json;
}

int pr_json_object_free(pr_json_object_t *json) {
  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  json_delete(json->object);
  json->object = NULL;

  destroy_pool(json->pool);
  json->pool = NULL;

  return 0;
}

pr_json_object_t *pr_json_object_from_text(pool *p, const char *text) {
  JsonNode *node;
  pr_json_object_t *json;

  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (json_validate(text) == FALSE) {
    pr_trace_msg(trace_channel, 9, "unable to parse invalid JSON text '%s'",
      text);
    errno = EPERM;
    return NULL;
  }

  node = json_decode(text);
  if (node->tag != JSON_OBJECT) {
    json_delete(node);

    pr_trace_msg(trace_channel, 9, "JSON text '%s' is not a JSON object", text);
    errno = EEXIST;
    return NULL;
  }

  json = alloc_object(p);
  json->object = node;
  json->member_count = get_count(node);

  return json;
}

char *pr_json_object_to_text(pool *p, const pr_json_object_t *json,
    const char *indent) {
  if (json == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return get_text(p, json->object, indent);
}

int pr_json_object_count(const pr_json_object_t *json) {
  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  return json->member_count;
}

int pr_json_object_remove(pr_json_object_t *json, const char *key) {
  JsonNode *node;

  if (json == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  node = json_find_member(json->object, key);
  if (node != NULL) {
    /* This CCAN JSON code automatically removes the node from its parent. */
    json_delete(node);

    if (json->member_count > 0) {
      json->member_count--;
    }
  }

  return 0;
}

int pr_json_object_exists(const pr_json_object_t *json, const char *key) {
  JsonNode *node;

  if (json == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  node = json_find_member(json->object, key);
  if (node == NULL) {
    return FALSE;
  }

  return TRUE;
}

static int can_get_member(pool *p, const pr_json_object_t *json,
    const char *key, JsonTag tag, void *val) {

  if (p == NULL ||
      json == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (tag != JSON_NULL &&
      val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int can_set_member(pool *p, const pr_json_object_t *json,
    const char *key) {

  if (p == NULL ||
      json == NULL ||
      key == NULL) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int get_val_from_node(pool *p, JsonNode *node, JsonTag tag, void *val) {
  switch (tag) {
    case JSON_NULL:
      break;

    case JSON_BOOL:
      *((int *) val) = node->bool_;
      break;

    case JSON_STRING:
      /* Fortunately, valid JSON does not allow an empty element, or
       * a member without a value.  Thus checking for NULL string_ here
       * would be superfluous.  The only way for that to happen is if the
       * caller were using the CCAN JSON API directly, in which case, they
       * get what they paid for.
       */
      *((char **) val) = pstrdup(p, node->string_);
      break;

    case JSON_NUMBER:
      *((double *) val) = node->number_;
      break; 

    case JSON_ARRAY: {
      pr_json_array_t *array;

      array = alloc_array(p);

      /* Make a duplicate of the child array, rather than just copying
       * its pointer.  Otherwise, freeing this array and then freeing
       * the parent node would cause a double free.
       *
       * A convenient way to get a deep copy is to encode the node
       * as a string, then decode it again.
       */
      if (node->children.head != NULL) {
        char *encoded_str = NULL;

        encoded_str = json_encode(node);
        array->array = json_decode(encoded_str);
        free(encoded_str);

      } else {
        array->array = json_mkarray();
      }
      array->item_count = get_count(array->array);

      *((pr_json_array_t **) val) = array;
      break;
    }

    case JSON_OBJECT: {
      pr_json_object_t *object;

      object = alloc_object(p);

      /* Make a duplicate of the child object, rather than just copying
       * its pointer.  Otherwise, freeing this object and then freeing
       * the parent node would cause a double free.
       *
       * A convenient way to get a deep copy is to encode the node
       * as a string, then decode it again.
       */
      if (node->children.head != NULL) {
        char *encoded_str = NULL;

        encoded_str = json_encode(node);
        object->object = json_decode(encoded_str);
        free(encoded_str);

      } else {
        object->object = json_mkobject();
      }
      object->member_count = get_count(object->object);

      *((pr_json_object_t **) val) = object;
      break;
    }
  }

  return 0;
}

static int get_member(pool *p, const pr_json_object_t *json, const char *key,
    JsonTag tag, void *val) {
  JsonNode *node;

  node = json_find_member(json->object, key);
  if (node == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (node->tag != tag) {
    errno = EEXIST;
    return -1;
  }

  return get_val_from_node(p, node, tag, val);
}

static JsonNode *get_node_from_val(JsonTag tag, const void *val) {
  JsonNode *node = NULL;

  switch (tag) {
    case JSON_NULL:
      node = json_mknull();
      break;

    case JSON_BOOL:
      node = json_mkbool(*((int *) val));
      break;

    case JSON_NUMBER:
      node = json_mknumber(*((double *) val));
      break;

    case JSON_STRING:
      node = json_mkstring(val);
      break;

    case JSON_ARRAY: {
      const pr_json_array_t *array;

      array = val;
      node = array->array;
      break;
    }

    case JSON_OBJECT: {
      const pr_json_object_t *object;

      object = val;
      node = object->object;
      break;
    }
  }

  return node;
}

static int set_member(pool *p, pr_json_object_t *json, const char *key,
    JsonTag tag, const void *val) {
  JsonNode *node = NULL;

  node = get_node_from_val(tag, val);
  json_append_member(json->object, key, node);
  json->member_count++;

  return 0;
}

int pr_json_object_get_bool(pool *p, const pr_json_object_t *json,
    const char *key, int *val) {
  if (can_get_member(p, json, key, JSON_BOOL, val) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_BOOL, val);
}

int pr_json_object_set_bool(pool *p, pr_json_object_t *json, const char *key,
    int val) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  return set_member(p, json, key, JSON_BOOL, &val);
}

int pr_json_object_get_null(pool *p, const pr_json_object_t *json,
    const char *key) {
  if (can_get_member(p, json, key, JSON_NULL, NULL) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_NULL, NULL);
}

int pr_json_object_set_null(pool *p, pr_json_object_t *json, const char *key) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  return set_member(p, json, key, JSON_NULL, NULL);
}

int pr_json_object_get_number(pool *p, const pr_json_object_t *json,
    const char *key, double *val) {
  if (can_get_member(p, json, key, JSON_NUMBER, val) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_NUMBER, val);
}

int pr_json_object_set_number(pool *p, pr_json_object_t *json, const char *key,
    double val) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  return set_member(p, json, key, JSON_NUMBER, &val);
}

int pr_json_object_get_string(pool *p, const pr_json_object_t *json,
    const char *key, char **val) {
  if (can_get_member(p, json, key, JSON_STRING, val) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_STRING, val);
}

int pr_json_object_set_string(pool *p, pr_json_object_t *json, const char *key,
    const char *val) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return set_member(p, json, key, JSON_STRING, val);
}

int pr_json_object_get_array(pool *p, const pr_json_object_t *json,
    const char *key, pr_json_array_t **val) {
  if (can_get_member(p, json, key, JSON_ARRAY, val) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_ARRAY, val);
}

int pr_json_object_set_array(pool *p, pr_json_object_t *json, const char *key,
    const pr_json_array_t *val) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return set_member(p, json, key, JSON_ARRAY, val);
}

int pr_json_object_get_object(pool *p, const pr_json_object_t *json,
    const char *key, pr_json_object_t **val) {
  if (can_get_member(p, json, key, JSON_OBJECT, val) < 0) {
    return -1;
  }

  return get_member(p, json, key, JSON_OBJECT, val);
}

int pr_json_object_set_object(pool *p, pr_json_object_t *json, const char *key,
    const pr_json_object_t *val) {
  if (can_set_member(p, json, key) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return set_member(p, json, key, JSON_OBJECT, val);
}

/* JSON Arrays */

pr_json_array_t *pr_json_array_alloc(pool *p) {
  pr_json_array_t *json;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  json = alloc_array(p);
  json->array = json_mkarray();

  return json;
}

int pr_json_array_free(pr_json_array_t *json) {
  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  json_delete(json->array);
  json->array = NULL;

  destroy_pool(json->pool);
  json->pool = NULL;

  return 0;
}

pr_json_array_t *pr_json_array_from_text(pool *p, const char *text) {
  JsonNode *node;
  pr_json_array_t *json;

  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (json_validate(text) == FALSE) {
    pr_trace_msg(trace_channel, 9, "unable to parse invalid JSON text '%s'",
      text);
    errno = EPERM;
    return NULL;
  }

  node = json_decode(text);
  if (node->tag != JSON_ARRAY) {
    json_delete(node);

    pr_trace_msg(trace_channel, 9, "JSON text '%s' is not a JSON array", text);
    errno = EEXIST;
    return NULL;
  }

  json = alloc_array(p);
  json->array = node;
  json->item_count = get_count(node);

  return json;
}

char *pr_json_array_to_text(pool *p, const pr_json_array_t *json,
    const char *indent) {
  if (json == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return get_text(p, json->array, indent);
}

int pr_json_array_count(const pr_json_array_t *json) {
  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  return json->item_count;
}

int pr_json_array_remove(pr_json_array_t *json, unsigned int idx) {
  JsonNode *node;

  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  node = json_find_element(json->array, idx);
  if (node != NULL) {
    /* This CCAN JSON code automatically removes the node from its parent. */
    json_delete(node);

    if (json->item_count > 0) {
      json->item_count--;
    }
  }

  return 0;
}

int pr_json_array_exists(const pr_json_array_t *json, unsigned int idx) {
  JsonNode *node;

  if (json == NULL) {
    errno = EINVAL;
    return -1;
  }

  node = json_find_element(json->array, idx);
  if (node == NULL) {
    return FALSE;
  }

  return TRUE;
}

static int can_get_item(pool *p, const pr_json_array_t *json, JsonTag tag,
    void *val) {

  if (p == NULL ||
      json == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (tag != JSON_NULL &&
      val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int can_add_item(pool *p, const pr_json_array_t *json) {

  if (p == NULL ||
      json == NULL) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int get_item(pool *p, const pr_json_array_t *json, unsigned int idx,
    JsonTag tag, void *val) {
  JsonNode *node;

  node = json_find_element(json->array, idx);
  if (node == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (node->tag != tag) {
    errno = EEXIST;
    return -1;
  }

  return get_val_from_node(p, node, tag, val);
}

static int append_item(pool *p, pr_json_array_t *json, JsonTag tag,
    const void *val) {
  JsonNode *node = NULL;

  node = get_node_from_val(tag, val);
  json_append_element(json->array, node);
  json->item_count++;

  return 0;
}

int pr_json_array_append_bool(pool *p, pr_json_array_t *json, int val) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  return append_item(p, json, JSON_BOOL, &val);
}

int pr_json_array_get_bool(pool *p, const pr_json_array_t *json,
    unsigned int idx, int *val) {
  if (can_get_item(p, json, JSON_BOOL, val) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_BOOL, val);
}

int pr_json_array_append_null(pool *p, pr_json_array_t *json) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  return append_item(p, json, JSON_NULL, NULL);
}

int pr_json_array_get_null(pool *p, const pr_json_array_t *json,
    unsigned int idx) {
  if (can_get_item(p, json, JSON_NULL, NULL) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_NULL, NULL);
}

int pr_json_array_append_number(pool *p, pr_json_array_t *json, double val) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  return append_item(p, json, JSON_NUMBER, &val);
}

int pr_json_array_get_number(pool *p, const pr_json_array_t *json,
    unsigned int idx, double *val) {
  if (can_get_item(p, json, JSON_NUMBER, val) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_NUMBER, val);
}

int pr_json_array_append_string(pool *p, pr_json_array_t *json,
    const char *val) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return append_item(p, json, JSON_STRING, val);
}

int pr_json_array_get_string(pool *p, const pr_json_array_t *json,
    unsigned int idx, char **val) {
  if (can_get_item(p, json, JSON_STRING, val) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_STRING, val);
}

int pr_json_array_append_array(pool *p, pr_json_array_t *json,
    const pr_json_array_t *val) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return append_item(p, json, JSON_ARRAY, val);
}

int pr_json_array_get_array(pool *p, const pr_json_array_t *json,
    unsigned int idx, pr_json_array_t **val) {
  if (can_get_item(p, json, JSON_ARRAY, val) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_ARRAY, val);
}

int pr_json_array_append_object(pool *p, pr_json_array_t *json,
    const pr_json_object_t *val) {
  if (can_add_item(p, json) < 0) {
    return -1;
  }

  if (val == NULL) {
    errno = EINVAL;
    return -1;
  }

  return append_item(p, json, JSON_OBJECT, val);
}

int pr_json_array_get_object(pool *p, const pr_json_array_t *json,
    unsigned int idx, pr_json_object_t **val) {
  if (can_get_item(p, json, JSON_OBJECT, val) < 0) {
    return -1;
  }

  return get_item(p, json, idx, JSON_OBJECT, val);
}

int pr_json_text_validate(pool *p, const char *text) {
  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return -1;
  }

  return json_validate(text);
}

const char *pr_json_type_name(unsigned int json_type) {
  const char *name;

  switch (json_type) {
    case PR_JSON_TYPE_BOOL:
      name = "boolean";
      break;

    case PR_JSON_TYPE_NUMBER:
      name = "number";
      break;

    case PR_JSON_TYPE_NULL:
      name = "null";
      break;

    case PR_JSON_TYPE_STRING:
      name = "string";
      break;

    case PR_JSON_TYPE_ARRAY:
      name = "array";
      break;

    case PR_JSON_TYPE_OBJECT:
      name = "object";
      break;

    default:
      errno = EINVAL;
      name = NULL;
  }

  return name;
}

static void json_oom(void) {
  pr_log_pri(PR_LOG_ALERT, "%s", "Out of memory!");
  exit(1);
}


int init_json(void) {
  json_set_oom(json_oom);
  return 0;
}

int finish_json(void) {
  json_set_oom(NULL);
  return 0;
}


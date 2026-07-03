/*
 * analyzer.c - High-performance AD authorization graph analyzer
 *
 * This is a C replacement for the NetworkX-based analyzer.py. It consumes the
 * graph JSON emitted by graph_builder.py and preserves the analyzer report
 * shape while using compact integer node IDs, CSR adjacency, bounded path
 * exploration, reverse-BFS reachability caches, and SCC-condensed group
 * reachability bitsets.
 *
 * Build examples:
 *   cl /O2 /std:c11 analyzer.c /Fe:analyzer.exe
 *   gcc -O3 -std=c11 -Wall -Wextra -o analyzer analyzer.c
 *
 * Usage:
 *   analyzer.exe <graph_json_file>
 *   analyzer.exe <graph_json_file> --compare <other_graph_json>
 */

#define _CRT_SECURE_NO_WARNINGS

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EXAMPLE_PATHS 5
#define DEFAULT_MAX_PATH_LENGTH 10
#define GENERATOR_SAFETY_MULTIPLIER 20
#define DEFAULT_DFS_STEP_BUDGET 250000u
#define ROUTE_COUNT_CAP 1000
#define DEFAULT_AUTHORITY_SAMPLE_LIMIT 25u
#define DA_NODE_ID "Group:Domain Admins"

typedef enum {
    NODE_OTHER = 0,
    NODE_USER,
    NODE_COMPUTER,
    NODE_GROUP
} NodeKind;

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} StrVec;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

typedef struct {
    char *id;
    char *node_type;
    char *spn;
    int enabled;
    NodeKind kind;
    int group_bit;
} Node;

typedef struct {
    Node *items;
    size_t count;
    size_t cap;
} NodeVec;

typedef struct {
    int src;
    int dst;
    char *edge_type;
    char *permission;
    char *full_permission;
    char *extended_right;
    char *delegation_type;
    int conditional;
    StrVec conditions;
    int is_acl_edge;
    int is_dangerous;
} Edge;

typedef struct {
    Edge *items;
    size_t count;
    size_t cap;
} EdgeVec;

typedef struct {
    int *offset;
    int *to;
    int *edge_idx;
} CSR;

typedef struct {
    char *key;
    int value;
    uint64_t hash;
    int used;
} MapEntry;

typedef struct {
    MapEntry *entries;
    size_t cap;
    size_t count;
} StrIntMap;

typedef struct {
    NodeVec nodes;
    EdgeVec edges;
    StrIntMap node_map;
    CSR out;
    CSR in;
    int da_node;
    int *group_nodes;
    size_t group_count;
    size_t group_cap;
    char *metadata_json;
    size_t metadata_len;
    char *metadata_domain;
    char *metadata_collection_date;
} Graph;

typedef struct {
    int *nodes;
    int len;
} Path;

typedef struct {
    Path *items;
    size_t count;
    size_t cap;
} PathList;

typedef struct {
    int identity;
    PathList paths;
} DAEntry;

typedef struct {
    DAEntry *items;
    size_t count;
    size_t cap;
} DAResult;

typedef struct {
    int node;
    StrVec spns;
    int paths_to_da;
    int shortest_path_length;
    const char *risk_level;
} KerbEntry;

typedef struct {
    KerbEntry *items;
    size_t count;
    size_t cap;
} KerbResult;

typedef struct {
    int source;
    int target;
    int edge_idx;
    const char *risk_level;
    Path abuse_chain;
    int chain_length;
} AbuseChain;

typedef struct {
    int target;
    AbuseChain *chains;
    size_t count;
    size_t cap;
} ACLTarget;

typedef struct {
    ACLTarget *items;
    size_t count;
    size_t cap;
} ACLResult;

typedef struct {
    int edge_idx;
    int has_high_privilege;
    const char *risk_level;
} DelegationRisk;

typedef struct {
    DelegationRisk *items;
    size_t count;
    size_t cap;
} DelegationResult;

typedef struct {
    size_t comp_count;
    size_t group_count;
    size_t words;
    int *node_comp;
    uint64_t *bits;
} Reachability;

typedef struct {
    const char *s;
    size_t len;
    size_t pos;
} Parser;

typedef struct {
    int v;
    int next;
} DFSFrame;

typedef struct {
    int full_output;
    size_t authority_sample_limit;
} ReportOptions;

static void die(const char *msg) {
    fprintf(stderr, "[-] %s\n", msg);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("Out of memory");
    return p;
}

static void *xcalloc(size_t count, size_t size) {
    void *p = calloc(count ? count : 1, size ? size : 1);
    if (!p) die("Out of memory");
    return p;
}

static void *xrealloc(void *ptr, size_t n) {
    void *p = realloc(ptr, n ? n : 1);
    if (!p) die("Out of memory");
    return p;
}

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *out = (char *)xmalloc(n + 1);
    memcpy(out, s, n + 1);
    return out;
}

static char *xstrndup2(const char *s, size_t n) {
    char *out = (char *)xmalloc(n + 1);
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static void sb_init(StrBuf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void sb_reserve(StrBuf *b, size_t extra) {
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return;
    size_t cap = b->cap ? b->cap * 2 : 64;
    while (cap < need) cap *= 2;
    b->data = (char *)xrealloc(b->data, cap);
    b->cap = cap;
}

static void sb_putc(StrBuf *b, char c) {
    sb_reserve(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void sb_puts(StrBuf *b, const char *s) {
    if (!s) return;
    size_t n = strlen(s);
    sb_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static char *sb_take(StrBuf *b) {
    if (!b->data) return xstrdup("");
    char *out = b->data;
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    return out;
}

static void strvec_push_owned(StrVec *v, char *s) {
    if (v->count == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 4;
        v->items = (char **)xrealloc(v->items, v->cap * sizeof(char *));
    }
    v->items[v->count++] = s ? s : xstrdup("");
}

static void strvec_push_copy(StrVec *v, const char *s) {
    strvec_push_owned(v, xstrdup(s ? s : ""));
}

static void strvec_free(StrVec *v) {
    for (size_t i = 0; i < v->count; i++) free(v->items[i]);
    free(v->items);
    v->items = NULL;
    v->count = 0;
    v->cap = 0;
}

static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ull;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ull;
    }
    return h ? h : 1;
}

static void map_init(StrIntMap *m) {
    m->entries = NULL;
    m->cap = 0;
    m->count = 0;
}

static void map_rehash(StrIntMap *m, size_t new_cap) {
    MapEntry *old = m->entries;
    size_t old_cap = m->cap;
    m->entries = (MapEntry *)xcalloc(new_cap, sizeof(MapEntry));
    m->cap = new_cap;
    m->count = 0;
    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].used) continue;
        size_t mask = m->cap - 1;
        size_t pos = (size_t)old[i].hash & mask;
        while (m->entries[pos].used) pos = (pos + 1) & mask;
        m->entries[pos] = old[i];
        m->count++;
    }
    free(old);
}

static void map_ensure(StrIntMap *m) {
    if (!m->cap) {
        map_rehash(m, 1024);
    } else if ((m->count + 1) * 10 >= m->cap * 7) {
        map_rehash(m, m->cap * 2);
    }
}

static int map_get(const StrIntMap *m, const char *key, int *value_out) {
    if (!m->cap) return 0;
    uint64_t h = fnv1a(key);
    size_t mask = m->cap - 1;
    size_t pos = (size_t)h & mask;
    while (m->entries[pos].used) {
        if (m->entries[pos].hash == h && strcmp(m->entries[pos].key, key) == 0) {
            if (value_out) *value_out = m->entries[pos].value;
            return 1;
        }
        pos = (pos + 1) & mask;
    }
    return 0;
}

static void map_put(StrIntMap *m, char *key, int value) {
    map_ensure(m);
    uint64_t h = fnv1a(key);
    size_t mask = m->cap - 1;
    size_t pos = (size_t)h & mask;
    while (m->entries[pos].used) {
        if (m->entries[pos].hash == h && strcmp(m->entries[pos].key, key) == 0) {
            m->entries[pos].value = value;
            return;
        }
        pos = (pos + 1) & mask;
    }
    m->entries[pos].used = 1;
    m->entries[pos].hash = h;
    m->entries[pos].key = key;
    m->entries[pos].value = value;
    m->count++;
}

static NodeKind node_kind_from_type(const char *t) {
    if (!t) return NODE_OTHER;
    if (strcmp(t, "user") == 0) return NODE_USER;
    if (strcmp(t, "computer") == 0) return NODE_COMPUTER;
    if (strcmp(t, "group") == 0) return NODE_GROUP;
    return NODE_OTHER;
}

static int str_contains(const char *s, const char *needle) {
    return s && needle && strstr(s, needle) != NULL;
}

static int str_contains_casefold_ascii(const char *s, const char *needle) {
    if (!s || !needle) return 0;
    size_t n = strlen(needle);
    if (!n) return 1;
    for (; *s; s++) {
        size_t i = 0;
        while (i < n && s[i] &&
               (char)tolower((unsigned char)s[i]) == (char)tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == n) return 1;
    }
    return 0;
}

static int is_acl_edge_type(const char *edge_type) {
    static const char *types[] = {
        "has_GenericAll_on",
        "has_WriteDACL_on",
        "has_WriteOwner_on",
        "has_GenericWrite_on",
        "has_WriteProperty_on",
        "has_ExtendedRight_on",
        "has_permission_on",
        NULL
    };
    if (!edge_type) return 0;
    for (int i = 0; types[i]; i++) {
        if (strcmp(edge_type, types[i]) == 0) return 1;
    }
    return 0;
}

static int is_dangerous_raw_permission(const char *permission) {
    static const char *perms[] = {
        "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
        "WriteProperty", "ExtendedRight", "ResetPassword", "ForceChangePassword",
        NULL
    };
    if (!permission) return 0;
    for (int i = 0; perms[i]; i++) {
        if (str_contains(permission, perms[i])) return 1;
    }
    return 0;
}

static void nodevec_push(NodeVec *v, Node n) {
    if (v->count == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 1024;
        v->items = (Node *)xrealloc(v->items, v->cap * sizeof(Node));
    }
    v->items[v->count++] = n;
}

static void edgevec_push(EdgeVec *v, Edge e) {
    if (v->count == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 2048;
        v->items = (Edge *)xrealloc(v->items, v->cap * sizeof(Edge));
    }
    v->items[v->count++] = e;
}

static void graph_init(Graph *g) {
    memset(g, 0, sizeof(*g));
    map_init(&g->node_map);
    g->da_node = -1;
}

static int graph_add_node_owned(Graph *g, char *id, char *node_type, char *spn, int enabled) {
    int existing = -1;
    if (map_get(&g->node_map, id, &existing)) {
        Node *n = &g->nodes.items[existing];
        if (node_type && node_type[0]) {
            free(n->node_type);
            n->node_type = node_type;
            n->kind = node_kind_from_type(node_type);
        } else {
            free(node_type);
        }
        if (spn) {
            free(n->spn);
            n->spn = spn;
        }
        n->enabled = enabled;
        free(id);
        return existing;
    }

    Node n;
    n.id = id;
    n.node_type = node_type ? node_type : xstrdup("");
    n.spn = spn;
    n.enabled = enabled;
    n.kind = node_kind_from_type(n.node_type);
    n.group_bit = -1;

    int idx = (int)g->nodes.count;
    nodevec_push(&g->nodes, n);
    map_put(&g->node_map, g->nodes.items[idx].id, idx);
    if (strcmp(g->nodes.items[idx].id, DA_NODE_ID) == 0) g->da_node = idx;
    return idx;
}

static int graph_ensure_node_owned(Graph *g, char *id) {
    int existing = -1;
    if (map_get(&g->node_map, id, &existing)) {
        free(id);
        return existing;
    }
    return graph_add_node_owned(g, id, xstrdup(""), NULL, 1);
}

static void graph_add_group_node(Graph *g, int node_idx) {
    if (g->group_count == g->group_cap) {
        g->group_cap = g->group_cap ? g->group_cap * 2 : 1024;
        g->group_nodes = (int *)xrealloc(g->group_nodes, g->group_cap * sizeof(int));
    }
    g->nodes.items[node_idx].group_bit = (int)g->group_count;
    g->group_nodes[g->group_count++] = node_idx;
}

static void parser_skip_ws(Parser *p) {
    while (p->pos < p->len && isspace((unsigned char)p->s[p->pos])) p->pos++;
}

static int parser_peek(Parser *p) {
    parser_skip_ws(p);
    if (p->pos >= p->len) return EOF;
    return (unsigned char)p->s[p->pos];
}

static int parser_consume(Parser *p, char c) {
    parser_skip_ws(p);
    if (p->pos < p->len && p->s[p->pos] == c) {
        p->pos++;
        return 1;
    }
    return 0;
}

static void parser_expect(Parser *p, char c, const char *context) {
    if (!parser_consume(p, c)) {
        fprintf(stderr, "[-] JSON parse error near byte %zu: expected '%c' in %s\n", p->pos, c, context);
        exit(1);
    }
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void sb_put_utf8(StrBuf *b, uint32_t cp) {
    if (cp <= 0x7F) {
        sb_putc(b, (char)cp);
    } else if (cp <= 0x7FF) {
        sb_putc(b, (char)(0xC0 | (cp >> 6)));
        sb_putc(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        sb_putc(b, (char)(0xE0 | (cp >> 12)));
        sb_putc(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        sb_putc(b, (char)(0x80 | (cp & 0x3F)));
    } else {
        sb_putc(b, (char)(0xF0 | (cp >> 18)));
        sb_putc(b, (char)(0x80 | ((cp >> 12) & 0x3F)));
        sb_putc(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        sb_putc(b, (char)(0x80 | (cp & 0x3F)));
    }
}

static uint32_t parser_read_u4(Parser *p) {
    uint32_t cp = 0;
    if (p->pos + 4 > p->len) die("Truncated unicode escape in JSON string");
    for (int i = 0; i < 4; i++) {
        int h = hexval((unsigned char)p->s[p->pos++]);
        if (h < 0) die("Invalid unicode escape in JSON string");
        cp = (cp << 4) | (uint32_t)h;
    }
    return cp;
}

static char *parser_parse_string(Parser *p) {
    parser_skip_ws(p);
    if (p->pos >= p->len || p->s[p->pos] != '"') die("Expected JSON string");
    p->pos++;
    StrBuf b;
    sb_init(&b);
    while (p->pos < p->len) {
        unsigned char c = (unsigned char)p->s[p->pos++];
        if (c == '"') return sb_take(&b);
        if (c != '\\') {
            sb_putc(&b, (char)c);
            continue;
        }
        if (p->pos >= p->len) die("Truncated JSON string escape");
        c = (unsigned char)p->s[p->pos++];
        switch (c) {
            case '"': sb_putc(&b, '"'); break;
            case '\\': sb_putc(&b, '\\'); break;
            case '/': sb_putc(&b, '/'); break;
            case 'b': sb_putc(&b, '\b'); break;
            case 'f': sb_putc(&b, '\f'); break;
            case 'n': sb_putc(&b, '\n'); break;
            case 'r': sb_putc(&b, '\r'); break;
            case 't': sb_putc(&b, '\t'); break;
            case 'u': {
                uint32_t cp = parser_read_u4(p);
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (p->pos + 2 <= p->len && p->s[p->pos] == '\\' && p->s[p->pos + 1] == 'u') {
                        p->pos += 2;
                        uint32_t lo = parser_read_u4(p);
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                    }
                }
                sb_put_utf8(&b, cp);
                break;
            }
            default:
                sb_putc(&b, (char)c);
                break;
        }
    }
    die("Unterminated JSON string");
    return NULL;
}

static int parser_match_literal(Parser *p, const char *lit) {
    parser_skip_ws(p);
    size_t n = strlen(lit);
    if (p->pos + n <= p->len && memcmp(p->s + p->pos, lit, n) == 0) {
        p->pos += n;
        return 1;
    }
    return 0;
}

static void parser_skip_value(Parser *p);

static char *parser_parse_nullable_string(Parser *p) {
    parser_skip_ws(p);
    if (parser_match_literal(p, "null")) return NULL;
    if (parser_peek(p) == '"') return parser_parse_string(p);
    parser_skip_value(p);
    return NULL;
}

static int parser_parse_bool(Parser *p, int default_value) {
    if (parser_match_literal(p, "true")) return 1;
    if (parser_match_literal(p, "false")) return 0;
    if (parser_match_literal(p, "null")) return default_value;
    parser_skip_value(p);
    return default_value;
}

static void parser_skip_array(Parser *p) {
    parser_expect(p, '[', "array");
    if (parser_consume(p, ']')) return;
    for (;;) {
        parser_skip_value(p);
        if (parser_consume(p, ']')) break;
        parser_expect(p, ',', "array");
    }
}

static void parser_skip_object(Parser *p) {
    parser_expect(p, '{', "object");
    if (parser_consume(p, '}')) return;
    for (;;) {
        char *key = parser_parse_string(p);
        free(key);
        parser_expect(p, ':', "object");
        parser_skip_value(p);
        if (parser_consume(p, '}')) break;
        parser_expect(p, ',', "object");
    }
}

static void parser_skip_number(Parser *p) {
    parser_skip_ws(p);
    while (p->pos < p->len) {
        unsigned char c = (unsigned char)p->s[p->pos];
        if (isdigit(c) || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
            p->pos++;
        } else {
            break;
        }
    }
}

static void parser_skip_value(Parser *p) {
    int c = parser_peek(p);
    if (c == '"') {
        char *s = parser_parse_string(p);
        free(s);
    } else if (c == '{') {
        parser_skip_object(p);
    } else if (c == '[') {
        parser_skip_array(p);
    } else if (parser_match_literal(p, "true") ||
               parser_match_literal(p, "false") ||
               parser_match_literal(p, "null")) {
        return;
    } else {
        parser_skip_number(p);
    }
}

static void parse_conditions(Parser *p, StrVec *conditions) {
    parser_skip_ws(p);
    if (parser_match_literal(p, "null")) return;
    parser_expect(p, '[', "conditions");
    if (parser_consume(p, ']')) return;
    for (;;) {
        parser_skip_ws(p);
        if (parser_peek(p) == '"') {
            strvec_push_owned(conditions, parser_parse_string(p));
        } else {
            parser_skip_value(p);
        }
        if (parser_consume(p, ']')) break;
        parser_expect(p, ',', "conditions");
    }
}

static void parse_node_object(Parser *p, Graph *g) {
    char *id = NULL;
    char *node_type = NULL;
    char *spn = NULL;
    int enabled = 1;

    parser_expect(p, '{', "node");
    if (!parser_consume(p, '}')) {
        for (;;) {
            char *key = parser_parse_string(p);
            parser_expect(p, ':', "node");
            if (strcmp(key, "id") == 0) {
                id = parser_parse_nullable_string(p);
            } else if (strcmp(key, "node_type") == 0) {
                node_type = parser_parse_nullable_string(p);
            } else if (strcmp(key, "spn") == 0) {
                spn = parser_parse_nullable_string(p);
            } else if (strcmp(key, "enabled") == 0) {
                enabled = parser_parse_bool(p, 1);
            } else {
                parser_skip_value(p);
            }
            free(key);
            if (parser_consume(p, '}')) break;
            parser_expect(p, ',', "node");
        }
    }

    if (!id) {
        free(node_type);
        free(spn);
        return;
    }
    graph_add_node_owned(g, id, node_type ? node_type : xstrdup(""), spn, enabled);
}

static void parse_nodes_array(Parser *p, Graph *g) {
    parser_expect(p, '[', "nodes");
    if (parser_consume(p, ']')) return;
    for (;;) {
        parse_node_object(p, g);
        if (parser_consume(p, ']')) break;
        parser_expect(p, ',', "nodes");
    }
}

static void parse_edge_object(Parser *p, Graph *g) {
    char *source = NULL;
    char *target = NULL;
    Edge e;
    memset(&e, 0, sizeof(e));
    e.src = -1;
    e.dst = -1;

    parser_expect(p, '{', "edge");
    if (!parser_consume(p, '}')) {
        for (;;) {
            char *key = parser_parse_string(p);
            parser_expect(p, ':', "edge");
            if (strcmp(key, "source") == 0) {
                source = parser_parse_nullable_string(p);
            } else if (strcmp(key, "target") == 0) {
                target = parser_parse_nullable_string(p);
            } else if (strcmp(key, "edge_type") == 0) {
                e.edge_type = parser_parse_nullable_string(p);
            } else if (strcmp(key, "permission") == 0) {
                e.permission = parser_parse_nullable_string(p);
            } else if (strcmp(key, "full_permission") == 0) {
                e.full_permission = parser_parse_nullable_string(p);
            } else if (strcmp(key, "extended_right") == 0) {
                e.extended_right = parser_parse_nullable_string(p);
            } else if (strcmp(key, "delegation_type") == 0) {
                e.delegation_type = parser_parse_nullable_string(p);
            } else if (strcmp(key, "conditional") == 0) {
                e.conditional = parser_parse_bool(p, 0);
            } else if (strcmp(key, "conditions") == 0) {
                parse_conditions(p, &e.conditions);
            } else {
                parser_skip_value(p);
            }
            free(key);
            if (parser_consume(p, '}')) break;
            parser_expect(p, ',', "edge");
        }
    }

    if (!source || !target) {
        free(source);
        free(target);
        free(e.edge_type);
        free(e.permission);
        free(e.full_permission);
        free(e.extended_right);
        free(e.delegation_type);
        strvec_free(&e.conditions);
        return;
    }

    e.src = graph_ensure_node_owned(g, source);
    e.dst = graph_ensure_node_owned(g, target);
    e.edge_type = e.edge_type ? e.edge_type : xstrdup("");
    e.permission = e.permission ? e.permission : xstrdup("");
    e.full_permission = e.full_permission ? e.full_permission : xstrdup("");
    e.extended_right = e.extended_right ? e.extended_right : xstrdup("");
    e.delegation_type = e.delegation_type ? e.delegation_type : xstrdup("");
    e.is_acl_edge = is_acl_edge_type(e.edge_type);
    const char *raw_perm = e.permission[0] ? e.permission : e.full_permission;
    e.is_dangerous = e.is_acl_edge || is_dangerous_raw_permission(raw_perm);
    edgevec_push(&g->edges, e);
}

static void parse_edges_array(Parser *p, Graph *g) {
    parser_expect(p, '[', "edges");
    if (parser_consume(p, ']')) return;
    for (;;) {
        parse_edge_object(p, g);
        if (parser_consume(p, ']')) break;
        parser_expect(p, ',', "edges");
    }
}

static char *read_entire_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Error opening %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long n = ftell(f);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    char *buf = (char *)xmalloc((size_t)n + 1);
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    *len_out = got;
    return buf;
}

static char *extract_metadata_string(const char *json, size_t len, const char *wanted_key) {
    Parser p = { json, len, 0 };
    if (!parser_consume(&p, '{')) return NULL;
    if (parser_consume(&p, '}')) return NULL;
    for (;;) {
        char *key = parser_parse_string(&p);
        parser_expect(&p, ':', "metadata");
        if (strcmp(key, wanted_key) == 0 && parser_peek(&p) == '"') {
            char *value = parser_parse_string(&p);
            free(key);
            return value;
        }
        parser_skip_value(&p);
        free(key);
        if (parser_consume(&p, '}')) break;
        parser_expect(&p, ',', "metadata");
    }
    return NULL;
}

static int parse_graph_json(const char *path, Graph *g) {
    size_t len = 0;
    char *buf = read_entire_file(path, &len);
    if (!buf) return 0;

    Parser p = { buf, len, 0 };
    if (len >= 3 &&
        (unsigned char)buf[0] == 0xEF &&
        (unsigned char)buf[1] == 0xBB &&
        (unsigned char)buf[2] == 0xBF) {
        p.pos = 3;
    }

    parser_expect(&p, '{', "top-level graph");
    if (!parser_consume(&p, '}')) {
        for (;;) {
            char *key = parser_parse_string(&p);
            parser_expect(&p, ':', "top-level graph");
            if (strcmp(key, "metadata") == 0) {
                parser_skip_ws(&p);
                size_t start = p.pos;
                parser_skip_value(&p);
                size_t end = p.pos;
                g->metadata_json = xstrndup2(buf + start, end - start);
                g->metadata_len = end - start;
            } else if (strcmp(key, "nodes") == 0) {
                parse_nodes_array(&p, g);
            } else if (strcmp(key, "edges") == 0) {
                parse_edges_array(&p, g);
            } else {
                parser_skip_value(&p);
            }
            free(key);
            if (parser_consume(&p, '}')) break;
            parser_expect(&p, ',', "top-level graph");
        }
    }

    if (!g->metadata_json) {
        g->metadata_json = xstrdup("{}");
        g->metadata_len = 2;
    }
    g->metadata_domain = extract_metadata_string(g->metadata_json, g->metadata_len, "domain");
    g->metadata_collection_date = extract_metadata_string(g->metadata_json, g->metadata_len, "collection_date");

    free(buf);
    return 1;
}

static void csr_build(CSR *csr, size_t node_count, EdgeVec *edges, int reverse) {
    csr->offset = (int *)xcalloc(node_count + 1, sizeof(int));
    csr->to = (int *)xmalloc(edges->count * sizeof(int));
    csr->edge_idx = (int *)xmalloc(edges->count * sizeof(int));

    for (size_t i = 0; i < edges->count; i++) {
        int from = reverse ? edges->items[i].dst : edges->items[i].src;
        csr->offset[from + 1]++;
    }
    for (size_t i = 0; i < node_count; i++) {
        csr->offset[i + 1] += csr->offset[i];
    }

    int *cursor = (int *)xmalloc((node_count + 1) * sizeof(int));
    memcpy(cursor, csr->offset, (node_count + 1) * sizeof(int));
    for (size_t i = 0; i < edges->count; i++) {
        int from = reverse ? edges->items[i].dst : edges->items[i].src;
        int to = reverse ? edges->items[i].src : edges->items[i].dst;
        int pos = cursor[from]++;
        csr->to[pos] = to;
        csr->edge_idx[pos] = (int)i;
    }
    free(cursor);
}

static void graph_finalize(Graph *g) {
    g->da_node = -1;
    for (size_t i = 0; i < g->nodes.count; i++) {
        g->nodes.items[i].kind = node_kind_from_type(g->nodes.items[i].node_type);
        if (g->nodes.items[i].kind == NODE_GROUP) graph_add_group_node(g, (int)i);
        if (strcmp(g->nodes.items[i].id, DA_NODE_ID) == 0) g->da_node = (int)i;
    }
    csr_build(&g->out, g->nodes.count, &g->edges, 0);
    csr_build(&g->in, g->nodes.count, &g->edges, 1);
}

static int *compute_reverse_bfs(Graph *g, int da_node, int membership_only, int **pred_out) {
    size_t n = g->nodes.count;
    int *dist = (int *)xmalloc(n * sizeof(int));
    int *pred = (int *)xmalloc(n * sizeof(int));
    for (size_t i = 0; i < n; i++) {
        dist[i] = -1;
        pred[i] = -1;
    }
    if (da_node < 0) {
        *pred_out = pred;
        return dist;
    }

    int *queue = (int *)xmalloc(n * sizeof(int));
    size_t head = 0, tail = 0;
    dist[da_node] = 0;
    queue[tail++] = da_node;

    while (head < tail) {
        int cur = queue[head++];
        for (int pos = g->in.offset[cur]; pos < g->in.offset[cur + 1]; pos++) {
            int eidx = g->in.edge_idx[pos];
            if (membership_only && g->edges.items[eidx].is_acl_edge) continue;
            int nxt = g->in.to[pos];
            if (dist[nxt] == -1) {
                dist[nxt] = dist[cur] + 1;
                pred[nxt] = cur;
                queue[tail++] = nxt;
            }
        }
    }

    free(queue);
    *pred_out = pred;
    return dist;
}

static void path_free(Path *p) {
    free(p->nodes);
    p->nodes = NULL;
    p->len = 0;
}

static Path path_from_pred(int source, int target, const int *pred) {
    Path p;
    p.nodes = NULL;
    p.len = 0;
    int cur = source;
    int len = 1;
    while (cur != target) {
        cur = pred[cur];
        if (cur < 0) {
            p.nodes = NULL;
            p.len = 0;
            return p;
        }
        len++;
        if (len > 10000000) die("Path reconstruction loop detected");
    }
    p.nodes = (int *)xmalloc((size_t)len * sizeof(int));
    p.len = len;
    cur = source;
    for (int i = 0; i < len; i++) {
        p.nodes[i] = cur;
        if (cur != target) cur = pred[cur];
    }
    return p;
}

static Path path_prefix_source(int source, const Path *tail) {
    Path p;
    p.len = tail->len + 1;
    p.nodes = (int *)xmalloc((size_t)p.len * sizeof(int));
    p.nodes[0] = source;
    memcpy(p.nodes + 1, tail->nodes, (size_t)tail->len * sizeof(int));
    return p;
}

static void pathlist_push_owned(PathList *pl, Path p) {
    if (!p.nodes || p.len <= 0) return;
    if (pl->count == pl->cap) {
        pl->cap = pl->cap ? pl->cap * 2 : 4;
        pl->items = (Path *)xrealloc(pl->items, pl->cap * sizeof(Path));
    }
    pl->items[pl->count++] = p;
}

static int path_equals(const Path *a, const Path *b) {
    if (a->len != b->len) return 0;
    return memcmp(a->nodes, b->nodes, (size_t)a->len * sizeof(int)) == 0;
}

static int pathlist_contains(const PathList *pl, const Path *p) {
    for (size_t i = 0; i < pl->count; i++) {
        if (path_equals(&pl->items[i], p)) return 1;
    }
    return 0;
}

static void pathlist_free(PathList *pl) {
    for (size_t i = 0; i < pl->count; i++) path_free(&pl->items[i]);
    free(pl->items);
    pl->items = NULL;
    pl->count = 0;
    pl->cap = 0;
}

static void dfs_collect_paths(Graph *g, int cur, int target, int max_depth, int limit,
                              int membership_only, uint32_t step_budget, uint32_t *steps,
                              unsigned char *visited, int *stack, int depth, PathList *out) {
    if ((int)out->count >= limit || *steps >= step_budget) return;
    if (cur == target) {
        Path p;
        p.len = depth + 1;
        p.nodes = (int *)xmalloc((size_t)p.len * sizeof(int));
        memcpy(p.nodes, stack, (size_t)p.len * sizeof(int));
        pathlist_push_owned(out, p);
        return;
    }
    if (depth >= max_depth) return;

    for (int pos = g->out.offset[cur]; pos < g->out.offset[cur + 1]; pos++) {
        if ((int)out->count >= limit || *steps >= step_budget) return;
        int eidx = g->out.edge_idx[pos];
        if (membership_only && g->edges.items[eidx].is_acl_edge) continue;
        int nxt = g->out.to[pos];
        if (visited[nxt]) continue;
        (*steps)++;
        visited[nxt] = 1;
        stack[depth + 1] = nxt;
        dfs_collect_paths(g, nxt, target, max_depth, limit, membership_only, step_budget,
                          steps, visited, stack, depth + 1, out);
        visited[nxt] = 0;
    }
}

static PathList sample_example_paths(Graph *g, int source, int target, int max_length,
                                     int limit, int membership_only) {
    PathList out = {0};
    if (source < 0 || target < 0 || limit <= 0) return out;
    unsigned char *visited = (unsigned char *)xcalloc(g->nodes.count, 1);
    int *stack = (int *)xmalloc((size_t)(max_length + 1) * sizeof(int));
    uint32_t steps = 0;
    uint32_t step_budget = DEFAULT_DFS_STEP_BUDGET;
    uint32_t multiplier_budget = (uint32_t)(limit * GENERATOR_SAFETY_MULTIPLIER * 10000);
    if (multiplier_budget > step_budget) step_budget = multiplier_budget;
    visited[source] = 1;
    stack[0] = source;
    dfs_collect_paths(g, source, target, max_length, limit, membership_only, step_budget,
                      &steps, visited, stack, 0, &out);
    free(visited);
    free(stack);
    return out;
}

static void dfs_count_paths(Graph *g, int cur, int target, int max_depth, int cap,
                            uint32_t step_budget, uint32_t *steps, int *count,
                            unsigned char *visited, int depth) {
    if (*count >= cap || *steps >= step_budget) return;
    if (cur == target) {
        (*count)++;
        return;
    }
    if (depth >= max_depth) return;
    for (int pos = g->out.offset[cur]; pos < g->out.offset[cur + 1]; pos++) {
        if (*count >= cap || *steps >= step_budget) return;
        int nxt = g->out.to[pos];
        if (visited[nxt]) continue;
        (*steps)++;
        visited[nxt] = 1;
        dfs_count_paths(g, nxt, target, max_depth, cap, step_budget, steps, count, visited, depth + 1);
        visited[nxt] = 0;
    }
}

static int get_da_path_route_count(Graph *g, int node, int da_node, int cap) {
    if (node < 0 || da_node < 0) return 0;
    unsigned char *visited = (unsigned char *)xcalloc(g->nodes.count, 1);
    uint32_t steps = 0;
    uint32_t budget = DEFAULT_DFS_STEP_BUDGET * 4u;
    int count = 0;
    visited[node] = 1;
    dfs_count_paths(g, node, da_node, DEFAULT_MAX_PATH_LENGTH, cap, budget, &steps, &count, visited, 0);
    free(visited);
    if (steps >= budget && count < cap) return cap;
    return count;
}

static void daresult_push(DAResult *r, int identity, PathList paths) {
    if (r->count == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 128;
        r->items = (DAEntry *)xrealloc(r->items, r->cap * sizeof(DAEntry));
    }
    r->items[r->count].identity = identity;
    r->items[r->count].paths = paths;
    r->count++;
}

static DAResult build_da_result(Graph *g, const int *da_dist, const int *da_pred) {
    DAResult result = {0};
    if (g->da_node < 0) return result;

    for (size_t i = 0; i < g->nodes.count; i++) {
        NodeKind kind = g->nodes.items[i].kind;
        if (kind != NODE_USER && kind != NODE_COMPUTER) continue;
        if (da_dist[i] < 0) continue;

        PathList paths = {0};
        Path shortest = path_from_pred((int)i, g->da_node, da_pred);
        pathlist_push_owned(&paths, shortest);

        int remaining = MAX_EXAMPLE_PATHS - (int)paths.count;
        if (remaining > 0) {
            PathList extra = sample_example_paths(g, (int)i, g->da_node,
                                                  DEFAULT_MAX_PATH_LENGTH, remaining, 0);
            for (size_t j = 0; j < extra.count && paths.count < MAX_EXAMPLE_PATHS; j++) {
                if (!pathlist_contains(&paths, &extra.items[j])) {
                    Path moved = extra.items[j];
                    extra.items[j].nodes = NULL;
                    extra.items[j].len = 0;
                    pathlist_push_owned(&paths, moved);
                }
            }
            pathlist_free(&extra);
        }

        if (paths.count) daresult_push(&result, (int)i, paths);
    }
    return result;
}

static void json_write_string(FILE *f, const char *s) {
    fputc('"', f);
    if (!s) s = "";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"': fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\b': fputs("\\b", f); break;
            case '\f': fputs("\\f", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (c < 0x20) fprintf(f, "\\u%04x", c);
                else fputc(c, f);
                break;
        }
    }
    fputc('"', f);
}

static void json_write_path(FILE *f, Graph *g, const Path *p, int indent) {
    fprintf(f, "[\n");
    for (int i = 0; i < p->len; i++) {
        fprintf(f, "%*s", indent + 2, "");
        json_write_string(f, g->nodes.items[p->nodes[i]].id);
        fprintf(f, "%s\n", i + 1 == p->len ? "" : ",");
    }
    fprintf(f, "%*s]", indent, "");
}

static int bit_ctz64(uint64_t x) {
    int n = 0;
    while ((x & 1ull) == 0ull) {
        n++;
        x >>= 1;
    }
    return n;
}

static int bit_get(const uint64_t *bits, size_t bit) {
    return (bits[bit >> 6] & (1ull << (bit & 63))) != 0;
}

static void bit_set(uint64_t *bits, size_t bit) {
    bits[bit >> 6] |= (1ull << (bit & 63));
}

static void bit_or(uint64_t *dst, const uint64_t *src, size_t words) {
    for (size_t i = 0; i < words; i++) dst[i] |= src[i];
}

static void kosaraju_components(Graph *g, int **node_comp_out, size_t *comp_count_out) {
    size_t n = g->nodes.count;
    unsigned char *visited = (unsigned char *)xcalloc(n, 1);
    int *order = (int *)xmalloc(n * sizeof(int));
    size_t order_count = 0;
    DFSFrame *stack = (DFSFrame *)xmalloc(n * sizeof(DFSFrame));

    for (size_t start = 0; start < n; start++) {
        if (visited[start]) continue;
        size_t sp = 0;
        visited[start] = 1;
        stack[sp++] = (DFSFrame){ (int)start, g->out.offset[start] };
        while (sp) {
            DFSFrame *top = &stack[sp - 1];
            int v = top->v;
            if (top->next < g->out.offset[v + 1]) {
                int nxt = g->out.to[top->next++];
                if (!visited[nxt]) {
                    visited[nxt] = 1;
                    stack[sp++] = (DFSFrame){ nxt, g->out.offset[nxt] };
                }
            } else {
                order[order_count++] = v;
                sp--;
            }
        }
    }

    int *comp = (int *)xmalloc(n * sizeof(int));
    for (size_t i = 0; i < n; i++) comp[i] = -1;
    int *q = (int *)xmalloc(n * sizeof(int));
    size_t comp_count = 0;

    for (size_t oi = order_count; oi > 0; oi--) {
        int start = order[oi - 1];
        if (comp[start] != -1) continue;
        size_t head = 0, tail = 0;
        q[tail++] = start;
        comp[start] = (int)comp_count;
        while (head < tail) {
            int cur = q[head++];
            for (int pos = g->in.offset[cur]; pos < g->in.offset[cur + 1]; pos++) {
                int nxt = g->in.to[pos];
                if (comp[nxt] == -1) {
                    comp[nxt] = (int)comp_count;
                    q[tail++] = nxt;
                }
            }
        }
        comp_count++;
    }

    free(visited);
    free(order);
    free(stack);
    free(q);
    *node_comp_out = comp;
    *comp_count_out = comp_count;
}

static Reachability build_reachability(Graph *g) {
    Reachability r;
    memset(&r, 0, sizeof(r));
    kosaraju_components(g, &r.node_comp, &r.comp_count);
    r.group_count = g->group_count;
    r.words = (r.group_count + 63) / 64;

    if (r.words && r.comp_count > SIZE_MAX / r.words) {
        die("Reachability bitset is too large for this platform");
    }
    size_t total_words = r.comp_count * (r.words ? r.words : 1);
    r.bits = (uint64_t *)xcalloc(total_words, sizeof(uint64_t));

    for (size_t i = 0; i < g->group_count; i++) {
        int node = g->group_nodes[i];
        int comp = r.node_comp[node];
        bit_set(r.bits + (size_t)comp * r.words, i);
    }

    int *comp_out_count = (int *)xcalloc(r.comp_count + 1, sizeof(int));
    int *indeg = (int *)xcalloc(r.comp_count, sizeof(int));
    for (size_t i = 0; i < g->edges.count; i++) {
        int cu = r.node_comp[g->edges.items[i].src];
        int cv = r.node_comp[g->edges.items[i].dst];
        if (cu == cv) continue;
        comp_out_count[cu + 1]++;
        indeg[cv]++;
    }
    for (size_t i = 0; i < r.comp_count; i++) comp_out_count[i + 1] += comp_out_count[i];
    int total_comp_edges = comp_out_count[r.comp_count];
    int *comp_to = (int *)xmalloc((size_t)total_comp_edges * sizeof(int));
    int *cursor = (int *)xmalloc((r.comp_count + 1) * sizeof(int));
    memcpy(cursor, comp_out_count, (r.comp_count + 1) * sizeof(int));
    for (size_t i = 0; i < g->edges.count; i++) {
        int cu = r.node_comp[g->edges.items[i].src];
        int cv = r.node_comp[g->edges.items[i].dst];
        if (cu == cv) continue;
        comp_to[cursor[cu]++] = cv;
    }
    free(cursor);

    int *queue = (int *)xmalloc(r.comp_count * sizeof(int));
    int *topo = (int *)xmalloc(r.comp_count * sizeof(int));
    size_t head = 0, tail = 0, topo_count = 0;
    for (size_t c = 0; c < r.comp_count; c++) {
        if (indeg[c] == 0) queue[tail++] = (int)c;
    }
    while (head < tail) {
        int c = queue[head++];
        topo[topo_count++] = c;
        for (int pos = comp_out_count[c]; pos < comp_out_count[c + 1]; pos++) {
            int nxt = comp_to[pos];
            indeg[nxt]--;
            if (indeg[nxt] == 0) queue[tail++] = nxt;
        }
    }
    if (topo_count != r.comp_count) {
        for (size_t c = 0; c < r.comp_count; c++) topo[c] = (int)c;
        topo_count = r.comp_count;
    }

    if (r.words) {
        for (size_t ti = topo_count; ti > 0; ti--) {
            int c = topo[ti - 1];
            uint64_t *dst = r.bits + (size_t)c * r.words;
            for (int pos = comp_out_count[c]; pos < comp_out_count[c + 1]; pos++) {
                int nxt = comp_to[pos];
                bit_or(dst, r.bits + (size_t)nxt * r.words, r.words);
            }
        }
    }

    free(comp_out_count);
    free(indeg);
    free(comp_to);
    free(queue);
    free(topo);
    return r;
}

static int authority_bit_effective(Graph *g, Reachability *r, int source_node, size_t group_bit) {
    if (!r->words) return 0;
    int comp = r->node_comp[source_node];
    if (!bit_get(r->bits + (size_t)comp * r->words, group_bit)) return 0;
    if (g->nodes.items[source_node].kind == NODE_GROUP &&
        g->nodes.items[source_node].group_bit == (int)group_bit) {
        return 0;
    }
    return 1;
}

static int authority_has_group(Graph *g, Reachability *r, int source_node, int group_node) {
    if (group_node < 0 || g->nodes.items[group_node].group_bit < 0) return 0;
    return authority_bit_effective(g, r, source_node, (size_t)g->nodes.items[group_node].group_bit);
}

static int authority_has_admin(Graph *g, Reachability *r, int source_node) {
    if (!r->words) return 0;
    int comp = r->node_comp[source_node];
    uint64_t *bits = r->bits + (size_t)comp * r->words;
    for (size_t w = 0; w < r->words; w++) {
        uint64_t word = bits[w];
        while (word) {
            int b = bit_ctz64(word);
            size_t bit = (w << 6) + (size_t)b;
            if (bit < g->group_count && authority_bit_effective(g, r, source_node, bit)) {
                int group_node = g->group_nodes[bit];
                if (str_contains_casefold_ascii(g->nodes.items[group_node].id, "admin")) return 1;
            }
            word &= word - 1;
        }
    }
    return 0;
}

static size_t authority_count(Graph *g, Reachability *r, int source_node) {
    size_t count = 0;
    if (!r->words) return 0;
    int comp = r->node_comp[source_node];
    uint64_t *bits = r->bits + (size_t)comp * r->words;
    for (size_t w = 0; w < r->words; w++) {
        uint64_t word = bits[w];
        while (word) {
            int b = bit_ctz64(word);
            size_t bit = (w << 6) + (size_t)b;
            if (bit < g->group_count && authority_bit_effective(g, r, source_node, bit)) {
                count++;
            }
            word &= word - 1;
        }
    }
    return count;
}

static size_t authorities_gained_count(Graph *g, Reachability *r, int target_node, int source_node) {
    size_t count = 0;
    for (size_t bit = 0; bit < g->group_count; bit++) {
        int target_has = authority_bit_effective(g, r, target_node, bit);
        int source_has = authority_bit_effective(g, r, source_node, bit);
        if (target_has && !source_has) count++;
    }
    return count;
}

static void write_authority_list_json(FILE *f, Graph *g, Reachability *r, int source_node,
                                      int indent, size_t limit) {
    fprintf(f, "[");
    int first = 1;
    size_t emitted = 0;
    if (r->words) {
        int comp = r->node_comp[source_node];
        uint64_t *bits = r->bits + (size_t)comp * r->words;
        for (size_t w = 0; w < r->words; w++) {
            uint64_t word = bits[w];
            while (word) {
                int b = bit_ctz64(word);
                size_t bit = (w << 6) + (size_t)b;
                if (bit < g->group_count && authority_bit_effective(g, r, source_node, bit)) {
                    if (emitted >= limit) {
                        word = 0;
                        break;
                    }
                    if (first) {
                        fprintf(f, "\n");
                        first = 0;
                    } else {
                        fprintf(f, ",\n");
                    }
                    fprintf(f, "%*s", indent + 2, "");
                    json_write_string(f, g->nodes.items[g->group_nodes[bit]].id);
                    emitted++;
                }
                word &= word - 1;
            }
            if (emitted >= limit) break;
        }
    }
    if (!first) fprintf(f, "\n%*s", indent, "");
    fprintf(f, "]");
}

static void write_authorities_gained_json(FILE *f, Graph *g, Reachability *r,
                                          int target_node, int source_node, int indent,
                                          size_t limit) {
    fprintf(f, "[");
    int first = 1;
    size_t emitted = 0;
    for (size_t bit = 0; bit < g->group_count; bit++) {
        int target_has = authority_bit_effective(g, r, target_node, bit);
        int source_has = authority_bit_effective(g, r, source_node, bit);
        if (target_has && !source_has) {
            if (emitted >= limit) break;
            if (first) {
                fprintf(f, "\n");
                first = 0;
            } else {
                fprintf(f, ",\n");
            }
            fprintf(f, "%*s", indent + 2, "");
            json_write_string(f, g->nodes.items[g->group_nodes[bit]].id);
            emitted++;
        }
    }
    if (!first) fprintf(f, "\n%*s", indent, "");
    fprintf(f, "]");
}

static void kerbresult_push(KerbResult *r, KerbEntry e) {
    if (r->count == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 64;
        r->items = (KerbEntry *)xrealloc(r->items, r->cap * sizeof(KerbEntry));
    }
    r->items[r->count++] = e;
}

static KerbResult identify_kerberoastable(Graph *g, Reachability *reach, const int *da_dist) {
    KerbResult result = {0};
    for (size_t i = 0; i < g->nodes.count; i++) {
        NodeKind kind = g->nodes.items[i].kind;
        if (kind != NODE_USER && kind != NODE_COMPUTER) continue;

        int has_spn = 0;
        KerbEntry e;
        memset(&e, 0, sizeof(e));
        e.node = (int)i;
        e.shortest_path_length = -1;

        for (int pos = g->out.offset[i]; pos < g->out.offset[i + 1]; pos++) {
            int edge_idx = g->out.edge_idx[pos];
            Edge *edge = &g->edges.items[edge_idx];
            if (strcmp(edge->edge_type, "has_spn") == 0) {
                has_spn = 1;
                int target = g->out.to[pos];
                const char *spn = g->nodes.items[target].spn;
                if (spn && spn[0]) strvec_push_copy(&e.spns, spn);
            }
        }

        if (!has_spn) {
            strvec_free(&e.spns);
            continue;
        }

        if (g->da_node >= 0 && da_dist[i] >= 0) {
            e.paths_to_da = get_da_path_route_count(g, (int)i, g->da_node, ROUTE_COUNT_CAP);
            e.shortest_path_length = da_dist[i];
            e.risk_level = "CRITICAL";
        } else {
            e.paths_to_da = 0;
            e.shortest_path_length = -1;
            e.risk_level = authority_has_admin(g, reach, (int)i) ? "HIGH" : "MEDIUM";
        }
        kerbresult_push(&result, e);
    }
    return result;
}

static void acltarget_push_chain(ACLTarget *t, AbuseChain c) {
    if (t->count == t->cap) {
        t->cap = t->cap ? t->cap * 2 : 4;
        t->chains = (AbuseChain *)xrealloc(t->chains, t->cap * sizeof(AbuseChain));
    }
    t->chains[t->count++] = c;
}

static ACLTarget *aclresult_get_target(ACLResult *r, int target) {
    for (size_t i = 0; i < r->count; i++) {
        if (r->items[i].target == target) return &r->items[i];
    }
    if (r->count == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 32;
        r->items = (ACLTarget *)xrealloc(r->items, r->cap * sizeof(ACLTarget));
    }
    ACLTarget *t = &r->items[r->count++];
    memset(t, 0, sizeof(*t));
    t->target = target;
    return t;
}

static ACLResult identify_acl_abuse(Graph *g, Reachability *reach,
                                    const int *da_dist, const int *da_pred,
                                    const int *membership_dist) {
    ACLResult result = {0};
    if (g->da_node < 0) return result;

    for (size_t ei = 0; ei < g->edges.count; ei++) {
        Edge *edge = &g->edges.items[ei];
        if (!edge->is_dangerous) continue;

        int u = edge->src;
        int v = edge->dst;
        if (da_dist[v] < 0 || da_dist[v] > DEFAULT_MAX_PATH_LENGTH) continue;

        Path target_path = path_from_pred(v, g->da_node, da_pred);
        if (!target_path.nodes) continue;

        int source_has_membership_da = membership_dist[u] >= 0;
        int add_chain = 0;
        const char *risk_level = NULL;
        int chain_length = target_path.len + 1;

        if (!source_has_membership_da) {
            add_chain = 1;
            risk_level = authority_has_group(g, reach, v, g->da_node) ? "CRITICAL" : "HIGH";
        } else {
            int path_direct_len = membership_dist[u] + 1;
            if (chain_length < path_direct_len) {
                add_chain = 1;
                risk_level = "MEDIUM";
            }
        }

        if (!add_chain) {
            path_free(&target_path);
            continue;
        }

        AbuseChain c;
        memset(&c, 0, sizeof(c));
        c.source = u;
        c.target = v;
        c.edge_idx = (int)ei;
        c.risk_level = risk_level;
        c.abuse_chain = path_prefix_source(u, &target_path);
        c.chain_length = chain_length;
        path_free(&target_path);

        ACLTarget *target = aclresult_get_target(&result, v);
        acltarget_push_chain(target, c);
    }
    return result;
}

static void delegation_push(DelegationResult *r, DelegationRisk risk) {
    if (r->count == r->cap) {
        r->cap = r->cap ? r->cap * 2 : 32;
        r->items = (DelegationRisk *)xrealloc(r->items, r->cap * sizeof(DelegationRisk));
    }
    r->items[r->count++] = risk;
}

static DelegationResult identify_delegation_risks(Graph *g, Reachability *reach) {
    DelegationResult result = {0};
    for (size_t ei = 0; ei < g->edges.count; ei++) {
        Edge *edge = &g->edges.items[ei];
        if (!str_contains_casefold_ascii(edge->edge_type, "delegation")) continue;

        int has_high = authority_has_admin(g, reach, edge->src);
        DelegationRisk r;
        r.edge_idx = (int)ei;
        r.has_high_privilege = has_high;
        r.risk_level = (strcmp(edge->delegation_type, "unconstrained") == 0 && has_high)
            ? "CRITICAL"
            : "MEDIUM";
        delegation_push(&result, r);
    }
    return result;
}

static int *compute_privilege_distribution(Graph *g, Reachability *reach) {
    int *counts = (int *)xcalloc(g->group_count ? g->group_count : 1, sizeof(int));
    if (!reach->words) return counts;

    for (size_t n = 0; n < g->nodes.count; n++) {
        NodeKind kind = g->nodes.items[n].kind;
        if (kind != NODE_USER && kind != NODE_COMPUTER) continue;
        int comp = reach->node_comp[n];
        uint64_t *bits = reach->bits + (size_t)comp * reach->words;
        for (size_t w = 0; w < reach->words; w++) {
            uint64_t word = bits[w];
            while (word) {
                int b = bit_ctz64(word);
                size_t bit = (w << 6) + (size_t)b;
                if (bit < g->group_count) counts[bit]++;
                word &= word - 1;
            }
        }
    }
    return counts;
}

static size_t total_identities(Graph *g) {
    size_t count = 0;
    for (size_t i = 0; i < g->nodes.count; i++) {
        NodeKind kind = g->nodes.items[i].kind;
        if (kind == NODE_USER || kind == NODE_COMPUTER) count++;
    }
    return count;
}

static size_t total_sampled_da_paths(DAResult *da) {
    size_t total = 0;
    for (size_t i = 0; i < da->count; i++) total += da->items[i].paths.count;
    return total;
}

static int shortest_path_node_length(PathList *paths) {
    int best = INT_MAX;
    for (size_t i = 0; i < paths->count; i++) {
        if (paths->items[i].len < best) best = paths->items[i].len;
    }
    return best == INT_MAX ? 0 : best;
}

static void write_str_array_json(FILE *f, StrVec *v, int indent) {
    fprintf(f, "[");
    if (v->count) fprintf(f, "\n");
    for (size_t i = 0; i < v->count; i++) {
        fprintf(f, "%*s", indent + 2, "");
        json_write_string(f, v->items[i]);
        fprintf(f, "%s\n", i + 1 == v->count ? "" : ",");
    }
    if (v->count) fprintf(f, "%*s", indent, "");
    fprintf(f, "]");
}

static void write_report_json(const char *output_file, Graph *g, Reachability *reach,
                              DAResult *da, KerbResult *kerb, ACLResult *acl,
                              DelegationResult *delegation, int *priv_dist,
                              const ReportOptions *opts) {
    FILE *f = fopen(output_file, "wb");
    if (!f) {
        fprintf(stderr, "[-] Error saving report %s: %s\n", output_file, strerror(errno));
        return;
    }
    size_t authority_limit = opts->full_output ? SIZE_MAX : opts->authority_sample_limit;

    fprintf(f, "{\n");
    fprintf(f, "  \"metadata\": ");
    fwrite(g->metadata_json, 1, g->metadata_len, f);
    fprintf(f, ",\n");
    fprintf(f, "  \"analysis_output_mode\": ");
    json_write_string(f, opts->full_output ? "full" : "compact_refiner");
    fprintf(f, ",\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_identities\": %zu,\n", total_identities(g));
    fprintf(f, "    \"identities_with_da_paths\": %zu,\n", da->count);
    fprintf(f, "    \"total_da_paths\": %zu,\n", total_sampled_da_paths(da));
    fprintf(f, "    \"kerberoastable_identities\": %zu,\n", kerb->count);
    fprintf(f, "    \"acl_abuse_targets\": %zu,\n", acl->count);
    fprintf(f, "    \"delegation_risks\": %zu,\n", delegation->count);
    fprintf(f, "    \"output_mode\": ");
    json_write_string(f, opts->full_output ? "full" : "compact_refiner");
    fprintf(f, ",\n");
    if (opts->full_output) {
        fprintf(f, "    \"authority_sample_limit\": null\n");
    } else {
        fprintf(f, "    \"authority_sample_limit\": %zu\n", opts->authority_sample_limit);
    }
    fprintf(f, "  },\n");

    fprintf(f, "  \"domain_admin_paths\": {");
    if (da->count) fprintf(f, "\n");
    for (size_t i = 0; i < da->count; i++) {
        DAEntry *entry = &da->items[i];
        fprintf(f, "    ");
        json_write_string(f, g->nodes.items[entry->identity].id);
        fprintf(f, ": {\n");
        fprintf(f, "      \"path_count\": %zu,\n", entry->paths.count);
        fprintf(f, "      \"shortest_path_length\": %d,\n", shortest_path_node_length(&entry->paths));
        fprintf(f, "      \"paths\": [");
        if (entry->paths.count) fprintf(f, "\n");
        for (size_t j = 0; j < entry->paths.count; j++) {
            fprintf(f, "        ");
            json_write_path(f, g, &entry->paths.items[j], 8);
            fprintf(f, "%s\n", j + 1 == entry->paths.count ? "" : ",");
        }
        if (entry->paths.count) fprintf(f, "      ");
        fprintf(f, "]\n");
        fprintf(f, "    }%s\n", i + 1 == da->count ? "" : ",");
    }
    fprintf(f, "  },\n");

    fprintf(f, "  \"kerberoastable_analysis\": {");
    if (kerb->count) fprintf(f, "\n");
    for (size_t i = 0; i < kerb->count; i++) {
        KerbEntry *e = &kerb->items[i];
        fprintf(f, "    ");
        json_write_string(f, g->nodes.items[e->node].id);
        fprintf(f, ": {\n");
        fprintf(f, "      \"spns\": ");
        write_str_array_json(f, &e->spns, 6);
        fprintf(f, ",\n");
        fprintf(f, "      \"spn_count\": %zu,\n", e->spns.count);
        fprintf(f, "      \"paths_to_da\": %d,\n", e->paths_to_da);
        if (e->shortest_path_length >= 0) {
            fprintf(f, "      \"shortest_path_length\": %d,\n", e->shortest_path_length);
        } else {
            fprintf(f, "      \"shortest_path_length\": null,\n");
        }
        size_t auth_count = authority_count(g, reach, e->node);
        fprintf(f, "      \"authorities\": ");
        write_authority_list_json(f, g, reach, e->node, 6, authority_limit);
        fprintf(f, ",\n");
        fprintf(f, "      \"authority_count\": %zu,\n", auth_count);
        fprintf(f, "      \"authorities_truncated\": %s,\n",
                (!opts->full_output && auth_count > authority_limit) ? "true" : "false");
        fprintf(f, "      \"risk_level\": ");
        json_write_string(f, e->risk_level);
        fprintf(f, ",\n");
        fprintf(f, "      \"enabled\": %s\n", g->nodes.items[e->node].enabled ? "true" : "false");
        fprintf(f, "    }%s\n", i + 1 == kerb->count ? "" : ",");
    }
    fprintf(f, "  },\n");

    fprintf(f, "  \"acl_abuse_chains\": {");
    if (acl->count) fprintf(f, "\n");
    for (size_t i = 0; i < acl->count; i++) {
        ACLTarget *target = &acl->items[i];
        fprintf(f, "    ");
        json_write_string(f, g->nodes.items[target->target].id);
        fprintf(f, ": [\n");
        for (size_t j = 0; j < target->count; j++) {
            AbuseChain *c = &target->chains[j];
            Edge *edge = &g->edges.items[c->edge_idx];
            const char *permission = edge->extended_right[0] ? edge->extended_right : edge->edge_type;
            fprintf(f, "      {\n");
            fprintf(f, "        \"source\": "); json_write_string(f, g->nodes.items[c->source].id); fprintf(f, ",\n");
            fprintf(f, "        \"source_type\": "); json_write_string(f, g->nodes.items[c->source].node_type); fprintf(f, ",\n");
            fprintf(f, "        \"target\": "); json_write_string(f, g->nodes.items[c->target].id); fprintf(f, ",\n");
            fprintf(f, "        \"target_type\": "); json_write_string(f, g->nodes.items[c->target].node_type); fprintf(f, ",\n");
            fprintf(f, "        \"permission\": "); json_write_string(f, permission); fprintf(f, ",\n");
            fprintf(f, "        \"full_permission\": "); json_write_string(f, edge->permission); fprintf(f, ",\n");
            size_t gained_count = authorities_gained_count(g, reach, c->target, c->source);
            fprintf(f, "        \"authorities_gained\": ");
            write_authorities_gained_json(f, g, reach, c->target, c->source, 8, authority_limit);
            fprintf(f, ",\n");
            fprintf(f, "        \"authorities_gained_count\": %zu,\n", gained_count);
            fprintf(f, "        \"authorities_gained_truncated\": %s,\n",
                    (!opts->full_output && gained_count > authority_limit) ? "true" : "false");
            fprintf(f, "        \"risk_level\": "); json_write_string(f, c->risk_level); fprintf(f, ",\n");
            fprintf(f, "        \"abuse_chain\": ");
            json_write_path(f, g, &c->abuse_chain, 8);
            fprintf(f, ",\n");
            fprintf(f, "        \"chain_length\": %d,\n", c->chain_length);
            fprintf(f, "        \"explanation\": ");
            StrBuf expl; sb_init(&expl);
            sb_puts(&expl, g->nodes.items[c->source].id);
            if (strcmp(c->risk_level, "MEDIUM") == 0) {
                sb_puts(&expl, " can use ");
                sb_puts(&expl, permission);
                sb_puts(&expl, " on ");
                sb_puts(&expl, g->nodes.items[c->target].id);
                sb_puts(&expl, " for shorter path to DA");
            } else {
                sb_puts(&expl, " can use ");
                sb_puts(&expl, permission);
                sb_puts(&expl, " on ");
                sb_puts(&expl, g->nodes.items[c->target].id);
                sb_puts(&expl, " to gain access to Domain Admins via: ");
                for (int pi = 0; pi < c->abuse_chain.len; pi++) {
                    if (pi) sb_puts(&expl, " -> ");
                    sb_puts(&expl, g->nodes.items[c->abuse_chain.nodes[pi]].id);
                }
            }
            char *expl_s = sb_take(&expl);
            json_write_string(f, expl_s);
            free(expl_s);
            fprintf(f, "\n");
            fprintf(f, "      }%s\n", j + 1 == target->count ? "" : ",");
        }
        fprintf(f, "    ]%s\n", i + 1 == acl->count ? "" : ",");
    }
    fprintf(f, "  },\n");

    fprintf(f, "  \"delegation_risks\": [");
    if (delegation->count) fprintf(f, "\n");
    for (size_t i = 0; i < delegation->count; i++) {
        DelegationRisk *r = &delegation->items[i];
        Edge *edge = &g->edges.items[r->edge_idx];
        fprintf(f, "    {\n");
        fprintf(f, "      \"source\": "); json_write_string(f, g->nodes.items[edge->src].id); fprintf(f, ",\n");
        fprintf(f, "      \"target\": "); json_write_string(f, g->nodes.items[edge->dst].id); fprintf(f, ",\n");
        fprintf(f, "      \"delegation_type\": "); json_write_string(f, edge->delegation_type); fprintf(f, ",\n");
        fprintf(f, "      \"edge_type\": "); json_write_string(f, edge->edge_type); fprintf(f, ",\n");
        fprintf(f, "      \"conditional\": %s,\n", edge->conditional ? "true" : "false");
        fprintf(f, "      \"conditions\": ");
        write_str_array_json(f, &edge->conditions, 6);
        fprintf(f, ",\n");
        fprintf(f, "      \"has_high_privilege\": %s,\n", r->has_high_privilege ? "true" : "false");
        fprintf(f, "      \"risk_level\": "); json_write_string(f, r->risk_level); fprintf(f, "\n");
        fprintf(f, "    }%s\n", i + 1 == delegation->count ? "" : ",");
    }
    if (delegation->count) fprintf(f, "  ");
    fprintf(f, "],\n");

    fprintf(f, "  \"privilege_distribution\": {");
    if (g->group_count) fprintf(f, "\n");
    for (size_t i = 0; i < g->group_count; i++) {
        fprintf(f, "    ");
        json_write_string(f, g->nodes.items[g->group_nodes[i]].id);
        fprintf(f, ": %d%s\n", priv_dist[i], i + 1 == g->group_count ? "" : ",");
    }
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    fclose(f);
    printf("[+] Report saved to: %s\n", output_file);
}

static void print_path_text(Graph *g, const Path *p) {
    for (int i = 0; i < p->len; i++) {
        if (i) printf(" -> ");
        printf("%s", g->nodes.items[p->nodes[i]].id);
    }
}

static void print_authority_list_text(Graph *g, Reachability *reach, int source_node) {
    int first = 1;
    for (size_t bit = 0; bit < g->group_count; bit++) {
        if (authority_bit_effective(g, reach, source_node, bit)) {
            if (!first) printf(", ");
            printf("%s", g->nodes.items[g->group_nodes[bit]].id);
            first = 0;
        }
    }
}

static void print_authorities_gained_text(Graph *g, Reachability *reach, int target, int source,
                                          const ReportOptions *opts) {
    int first = 1;
    size_t emitted = 0;
    size_t total = authorities_gained_count(g, reach, target, source);
    size_t limit = opts->full_output ? SIZE_MAX : opts->authority_sample_limit;
    for (size_t bit = 0; bit < g->group_count; bit++) {
        if (authority_bit_effective(g, reach, target, bit) &&
            !authority_bit_effective(g, reach, source, bit)) {
            if (emitted >= limit) break;
            if (!first) printf(", ");
            printf("%s", g->nodes.items[g->group_nodes[bit]].id);
            first = 0;
            emitted++;
        }
    }
    if (!opts->full_output && total > limit) {
        if (!first) printf(", ");
        printf("... (%zu total, %zu omitted)", total, total - emitted);
    } else if (first) {
        printf("(none)");
    }
}

static void print_report_text(Graph *g, Reachability *reach, DAResult *da, KerbResult *kerb,
                              ACLResult *acl, DelegationResult *delegation,
                              const ReportOptions *opts) {
    printf("\n================================================================================\n");
    printf("ACTIVE DIRECTORY AUTHORIZATION ANALYSIS REPORT\n");
    printf("================================================================================\n");
    printf("\nDomain: %s\n", g->metadata_domain ? g->metadata_domain : "Unknown");
    printf("Collection Date: %s\n", g->metadata_collection_date ? g->metadata_collection_date : "Unknown");
    printf("\n================================================================================\n");
    printf("EXECUTIVE SUMMARY\n");
    printf("================================================================================\n");
    printf("\nTotal Identities: %zu\n", total_identities(g));
    printf("Identities with Domain Admin Paths: %zu\n", da->count);
    printf("Total Privilege Escalation Paths (sampled): %zu\n", total_sampled_da_paths(da));
    printf("Kerberoastable Identities: %zu\n", kerb->count);
    printf("ACL Abuse Targets: %zu\n", acl->count);
    printf("Delegation Risks: %zu\n", delegation->count);

    if (da->count) {
        printf("\n================================================================================\n");
        printf("DOMAIN ADMIN PRIVILEGE PATHS\n");
        printf("================================================================================\n");
        for (size_t i = 0; i < da->count; i++) {
            DAEntry *entry = &da->items[i];
            printf("\n%s\n", g->nodes.items[entry->identity].id);
            printf("  Path Count (sampled, capped at %d): %zu\n", MAX_EXAMPLE_PATHS, entry->paths.count);
            printf("  Shortest Path: %d hops\n", shortest_path_node_length(&entry->paths));
            printf("  Example Paths:\n");
            size_t show = entry->paths.count < 2 ? entry->paths.count : 2;
            for (size_t j = 0; j < show; j++) {
                printf("    %zu. ", j + 1);
                print_path_text(g, &entry->paths.items[j]);
                printf("\n");
            }
        }
    }

    if (kerb->count) {
        printf("\n================================================================================\n");
        printf("KERBEROASTABLE IDENTITY ANALYSIS\n");
        printf("================================================================================\n");
        for (size_t i = 0; i < kerb->count; i++) {
            KerbEntry *e = &kerb->items[i];
            printf("\n%s\n", g->nodes.items[e->node].id);
            printf("  SPNs: ");
            for (size_t j = 0; j < e->spns.count; j++) {
                if (j) printf(", ");
                printf("%s", e->spns.items[j]);
            }
            printf("\n");
            printf("  Paths to DA (estimate, capped): %d\n", e->paths_to_da);
            printf("  Risk Level: %s\n", e->risk_level);
            if (e->paths_to_da > 0) {
                printf("  Shortest Path Length: %d hops\n", e->shortest_path_length);
            }
        }
    }

    if (acl->count) {
        printf("\n================================================================================\n");
        printf("ACL PERMISSION ABUSE CHAINS\n");
        printf("================================================================================\n");
        for (size_t i = 0; i < acl->count; i++) {
            ACLTarget *target = &acl->items[i];
            printf("\nTarget: %s\n", g->nodes.items[target->target].id);
            for (size_t j = 0; j < target->count; j++) {
                AbuseChain *c = &target->chains[j];
                Edge *edge = &g->edges.items[c->edge_idx];
                const char *permission = edge->extended_right[0] ? edge->extended_right : edge->edge_type;
                printf("  Source: %s\n", g->nodes.items[c->source].id);
                printf("  Permission: %s\n", permission);
                printf("  Risk Level: %s\n", c->risk_level);
                printf("  Full Path to DA (%d hops):\n    ", c->chain_length);
                print_path_text(g, &c->abuse_chain);
                printf("\n  Authorities Gained: ");
                print_authorities_gained_text(g, reach, c->target, c->source, opts);
                printf("\n");
            }
        }
    }

    if (delegation->count) {
        printf("\n================================================================================\n");
        printf("DELEGATION CONFIGURATION RISKS\n");
        printf("================================================================================\n");
        for (size_t i = 0; i < delegation->count; i++) {
            DelegationRisk *r = &delegation->items[i];
            Edge *edge = &g->edges.items[r->edge_idx];
            printf("\nSource: %s\n", g->nodes.items[edge->src].id);
            printf("  Delegation Type: %s\n", edge->delegation_type);
            printf("  Target: %s\n", g->nodes.items[edge->dst].id);
            printf("  Risk Level: %s\n", r->risk_level);
            if (edge->conditional) {
                printf("  Conditions: ");
                for (size_t j = 0; j < edge->conditions.count; j++) {
                    if (j) printf(", ");
                    printf("%s", edge->conditions.items[j]);
                }
                printf("\n");
            }
        }
    }

    printf("\n================================================================================\n");
    printf("END OF REPORT\n");
    printf("================================================================================\n");
}

static char *analysis_output_path(const char *input) {
    const char *needle = "_graph.json";
    const char *hit = strstr(input, needle);
    if (hit) {
        size_t prefix = (size_t)(hit - input);
        const char *suffix = hit + strlen(needle);
        const char *replacement = "_analysis.json";
        size_t len = prefix + strlen(replacement) + strlen(suffix);
        char *out = (char *)xmalloc(len + 1);
        memcpy(out, input, prefix);
        strcpy(out + prefix, replacement);
        strcat(out, suffix);
        return out;
    }
    size_t len = strlen(input) + strlen("_analysis.json");
    char *out = (char *)xmalloc(len + 1);
    strcpy(out, input);
    strcat(out, "_analysis.json");
    return out;
}

static void run_analysis(const char *graph_file, const ReportOptions *opts) {
    Graph g;
    graph_init(&g);
    printf("[*] Loading graph from: %s\n", graph_file);
    if (!parse_graph_json(graph_file, &g)) die("Failed to load graph JSON");
    graph_finalize(&g);
    printf("    [+] Loaded %zu nodes\n", g.nodes.count);
    printf("    [+] Loaded %zu edges\n", g.edges.count);
    if (g.metadata_domain) printf("    Domain: %s\n", g.metadata_domain);
    if (g.metadata_collection_date) printf("    Collection Date: %s\n", g.metadata_collection_date);
    printf("[+] Graph loaded: %zu nodes, %zu edges\n", g.nodes.count, g.edges.count);

    printf("\n[*] Analyzing authorization state...\n");
    int *da_pred = NULL;
    int *da_dist = compute_reverse_bfs(&g, g.da_node, 0, &da_pred);
    int *membership_pred = NULL;
    int *membership_dist = compute_reverse_bfs(&g, g.da_node, 1, &membership_pred);
    Reachability reach = build_reachability(&g);
    DAResult da = build_da_result(&g, da_dist, da_pred);
    KerbResult kerb = identify_kerberoastable(&g, &reach, da_dist);
    ACLResult acl = identify_acl_abuse(&g, &reach, da_dist, da_pred, membership_dist);
    DelegationResult delegation = identify_delegation_risks(&g, &reach);
    int *priv_dist = compute_privilege_distribution(&g, &reach);

    char *out = analysis_output_path(graph_file);
    if (!opts->full_output) {
        printf("[*] Output mode: compact_refiner (authority lists sampled at %zu entries; use --full for exhaustive export)\n",
               opts->authority_sample_limit);
    } else {
        printf("[*] Output mode: full (authority lists will be exhaustively materialized)\n");
    }
    write_report_json(out, &g, &reach, &da, &kerb, &acl, &delegation, priv_dist, opts);
    print_report_text(&g, &reach, &da, &kerb, &acl, &delegation, opts);
    printf("\n[+] Analysis complete!\n");
    free(out);
    free(priv_dist);
    free(da_dist);
    free(da_pred);
    free(membership_dist);
    free(membership_pred);
}

static void collect_da_set(Graph *g, const int *da_dist, StrIntMap *set) {
    for (size_t i = 0; i < g->nodes.count; i++) {
        NodeKind kind = g->nodes.items[i].kind;
        if ((kind == NODE_USER || kind == NODE_COMPUTER) && da_dist[i] >= 0) {
            map_put(set, g->nodes.items[i].id, 1);
        }
    }
}

static void collect_kerb_set(Graph *g, StrIntMap *set) {
    for (size_t i = 0; i < g->nodes.count; i++) {
        NodeKind kind = g->nodes.items[i].kind;
        if (kind != NODE_USER && kind != NODE_COMPUTER) continue;
        int has_spn = 0;
        for (int pos = g->out.offset[i]; pos < g->out.offset[i + 1]; pos++) {
            int edge_idx = g->out.edge_idx[pos];
            if (strcmp(g->edges.items[edge_idx].edge_type, "has_spn") == 0) {
                has_spn = 1;
                break;
            }
        }
        if (has_spn) map_put(set, g->nodes.items[i].id, 1);
    }
}

static uint64_t fnv1a_pair(const char *a, const char *b) {
    uint64_t h = 1469598103934665603ull;
    while (*a) { h ^= (unsigned char)*a++; h *= 1099511628211ull; }
    h ^= 0xffu; h *= 1099511628211ull;
    while (*b) { h ^= (unsigned char)*b++; h *= 1099511628211ull; }
    return h ? h : 1;
}

typedef struct {
    const char *src;
    const char *dst;
    uint64_t hash;
    int used;
} PairEntry;

typedef struct {
    PairEntry *entries;
    size_t cap;
    size_t count;
} PairSet;

static void pairset_rehash(PairSet *s, size_t cap) {
    PairEntry *old = s->entries;
    size_t old_cap = s->cap;
    s->entries = (PairEntry *)xcalloc(cap, sizeof(PairEntry));
    s->cap = cap;
    s->count = 0;
    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].used) continue;
        size_t pos = (size_t)old[i].hash & (s->cap - 1);
        while (s->entries[pos].used) pos = (pos + 1) & (s->cap - 1);
        s->entries[pos] = old[i];
        s->count++;
    }
    free(old);
}

static void pairset_ensure(PairSet *s) {
    if (!s->cap) pairset_rehash(s, 1024);
    else if ((s->count + 1) * 10 >= s->cap * 7) pairset_rehash(s, s->cap * 2);
}

static void pairset_add(PairSet *s, const char *src, const char *dst) {
    pairset_ensure(s);
    uint64_t h = fnv1a_pair(src, dst);
    size_t pos = (size_t)h & (s->cap - 1);
    while (s->entries[pos].used) {
        if (s->entries[pos].hash == h &&
            strcmp(s->entries[pos].src, src) == 0 &&
            strcmp(s->entries[pos].dst, dst) == 0) return;
        pos = (pos + 1) & (s->cap - 1);
    }
    s->entries[pos].used = 1;
    s->entries[pos].hash = h;
    s->entries[pos].src = src;
    s->entries[pos].dst = dst;
    s->count++;
}

static int pairset_has(PairSet *s, const char *src, const char *dst) {
    if (!s->cap) return 0;
    uint64_t h = fnv1a_pair(src, dst);
    size_t pos = (size_t)h & (s->cap - 1);
    while (s->entries[pos].used) {
        if (s->entries[pos].hash == h &&
            strcmp(s->entries[pos].src, src) == 0 &&
            strcmp(s->entries[pos].dst, dst) == 0) return 1;
        pos = (pos + 1) & (s->cap - 1);
    }
    return 0;
}

static PairSet build_pairset(Graph *g) {
    PairSet set = {0};
    for (size_t i = 0; i < g->edges.count; i++) {
        Edge *e = &g->edges.items[i];
        pairset_add(&set, g->nodes.items[e->src].id, g->nodes.items[e->dst].id);
    }
    return set;
}

static void json_write_set_difference(FILE *f, StrIntMap *a, StrIntMap *b) {
    fprintf(f, "[");
    int first = 1;
    for (size_t i = 0; i < a->cap; i++) {
        if (!a->entries[i].used) continue;
        int dummy = 0;
        if (!map_get(b, a->entries[i].key, &dummy)) {
            if (!first) fprintf(f, ", ");
            json_write_string(f, a->entries[i].key);
            first = 0;
        }
    }
    fprintf(f, "]");
}

static size_t set_difference_count(StrIntMap *a, StrIntMap *b) {
    size_t n = 0;
    for (size_t i = 0; i < a->cap; i++) {
        if (!a->entries[i].used) continue;
        int dummy = 0;
        if (!map_get(b, a->entries[i].key, &dummy)) n++;
    }
    return n;
}

static void run_compare(const char *current_file, const char *other_file) {
    Graph current, other;
    graph_init(&current);
    graph_init(&other);
    if (!parse_graph_json(current_file, &current)) die("Failed to load current graph");
    if (!parse_graph_json(other_file, &other)) die("Failed to load comparison graph");
    graph_finalize(&current);
    graph_finalize(&other);

    int *cur_pred = NULL, *other_pred = NULL;
    int *cur_dist = compute_reverse_bfs(&current, current.da_node, 0, &cur_pred);
    int *other_dist = compute_reverse_bfs(&other, other.da_node, 0, &other_pred);

    StrIntMap cur_da, other_da, cur_kerb, other_kerb;
    map_init(&cur_da); map_init(&other_da); map_init(&cur_kerb); map_init(&other_kerb);
    collect_da_set(&current, cur_dist, &cur_da);
    collect_da_set(&other, other_dist, &other_da);
    collect_kerb_set(&current, &cur_kerb);
    collect_kerb_set(&other, &other_kerb);

    PairSet cur_edges = build_pairset(&current);
    PairSet other_edges = build_pairset(&other);
    size_t new_edges = 0, removed_edges = 0;
    for (size_t i = 0; i < cur_edges.cap; i++) {
        if (cur_edges.entries[i].used &&
            !pairset_has(&other_edges, cur_edges.entries[i].src, cur_edges.entries[i].dst)) new_edges++;
    }
    for (size_t i = 0; i < other_edges.cap; i++) {
        if (other_edges.entries[i].used &&
            !pairset_has(&cur_edges, other_edges.entries[i].src, other_edges.entries[i].dst)) removed_edges++;
    }

    printf("{\n");
    printf("  \"current_state\": {\n");
    printf("    \"da_paths\": %zu,\n", cur_da.count);
    printf("    \"total_edges\": %zu,\n", cur_edges.count);
    printf("    \"kerberoastable\": %zu\n", cur_kerb.count);
    printf("  },\n");
    printf("  \"previous_state\": {\n");
    printf("    \"da_paths\": %zu,\n", other_da.count);
    printf("    \"total_edges\": %zu,\n", other_edges.count);
    printf("    \"kerberoastable\": %zu\n", other_kerb.count);
    printf("  },\n");
    printf("  \"changes\": {\n");
    printf("    \"new_da_paths\": "); json_write_set_difference(stdout, &cur_da, &other_da); printf(",\n");
    printf("    \"removed_da_paths\": "); json_write_set_difference(stdout, &other_da, &cur_da); printf(",\n");
    printf("    \"new_edges\": %zu,\n", new_edges);
    printf("    \"removed_edges\": %zu,\n", removed_edges);
    printf("    \"new_kerberoastable\": "); json_write_set_difference(stdout, &cur_kerb, &other_kerb); printf("\n");
    printf("  },\n");
    printf("  \"delta\": {\n");
    printf("    \"da_paths\": %lld,\n", (long long)cur_da.count - (long long)other_da.count);
    printf("    \"edges\": %lld,\n", (long long)cur_edges.count - (long long)other_edges.count);
    printf("    \"kerberoastable\": %lld\n", (long long)cur_kerb.count - (long long)other_kerb.count);
    printf("  }\n");
    printf("}\n");

    free(cur_dist); free(cur_pred);
    free(other_dist); free(other_pred);
}

static void usage(void) {
    printf("================================================================================\n");
    printf("Authorization Graph Analyzer - Usage\n");
    printf("================================================================================\n");
    printf("\nDirect Graph Analysis:\n");
    printf("  analyzer.exe <graph_json_file> [--full] [--authority-sample-limit N]\n");
    printf("  Example: analyzer.exe blues_state0_clean_graph.json\n");
    printf("\nOutput Modes:\n");
    printf("  default                         Compact/refiner-safe JSON output. Large authority\n");
    printf("                                  lists are sampled and exact counts are retained.\n");
    printf("  --full                          Exhaustive legacy export. May create very large\n");
    printf("                                  analysis JSON files on dense graphs.\n");
    printf("  --authority-sample-limit N       Compact-mode sample size for authorities and\n");
    printf("                                  authorities_gained (default: %u).\n", DEFAULT_AUTHORITY_SAMPLE_LIMIT);
    printf("\nState Comparison:\n");
    printf("  analyzer.exe <graph_json> --compare <other_graph_json>\n");
    printf("\nNote: this C engine consumes graph_builder.py graph JSON directly. Raw AD JSON\n");
    printf("      compatibility remains the responsibility of graph_builder.py.\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    ReportOptions opts;
    opts.full_output = 0;
    opts.authority_sample_limit = DEFAULT_AUTHORITY_SAMPLE_LIMIT;
    const char *compare_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0) {
            fprintf(stderr, "[-] --raw is not supported by the C engine. Run graph_builder.py first.\n");
            return 1;
        } else if (strcmp(argv[i], "--full") == 0) {
            opts.full_output = 1;
        } else if (strcmp(argv[i], "--authority-sample-limit") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] --authority-sample-limit requires a positive integer value.\n");
                return 1;
            }
            char *end = NULL;
            unsigned long long parsed = strtoull(argv[++i], &end, 10);
            if (!end || *end != '\0' || parsed == 0) {
                fprintf(stderr, "[-] Invalid --authority-sample-limit value: %s\n", argv[i]);
                return 1;
            }
            opts.authority_sample_limit = (size_t)parsed;
        } else if (strcmp(argv[i], "--compare") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] --compare requires a comparison graph JSON path.\n");
                return 1;
            }
            compare_file = argv[++i];
        }
    }

    if (compare_file) {
        run_compare(argv[1], compare_file);
        return 0;
    }

    printf("================================================================================\n");
    printf("Authorization Graph Analyzer\n");
    printf("================================================================================\n\n");
    run_analysis(argv[1], &opts);
    return 0;
}

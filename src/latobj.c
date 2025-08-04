/*
The MIT License (MIT)

Copyright (c) Latino - Lenguaje de Programacion

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>

#define LATINO_CORE

#include "latdic.h"
#include "latgc.h"
#include "latino.h"
#include "latlist.h"
#include "latmem.h"
#include "latobj.h"

lat_objeto latO_nulo_ = {{NULL}, T_NULL};
lat_objeto latO_verdadero_ = {.val.logico = 1, .tipo = T_BOOL};
lat_objeto latO_falso_ = {.val.logico = 0, T_BOOL};

char *minusculas(const char *str);
char *logico_acadena(int i);
char *decimal_acadena(double d);
char *entero_acadena(int i);
char *reemplazar(char *str, const char *orig, const char *rep);
char *analizar_fmt(const char *s, size_t len);
char *analizar(const char *s, size_t len);

void latO_asignar_ctx(lat_mv *mv, lat_objeto *ns, const char *name,
                      lat_objeto *o) {
    if (ns->tipo != T_CONTEXT) {
        latC_error(mv, "Objeto no es un contexto");
    } else {
        hash_map *h = getCtx(ns);
        if (strlen(name) > MAX_ID_LENGTH) {
            latC_error(mv, "Nombre de id mayor a %i caracteres", MAX_ID_LENGTH);
        }
        latH_asignar(mv, h, name, o);
    }
}

lat_objeto *latO_obtener_contexto(lat_mv *mv, lat_objeto *ns,
                                  const char *name) {
    if (ns->tipo != T_CONTEXT) {
        latC_error(mv, "Objeto no es un contexto");
    } else {
        hash_map *h = getCtx(ns);
        lat_objeto *ret = (lat_objeto *)latH_obtener(h, name);
        return ret;
    }
    return NULL;
}

lat_objeto *latO_crear(lat_mv *mv) {
    lat_objeto *ret = (lat_objeto *)latM_asignar(mv, sizeof(lat_objeto));
#if DEPURAR_MEM
    printf("latO_crear.ret: %p\n", ret);
#endif
    ret->tipo = T_NULL;
    ret->tam = sizeof(lat_objeto);
    ret->nref = 0;
    ret->es_vararg = 0;
    ret->esconst = 0;
#ifdef HABILITAR_GC
    gc_agregar(mv, ret);
#endif // HABILITAR_GC
    return ret;
}

lat_objeto *latO_contexto_crear(lat_mv *mv) {
    lat_objeto *ret = latO_crear(mv);
    ret->tipo = T_CONTEXT;
    ret->tam += sizeof(hash_map);
    setCtx(ret, latH_crear(mv));
    return ret;
}

static lat_cadena *nuevaCad(lat_mv *mv, const char *str, size_t l,
                            unsigned int h) {
    lat_cadena *ts;
    stringtable *tb;
    if (l + 1 > LAT_SIZE_MAX - sizeof(lat_cadena)) {
        latC_error(mv, "Cadena muy larga");
    }
    ts = (lat_cadena *)latM_asignar(mv, (l + 1) + sizeof(lat_cadena));
#if DEPURAR_MEM
    printf("nuevaCad.ts: %p\n", ts);
#endif
    ts->tsv.len = l;
    ts->tsv.hash = h;
    ts->tsv.marked = 0;
    ts->tsv.tipo = T_STR;
    ts->tsv.reserved = 0;
    memcpy(ts + 1, str, l);
    ((char *)(ts + 1))[l] = '\0';
    tb = &mv->global->strt;
    h = lmod(h, tb->size);
    ts->tsv.next = tb->hash[h];
    tb->hash[h] = (lat_gcobjeto *)ts;
    tb->nuse++;
    if (tb->nuse > tb->size && tb->size <= INT_MAX / 2) {
        latS_resize(mv, tb->size * 2);
    }
    return ts;
}

static lat_cadena *latO_cadenaNueva(lat_mv *mv, const char *str, size_t l) {
    lat_gcobjeto *o;
    unsigned int h = (unsigned int)l;
    size_t step = (l >> 5) + 1;
    size_t l1;
    for (l1 = l; l1 >= step; l1 -= step) {
        h = h ^ ((h << 5) + (h >> 2) + (unsigned char)str[l1 - 1]);
    }
    for (o = mv->global->strt.hash[lmod(h, mv->global->strt.size)]; o != NULL;
         o = o->gch.next) {
        lat_cadena *ts = &(o->cadena);
        if (ts->tsv.len == l && (0 == memcmp(str, getstr(ts), l))) {
            return ts;
        }
    }
    return nuevaCad(mv, str, l, h);
}

lat_objeto *latO_crear_funcion(lat_mv *mv) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latO_crear_funcion: %p\n", ret);
#endif
    ret->tipo = T_FUN;
    return ret; // We don't do anything here: all bytecode will be added
                // later
}

lat_objeto *latO_crear_cfuncion(lat_mv *mv) {
    lat_objeto *ret = latO_crear(mv);
    ret->tipo = T_CFUN;
    ret->marca = 0;
    return ret;
}

void latO_destruir(lat_mv *mv, lat_objeto *o) {
    if (o == NULL)
        return;
    switch (o->tipo) {
        case T_CONTEXT:
            latH_limpiar(mv, getCtx(o));
            break;
        case T_LIST: {
            lista *list = latC_checar_lista(mv, o);
            // OPTIMIZACIÓN: Evitar recursión profunda y liberar nodos de lista de forma iterativa
            if (list->longitud > 0) {
                nodo_lista *cur = list->primero;
                while (cur) {
                    lat_objeto *tmp = (lat_objeto *)cur->valor;
                    if (tmp != NULL) {
                        latO_destruir(mv, tmp);
                    }
                    cur = cur->siguiente;
                }
            }
            latL_destruir(mv, list);
        } break;
        case T_DIC:
            latH_destruir(mv, latC_checar_dic(mv, o));
            break;
        case T_STR: {
            lat_cadena *str = (lat_cadena *)getCadena(o);
            latM_liberar(mv, str);
        } break;
        case T_FUN: {
            lat_funcion *fun = getFun(o);
            lat_bytecode *inslist = fun->codigo;
            latM_liberar(mv, inslist);
            latM_liberar(mv, fun);
        } break;
        case T_CFUN:
        case T_NUMERIC:
            // No hay recursos dinámicos que liberar
            break;
        case T_NULL:
        case T_BOOL:
            // Nunca colectar nulo y booleano.
            return;
        default:
            return;
    }
    latM_liberar(mv, o);
}

// String builder para serialización eficiente
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sbuilder;

static void sb_init(sbuilder *sb, size_t cap) {
    sb->buf = malloc(cap);
    sb->len = 0;
    sb->cap = cap;
    sb->buf[0] = '\0';
}

static void sb_append(sbuilder *sb, const char *s) {
    size_t slen = strlen(s);
    if (sb->len + slen + 1 > sb->cap) {
        sb->cap = (sb->len + slen + 1) * 2;
        sb->buf = realloc(sb->buf, sb->cap);
    }
    memcpy(sb->buf + sb->len, s, slen + 1);
    sb->len += slen;
}

static char *sb_build(sbuilder *sb) {
    return sb->buf;
}

// OPTIMIZACIÓN: Mejorar latL_acadena para evitar uso excesivo de strcat y reducir reallocs
char *latL_acadena(lat_mv *mv, lista *list) {
    sbuilder sb;
    sb_init(&sb, 128 + list->longitud * 32);
    sb_append(&sb, "[");
    int first = 1;
    LIST_FOREACH(list, primero, siguiente, cur) {
        if (!first) sb_append(&sb, ", ");
        first = 0;
        if (cur->valor) {
            lat_objeto *o = (lat_objeto *)cur->valor;
            char *tmp = latC_astring(mv, o);
            if (o->tipo == T_STR) sb_append(&sb, "\"");
            sb_append(&sb, tmp);
            if (o->tipo == T_STR) sb_append(&sb, "\"");
            free(tmp);
        }
    }
    sb_append(&sb, "]");
    return sb_build(&sb);
}

// OPTIMIZACIÓN: Mejorar latH_acadena para evitar uso excesivo de strcat y liberar memoria correctamente
char *latH_acadena(lat_mv *mv, hash_map *m) {
    sbuilder sb;
    sb_init(&sb, 128);
    sb_append(&sb, "{");
    int first = 1;
    for (int i = 0; i < 256; i++) {
        lista *list = m->buckets[i];
        if (list) {
            LIST_FOREACH(list, primero, siguiente, cur) {
                if (cur->valor) {
                    if (!first) sb_append(&sb, ", ");
                    first = 0;
                    sb_append(&sb, "\"");
                    sb_append(&sb, ((hash_val *)cur->valor)->llave);
                    sb_append(&sb, "\": ");
                    lat_objeto *val = (lat_objeto *)((hash_val *)cur->valor)->valor;
                    if (val == NULL) {
                        sb_append(&sb, "\"nulo\"");
                    } else {
                        if (val->tipo == T_STR) sb_append(&sb, "\"");
                        char *tmp = latC_astring(mv, val);
                        sb_append(&sb, tmp);
                        if (val->tipo == T_STR) sb_append(&sb, "\"");
                        free(tmp);
                    }
                }
            }
        }
    }
    sb_append(&sb, "}");
    return sb_build(&sb);
}

void latL_modificar_elemento(lat_mv *mv, lista *list, void *data, int pos) {
    int i = 0;
    if (pos < 0 || pos >= latL_longitud(list)) {
        latC_error(mv, "Indice fuera de rango");
    }

    LIST_FOREACH(list, primero, siguiente, cur) {
        if (i == pos) {
            cur->valor = data;
        }
        i++;
    }
}

int latL_comparar(lat_mv *mv, lista *lhs, lista *rhs) {
    int res = 0;
    int len1 = latL_longitud(lhs);
    int len2 = latL_longitud(rhs);
    if (len1 < len2) {
        return -1;
    }
    if (len1 > len2) {
        return 1;
    }
    int i;
    for (i = 0; i < len1; i++) {
        lat_objeto *tmp1 = latL_obtener_elemento(mv, lhs, i);
        lat_objeto *tmp2 = latL_obtener_elemento(mv, rhs, i);
        res = latO_comparar(mv, tmp1, tmp2);
        if (res < 0) {
            return -1;
        }
        if (res > 0) {
            return 1;
        }
    }
    return res;
}

int latL_obtener_indice(lat_mv *mv, lista *list, void *data) {
    int i = 0;
    lat_objeto *find = (lat_objeto *)data;

    LIST_FOREACH(list, primero, siguiente, cur) {
        // if (memcmp(cur->valor, data, sizeof(cur->valor)) == 0)
        lat_objeto *tmp = (lat_objeto *)cur->valor;
        if (latO_es_igual(mv, find, tmp)) {
            return i;
        }
        i++;
    }
    return -1;
}

void latO_imprimir(lat_mv *mv, lat_objeto *o, bool fmt) {
    char *tmp = latC_astring(mv, o);
    char *tmp2 = NULL;
    if (fmt) {
        tmp2 = analizar_fmt(tmp, strlen(tmp));
        printf("%s", tmp2);
    } else {
        tmp2 = analizar(tmp, strlen(tmp));
        printf("%s", tmp2);
    }
    latM_liberar(mv, tmp);
    latM_liberar(mv, tmp2);
}

void latS_resize(lat_mv *mv, int newsize) {
    lat_gcobjeto **newhash;
    stringtable *tb;
    int i;
    newhash = latM_asignar(mv, newsize * sizeof(lat_gcobjeto *));
#if DEPURAR_MEM
    printf("latS_resize.newhash: %p\n", newhash);
#endif
    tb = &mv->global->strt;
    for (i = 0; i < newsize; i++) {
        newhash[i] = NULL;
    }
    for (i = 0; i < tb->size; i++) {
        lat_gcobjeto *p = tb->hash[i];
        while (p) {
            lat_gcobjeto *next = p->gch.next;
            unsigned int h = (&p->cadena)->tsv.hash;
            int h1 = lmod(h, newsize);
            p->gch.next = newhash[h1];
            newhash[h1] = p;
            p = next;
        }
    }
    latM_liberar(mv, tb->hash);
    tb->size = newsize;
    tb->hash = newhash;
}

LATINO_API lat_objeto *latC_crear_logico(lat_mv *mv, bool val) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_logico: %p\n", ret);
#endif
    ret->tam += sizeof(bool);
    setLogico(ret, val);
    return ret;
}

LATINO_API lat_objeto *latC_crear_numerico(lat_mv *mv, double val) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_numerico: %p\n", ret);
#endif
    ret->tam += sizeof(double);
    setNumerico(ret, val);
    return ret;
}

LATINO_API lat_objeto *latC_crear_entero(lat_mv *mv, int val) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_entero: %p\n", ret);
#endif
    ret->tam += sizeof(int);
    setEntero(ret, val);
    return ret;
}

LATINO_API lat_objeto *latC_crear_caracter(lat_mv *mv, char val) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_caracter: %p\n", ret);
#endif
    ret->tam += sizeof(int);
    setCaracter(ret, val);
    return ret;
}

LATINO_API lat_objeto *latC_crear_cadena(lat_mv *mv, const char *p) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_cadena: %p\n", ret);
#endif
    ret->tam += strlen(p);
    setCadena(ret, latO_cadenaNueva(mv, p, strlen(p)));
    return ret;
}

LATINO_API lat_objeto *latC_crear_lista(lat_mv *mv, lista *l) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_lista: %p\n", ret);
#endif
    ret->tam += sizeof(lista);
    setLista(ret, l);
    return ret;
}

LATINO_API lat_objeto *latC_crear_dic(lat_mv *mv, hash_map *dic) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_dic: %p\n", ret);
#endif
    ret->tam += sizeof(hash_map);
    setDic(ret, dic);
    return ret;
}

LATINO_API lat_objeto *latC_crear_cdato(lat_mv *mv, void *ptr) {
    lat_objeto *ret = latO_crear(mv);
#if DEPURAR_MEM
    printf("latC_crear_cdato: %p\n", ret);
#endif
    setPtr(ret, ptr);
    return ret;
}

LATINO_API bool latC_checar_logico(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_BOOL) {
        return getLogico(o);
    }
    latC_error(mv, "El parametro debe de ser un valor logico");
    return false;
}

LATINO_API double latC_checar_numerico(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_NUMERIC || o->tipo == T_INTEGER) {
        return getNumerico(o);
    }
    latC_error(mv, "El parametro debe de ser un decimal");
    return 0;
}

LATINO_API int latC_checar_entero(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_INTEGER) {
        return getEntero(o);
    }
    latC_error(mv, "El parametro debe de ser un entero");
    return 0;
}

LATINO_API char latC_checar_caracter(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_CHAR) {
        return getCaracter(o);
    }
    latC_error(mv, "El parametro debe de ser un caracter");
    return 0;
}

LATINO_API char *latC_checar_cadena(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_STR || o->tipo == T_LABEL) {
        return getstr(getCadena(o));
    }
    latC_error(mv, "El parametro debe de ser una cadena");
    return 0;
}

LATINO_API lista *latC_checar_lista(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_LIST) {
        return getLista(o);
    }
    latC_error(mv, "El parametro debe de ser una lista");
    return NULL;
}

LATINO_API hash_map *latC_checar_dic(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_DIC) {
        return getDic(o);
    }
    latC_error(mv, "El parametro debe de ser un diccionario");
    return NULL;
}

LATINO_API void *latC_checar_cptr(lat_mv *mv, lat_objeto *o) {
    if (o->tipo == T_CPTR) {
        return getPtr(o);
    }
    latC_error(mv, "El parametro debe de ser un dato de c (void *)");
    return NULL;
}

LATINO_API bool latC_abool(lat_mv *mv, lat_objeto *o) {
    switch (o->tipo) {
        case T_NULL:
            return false;
            break;
        case T_BOOL:
            return latC_checar_logico(mv, o);
            break;
        case T_NUMERIC:
            return latC_checar_numerico(mv, o) == 0 ? false : true;
            break;
        case T_STR:
            return !strcmp(latC_checar_cadena(mv, o), "") ||
                           !strcmp(latC_checar_cadena(mv, o), "0") ||
                           !strcmp(minusculas(latC_astring(mv, o)), "falso") ||
                           !strcmp(minusculas(latC_astring(mv, o)), "false")
                       ? false
                       : true;
            break;
        case T_LIST:
            return latL_longitud(latC_checar_lista(mv, o)) == 0 ? false : true;
        case T_DIC:
            return latH_longitud(latC_checar_dic(mv, o)) == 0 ? false : true;
        default:
            latC_error(mv, "Conversion de tipo de dato incompatible");
            break;
    }
    return false;
}

LATINO_API double latC_adouble(lat_mv *mv, lat_objeto *o) {
    switch (o->tipo) {
        case T_NULL:
            return 0;
        case T_BOOL:
            return latC_checar_logico(mv, o) ? 1 : 0;
        case T_NUMERIC:
            return latC_checar_numerico(mv, o);
        case T_STR: {
            const char *str = latC_checar_cadena(mv, o);
            char *ptr;
            double ret = strtod(str, &ptr);
            if (*ptr == '\0') {
                return ret;
            } else if (*str != '\0') {
                return (int)(str[0]);
            } else {
                return 0;
            }
        }
        case T_LIST:
            return latL_longitud(latC_checar_lista(mv, o));
        case T_DIC:
            return latH_longitud(latC_checar_dic(mv, o));
        default:
            latC_error(mv, "Conversion de tipo de dato incompatible");
            break;
    }
    return 0;
}

LATINO_API int latC_aint(lat_mv *mv, lat_objeto *o) {
    switch (o->tipo) {
        case T_NULL:
            return 0;
        case T_BOOL:
            return latC_checar_logico(mv, o) ? 1 : 0;
        case T_NUMERIC:
            return (int)latC_checar_numerico(mv, o);
        case T_CHAR:
            return latC_checar_caracter(mv, o);
        case T_STR: {
            const char *str = latC_checar_cadena(mv, o);
            char *ptr;
            double ret = strtod(str, &ptr);
            if (*ptr == '\0') {
                return (int)ret;
            } else if (*str != '\0') {
                return (int)(str[0]);
            } else {
                return 0;
            }
        }
        case T_LIST:
            return latL_longitud(latC_checar_lista(mv, o));
        case T_DIC:
            return latH_longitud(latC_checar_dic(mv, o));
        default:
            latC_error(mv, "Conversion de tipo de dato incompatible");
            break;
    }
    return 0;
}

LATINO_API char latC_achar(lat_mv *mv, lat_objeto *o) {
    switch (o->tipo) {
        case T_NULL:
            return 0;
        case T_BOOL:
            return latC_checar_logico(mv, o) ? 1 : 0;
        case T_NUMERIC:
            return (char)latC_checar_numerico(mv, o);
        case T_INTEGER:
            return (char)latC_checar_entero(mv, o);
        case T_CHAR:
            return latC_checar_caracter(mv, o);
        case T_STR: {
            const char *str = latC_checar_cadena(mv, o);
            char *ptr;
            double ret = strtod(str, &ptr);
            if (*ptr == '\0') {
                return (char)ret;
            } else if (*str != '\0') {
                return str[0];
            } else {
                return 0;
            }
        }
        case T_LIST:
            return (char)latL_longitud(latC_checar_lista(mv, o));
        case T_DIC:
            return (char)latH_longitud(latC_checar_dic(mv, o));
        default:
            latC_error(mv, "Conversion de tipo de dato incompatible");
            break;
    }
    return 0;
}

LATINO_API char *latC_astring(lat_mv *mv, lat_objeto *o) {
    if (o == NULL || o->tipo == T_NULL) {
        return strdup("nulo");
    } else if (o->tipo == T_BOOL) {
        return logico_acadena(latC_checar_logico(mv, o));
    } else if (o->tipo == T_CONTEXT) {
        return strdup("contexto");
    } else if (o->tipo == T_NUMERIC) {
        return decimal_acadena(getNumerico(o));
    } else if (o->tipo == T_INTEGER) {
        return entero_acadena(getEntero(o));
    } else if (o->tipo == T_CHAR) {
        return &getCaracter(o);
    } else if (o->tipo == T_STR) {
        return strdup(latC_checar_cadena(mv, o));
    } else if (o->tipo == T_LABEL) {
        return strdup(latC_checar_cadena(mv, o));
    } else if (o->tipo == T_FUN) {
        return strdup("fun");
    } else if (o->tipo == T_CFUN) {
        return strdup("cfun");
    } else if (o->tipo == T_CLASS) {
        return strdup("clase");
    } else if (o->tipo == T_LIST) {
        return latL_acadena(mv, latC_checar_lista(mv, o));
    } else if (o->tipo == T_DIC) {
        return latH_acadena(mv, latC_checar_dic(mv, o));
    }
    return strdup("");
}

/*
 *  The implementation of hashtable test.
 *  Copyright (C)  2008,2009,2010  Wangbo
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  Author e-mail: activesys.wb@gmail.com
 *                 activesys@sina.com.cn
 */

/** include section **/
#include <cstl/clist.h>
#include "test_hashtable.h"

/** local constant declaration and local macro section **/

/** local data type declaration and local struct, union, enum section **/

/** local function prototype section **/

/** exported global variable definition section **/

/** local global variable definition section **/

/** exported function implementation section **/
void test_hashtable(void)
{
}

void _hash_multimap_int_key_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = *(int*)pair_first((pair_t*)cpv_input);
}

void _hash_map_int_key_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = *(int*)pair_first((pair_t*)cpv_input);
}

void _print_hash_multiset_cstr(const hash_multiset_t* cpt_hmset)
{
    iterator_t t_iter;
    assert(cpt_hmset != NULL);
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multiset_empty(cpt_hmset), hash_multiset_size(cpt_hmset),
        hash_multiset_max_size(cpt_hmset), hash_multiset_bucket_count(cpt_hmset));
    for(t_iter= hash_multiset_begin(cpt_hmset);
        !iterator_equal(t_iter, hash_multiset_end(cpt_hmset));
        t_iter= iterator_next(t_iter))
    {
        printf("%s\n", (char*)iterator_get_pointer(t_iter));
    }
}
void _hash_multiset_cstr_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = strlen((char*)cpv_input);
}
void _hash_multiset_cstr_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(strcmp((char*)cpv_first, (char*)cpv_second) < 0)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

void _hash_set_cstr_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(strcmp((char*)cpv_first, (char*)cpv_second) < 0)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

void _hash_set_cstr_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = strlen((char*)cpv_input);
}

void _print_hash_set_cstr(const hash_set_t* cpt_hset)
{
    iterator_t t_iter;
    assert(cpt_hset != NULL);
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_set_empty(cpt_hset), hash_set_size(cpt_hset),
        hash_set_max_size(cpt_hset), hash_set_bucket_count(cpt_hset));
    for(t_iter= hash_set_begin(cpt_hset);
        !iterator_equal(t_iter, hash_set_end(cpt_hset));
        t_iter= iterator_next(t_iter))
    {
        printf("%s\n", (char*)iterator_get_pointer(t_iter));
    }
}

void _print_hash_multiset_cstl(const hash_multiset_t* cpt_hmset)
{
    iterator_t t_itercstl;
    assert(cpt_hmset != NULL);
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multiset_empty(cpt_hmset), hash_multiset_size(cpt_hmset),
        hash_multiset_max_size(cpt_hmset), hash_multiset_bucket_count(cpt_hmset));
    for(t_itercstl = hash_multiset_begin(cpt_hmset);
        !iterator_equal(t_itercstl, hash_multiset_end(cpt_hmset));
        t_itercstl = iterator_next(t_itercstl))
    {
        _print_hash_multiset_c((hash_multiset_t*)iterator_get_pointer(t_itercstl), "%d, ", int);
    }
}
void _print_hash_set_cstl(const hash_set_t* cpt_hset)
{
    iterator_t t_itercstl;
    assert(cpt_hset != NULL);
    printf("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_set_empty(cpt_hset), hash_set_size(cpt_hset),
        hash_set_max_size(cpt_hset), hash_set_bucket_count(cpt_hset));
    for(t_itercstl = hash_set_begin(cpt_hset);
        !iterator_equal(t_itercstl, hash_set_end(cpt_hset));
        t_itercstl = iterator_next(t_itercstl))
    {
        _print_hash_set_c((hash_set_t*)iterator_get_pointer(t_itercstl), "%d, ", int);
    }
}
void _hash_multiset_cstl_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = hash_multiset_size((hash_multiset_t*)cpv_input);
}
void _hash_set_cstl_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(size_t*)pv_output = hash_set_size((hash_set_t*)cpv_input);
}

void _hash_set_int_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(int*)pv_output = *(int*)cpv_input;
}

void _debug_hash_multiset_user(const hash_multiset_t* cpt_hmset)
{
    size_t t_index = 0;
    assert(cpt_hmset != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multiset_empty(cpt_hmset), hash_multiset_size(cpt_hmset),
        hash_multiset_max_size(cpt_hmset), hash_multiset_bucket_count(cpt_hmset));
    for(t_index = 0; t_index < hash_multiset_bucket_count(cpt_hmset); ++t_index)
    {
        _hashnode_t** ppt_bucket = (_hashnode_t**)vector_at(&cpt_hmset->_t_hashtable._vec_bucket, t_index);
        _hashnode_t*  pt_node = *ppt_bucket;
        printf("[%u]", t_index);
        while(pt_node != NULL)
        {
            printf("->[%lf,%ld]", ((hash_sample_t*)(pt_node->_pby_data))->_d_first,
                ((hash_sample_t*)(pt_node->_pby_data))->_l_second);
            pt_node = pt_node->_pt_next;
        }
        printf("\n");
    }
    printf("=======================================\n");
}
void _debug_hash_set_user(const hash_set_t* cpt_hset)
{
    size_t t_index = 0;
    assert(cpt_hset != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_set_empty(cpt_hset), hash_set_size(cpt_hset),
        hash_set_max_size(cpt_hset), hash_set_bucket_count(cpt_hset));
    for(t_index = 0; t_index < hash_set_bucket_count(cpt_hset); ++t_index)
    {
        _hashnode_t** ppt_bucket = (_hashnode_t**)vector_at(&cpt_hset->_t_hashtable._vec_bucket, t_index);
        _hashnode_t*  pt_node = *ppt_bucket;
        printf("[%u]", t_index);
        while(pt_node != NULL)
        {
            printf("->[%lf,%ld]", ((hash_sample_t*)(pt_node->_pby_data))->_d_first,
                ((hash_sample_t*)(pt_node->_pby_data))->_l_second);
            pt_node = pt_node->_pt_next;
        }
        printf("\n");
    }
    printf("=======================================\n");
}

void _print_hash_multimap_sample(const hash_multimap_t* cpt_hmmap)
{
    iterator_t t_iter;
    assert(cpt_hmmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multimap_empty(cpt_hmmap), hash_multimap_size(cpt_hmmap),
        hash_multimap_max_size(cpt_hmmap), hash_multimap_bucket_count(cpt_hmmap));
    for(t_iter = hash_multimap_begin(cpt_hmmap);
        !iterator_equal(t_iter, hash_multimap_end(cpt_hmmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        printf("<%d, [%lf,%ld]>, ", *(int*)pair_first(pt_pair),
            ((hash_sample_t*)pair_second(pt_pair))->_d_first,
            ((hash_sample_t*)pair_second(pt_pair))->_l_second);
    }
    printf("\n");
}
void _print_hash_map_sample(const hash_map_t* cpt_hmap)
{
    iterator_t t_iter;
    assert(cpt_hmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_map_empty(cpt_hmap), hash_map_size(cpt_hmap),
        hash_map_max_size(cpt_hmap), hash_map_bucket_count(cpt_hmap));
    for(t_iter = hash_map_begin(cpt_hmap);
        !iterator_equal(t_iter, hash_map_end(cpt_hmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        printf("<%d, [%lf,%ld]>, ", *(int*)pair_first(pt_pair),
            ((hash_sample_t*)pair_second(pt_pair))->_d_first,
            ((hash_sample_t*)pair_second(pt_pair))->_l_second);
    }
    printf("\n");
}
void _print_hash_multiset_sample(const hash_multiset_t* cpt_hmset)
{
    iterator_t t_iter;
    assert(cpt_hmset != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multiset_empty(cpt_hmset), hash_multiset_size(cpt_hmset),
        hash_multiset_max_size(cpt_hmset), hash_multiset_bucket_count(cpt_hmset));
    for(t_iter = hash_multiset_begin(cpt_hmset);
        !iterator_equal(t_iter, hash_multiset_end(cpt_hmset));
        t_iter = iterator_next(t_iter))
    {
        printf("[%lf,%ld], ", ((hash_sample_t*)iterator_get_pointer(t_iter))->_d_first,
            ((hash_sample_t*)iterator_get_pointer(t_iter))->_l_second);
    }
    printf("\n");
}
void _print_hash_set_sample(const hash_set_t* cpt_hset)
{
    iterator_t t_iter;
    assert(cpt_hset != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_set_empty(cpt_hset), hash_set_size(cpt_hset),
        hash_set_max_size(cpt_hset), hash_set_bucket_count(cpt_hset));
    for(t_iter = hash_set_begin(cpt_hset);
        !iterator_equal(t_iter, hash_set_end(cpt_hset));
        t_iter = iterator_next(t_iter))
    {
        printf("[%lf,%ld], ", ((hash_sample_t*)iterator_get_pointer(t_iter))->_d_first,
            ((hash_sample_t*)iterator_get_pointer(t_iter))->_l_second);
    }
    printf("\n");
}

void _hash_sample_init(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    ((hash_sample_t*)cpv_input)->_d_first = 0.0;
    ((hash_sample_t*)cpv_input)->_l_second = 0;
    *(bool_t*)pv_output = true;
}

void _hash_sample_copy(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    ((hash_sample_t*)cpv_first)->_d_first = ((hash_sample_t*)cpv_second)->_d_first;
    ((hash_sample_t*)cpv_first)->_l_second = ((hash_sample_t*)cpv_second)->_l_second;
    *(bool_t*)pv_output = true;
}

void _hash_sample_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((hash_sample_t*)cpv_first)->_d_first < ((hash_sample_t*)cpv_second)->_d_first)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

void _hash_sample_destroy(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    ((hash_sample_t*)cpv_input)->_d_first = 0.0;
    ((hash_sample_t*)cpv_input)->_l_second = 0;
    *(bool_t*)pv_output = true;
}

void _hash_sample_greater(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((hash_sample_t*)cpv_first)->_d_first > ((hash_sample_t*)cpv_second)->_d_first)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

void _print_hash_multimap_cstr(const hash_multimap_t* cpt_hmmap)
{
    iterator_t t_iter;
    assert(cpt_hmmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multimap_empty(cpt_hmmap), hash_multimap_size(cpt_hmmap),
        hash_multimap_max_size(cpt_hmmap), hash_multimap_bucket_count(cpt_hmmap));
    for(t_iter = hash_multimap_begin(cpt_hmmap);
        !iterator_equal(t_iter, hash_multimap_end(cpt_hmmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        printf("<%s, %s>, ", (char*)pair_first(pt_pair), (char*)pair_second(pt_pair));
    }
    printf("\n");
}
void _print_hash_map_cstr(const hash_map_t* cpt_hmap)
{
    iterator_t t_iter;
    assert(cpt_hmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_map_empty(cpt_hmap), hash_map_size(cpt_hmap),
        hash_map_max_size(cpt_hmap), hash_map_bucket_count(cpt_hmap));
    for(t_iter = hash_map_begin(cpt_hmap);
        !iterator_equal(t_iter, hash_map_end(cpt_hmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        printf("<%s, %s>, ", (char*)pair_first(pt_pair), (char*)pair_second(pt_pair));
    }
    printf("\n");
}

void _hash_multimap_cstr_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(size_t*)pv_output = strlen((char*)pair_first(pt_pair));
}
void _hash_map_cstr_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(size_t*)pv_output = strlen((char*)pair_first(pt_pair));
}

void _hash_multimap_cstr_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(strlen((char*)cpv_first) < strlen((char*)cpv_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}
void _hash_map_cstr_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(strlen((char*)cpv_first) < strlen((char*)cpv_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

void _print_hash_multimap_cstl(const hash_multimap_t* cpt_hmmap)
{
    iterator_t t_iter;
    iterator_t t_iterlist;
    assert(cpt_hmmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_multimap_empty(cpt_hmmap), hash_multimap_size(cpt_hmmap),
        hash_multimap_max_size(cpt_hmmap), hash_multimap_bucket_count(cpt_hmmap));
    for(t_iter = hash_multimap_begin(cpt_hmmap);
        !iterator_equal(t_iter, hash_multimap_end(cpt_hmmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        list_t* pt_list = (list_t*)pair_second(pt_pair);
        printf("<%d,[", *(int*)pair_first(pt_pair));
        for(t_iterlist = list_begin(pt_list);
            !iterator_equal(t_iterlist, list_end(pt_list));
            t_iterlist = iterator_next(t_iterlist))
        {
            printf("%d,", *(int*)iterator_get_pointer(t_iterlist));
        }
        printf("]>\n");
    }
}
void _print_hash_map_cstl(const hash_map_t* cpt_hmap)
{
    iterator_t t_iter;
    iterator_t t_iterlist;
    assert(cpt_hmap != NULL);
    printf("=======================================\n");
    printf("empty: %u, size: %u, max_size: %u, bucket count: %u\n",
        hash_map_empty(cpt_hmap), hash_map_size(cpt_hmap),
        hash_map_max_size(cpt_hmap), hash_map_bucket_count(cpt_hmap));
    for(t_iter = hash_map_begin(cpt_hmap);
        !iterator_equal(t_iter, hash_map_end(cpt_hmap));
        t_iter = iterator_next(t_iter))
    {
        pair_t* pt_pair = (pair_t*)iterator_get_pointer(t_iter);
        list_t* pt_list = (list_t*)pair_second(pt_pair);
        printf("<%d,[", *(int*)pair_first(pt_pair));
        for(t_iterlist = list_begin(pt_list);
            !iterator_equal(t_iterlist, list_end(pt_list));
            t_iterlist = iterator_next(t_iterlist))
        {
            printf("%d,", *(int*)iterator_get_pointer(t_iterlist));
        }
        printf("]>\n");
    }
}

void _hash_multimap_cstl_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(int*)pv_output = *(int*)pair_first(pt_pair);
}
void _hash_map_cstl_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(int*)pv_output = *(int*)pair_first(pt_pair);
}

void _hash_multimap_sample_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(int*)pv_output = *(int*)pair_first(pt_pair);
}
void _hash_map_sample_hash(const void* cpv_input, void* pv_output)
{
    pair_t* pt_pair = NULL;
    assert(cpv_input != NULL && pv_output != NULL);
    pt_pair = (pair_t*)cpv_input;
    *(int*)pv_output = *(int*)pair_first(pt_pair);
}
void _hash_set_sample_hash(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    *(int*)pv_output = (int)((hash_sample_t*)cpv_input)->_l_second;
}

/** local function implementation section **/

/** eof **/


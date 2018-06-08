/*
 *  The implementation of project test.
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
#include <stdio.h>
#include <stdlib.h>

#include "test_string.h"
#include "test_vector.h"
#include "test_list.h"
#include "test_deque.h"
#include "test_slist.h"
#include "test_stack.h"
#include "test_queue.h"
#include "test_pair.h"
#include "test_avl_tree.h"
#include "test_rb_tree.h"
#include "test_hashtable.h"
#include "test_function.h"
#include "test_numeric.h"
#include "test_algobase.h"
#include "test_algo.h"
#include "test_heap.h"
#include "test_set.h"
#include "test_map.h"
#include "test_type.h"
#include "test_hash_set.h"
#include "test_hash_map.h"
/* #include "test.h" */

/** local constant declaration and local macro section **/

/** local data type declaration and local struct, union, enum section **/

/** local function prototype section **/

/** exported global variable definition section **/

/** local global variable definition section **/

/** exported function implementation section **/
int main(int argc, char* argv[])
{
    printf("========== test vector_t ==========\n");
    test_vector();
    printf("========== test deque_t  ==========\n");
    test_deque();
    printf("========== test list_t  ==========\n");
    test_list();
    printf("========== test slist_t  ==========\n");
    test_slist();
    printf("========== test stack_t  ==========\n");
    test_stack();
    printf("========== test queue_t  ==========\n");
    test_queue();
    printf("========== test pair_t  ==========\n");
    test_pair();
    /*test_basic_string();*/
    /*test_avl_tree();*/
    /*test_rb_tree();*/
    /*test_hashtable();*/
    printf("========== test set_t  ==========\n");
    test_set();
    printf("========== test multiset_t =======\n");
    test_multiset();
    printf("========== test map_t  ==========\n");
    test_map();
    printf("========== test multimap_t  ==========\n");
    test_multimap();
    printf("========== test string_t  ==========\n");
    test_string(argc, argv);
    /*test_string_getline(); */
    /*test_type();*/
    printf("========== test hash_set_t  ==========\n");
    test_hash_set();
    printf("========== test hash_multiset_t  ==========\n");
    test_hash_multiset();
    printf("========== test hash_map_t  ==========\n");
    test_hash_map();
    printf("========== test hash_multimap_t  ==========\n");
    test_hash_multimap();
    /*test_function();*/
    printf("========== test numeric algorithm ==========\n");
    test_numeric();
    printf("========== test heap algorithm ==========\n");
    test_heap();
    printf("========== test heap algorithm ==========\n");
    test_priority_queue();
    printf("========== test basic algorithm ==========\n");
    test_algobase();
    printf("========== test algorithm ==========\n");
    test_algo();

    argc = 0;
    argv = NULL;

    return 0;
}

/** local function implementation section **/

/** eof **/


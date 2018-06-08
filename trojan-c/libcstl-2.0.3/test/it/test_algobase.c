/*
 *  The implementation of base algorithm base.
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
#include <ctype.h>
#include <cstl/cvector.h>
#include <cstl/clist.h>
#include <cstl/cstring.h>
#include <cstl/calgorithm.h>
#include <cstl/cnumeric.h>
#include <cstl/cfunctional.h>
#include "test_algobase.h"

/** local constant declaration and local macro section **/

/** local data type declaration and local struct, union, enum section **/

/** local function prototype section **/
static void _print_int(const void* cpv_input, void* pv_output);
static void _print_cstr(const void* cpv_input, void* pv_output);
static void _equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output);
static void _absless(const void* cpv_first, const void* cpv_second, void* pv_output);
static void _print_vector(const void* cpv_input, void* pv_output);
static void _print_list(const void* cpv_input, void* pv_output);
static void _list_equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output);
static void _sizeless(const void* cpv_first, const void* cpv_second, void* pv_output);
static void _cstr_equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output);
static void _nocaseless(const void* cpv_first, const void* cpv_second, void* pv_output);

/** exported global variable definition section **/

/** local global variable definition section **/

/** exported function implementation section **/
void test_algobase(void)
{
    /* c built-in type */
    {
        /*algo_fill                           */
        {
            list_t* pt_list = create_list(int);
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(list_begin(pt_list), list_begin(pt_list), 455);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(list_begin(pt_list), iterator_advance(list_begin(pt_list), 3), 90);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(iterator_next(list_begin(pt_list)),
                iterator_advance(list_begin(pt_list), 5), -512);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(iterator_advance(list_begin(pt_list), 6), list_end(pt_list), -1000);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(list_end(pt_list), list_end(pt_list), 33);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill(list_begin(pt_list), list_end(pt_list), 1234);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            list_destroy(pt_list);
        }
        /*algo_fill_n                         */
        {
            list_t* pt_list = create_list(int);
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill_n(list_begin(pt_list), 0, 455);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill_n(list_begin(pt_list), 3, 90);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill_n(iterator_next(list_begin(pt_list)), 5, -512);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill_n(list_end(pt_list), 0, 33);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            algo_fill_n(list_begin(pt_list), list_size(pt_list), 1234);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");

            list_destroy(pt_list);
        }
        /*algo_equal                          */
        {
            list_t* pt_list = create_list(int);
            vector_t* pt_vec = create_vector(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_list, t_index);
                vector_push_back(pt_vec, t_index + 5);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_list, t_index);
                vector_push_back(pt_vec, t_index);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_equal_if                       */
        {
            list_t* pt_list = create_list(int);
            vector_t* pt_vec = create_vector(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal_if(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec), _equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_list, t_index);
                vector_push_back(pt_vec, t_index + 5);
            }
            printf("equal : %d\n", algo_equal_if(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec), _equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_list, t_index);
                vector_push_back(pt_vec, t_index);
            }
            printf("equal : %d\n", algo_equal_if(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec), _equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_swap                           */
        /*algo_iter_swap                      */
        {
            list_t* pt_list = create_list(int);
            vector_t* pt_vec = create_vector(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_list, t_index + 1);
                vector_push_back(pt_vec, -(int)t_index - 1);
            }
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            algo_swap(list_begin(pt_list), list_begin(pt_list));
            algo_iter_swap(vector_begin(pt_vec), vector_begin(pt_vec));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_advance(list_begin(pt_list), 5));
            algo_iter_swap(vector_begin(pt_vec), iterator_next_n(vector_begin(pt_vec), 5));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_next(vector_begin(pt_vec)));
            algo_iter_swap(vector_begin(pt_vec), iterator_next(list_begin(pt_list)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare        */
        /*algo_lexicographical_compare_3way   */
        {
            list_t* pt_list = create_list(int);
            vector_t* pt_vec = create_vector(int);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 7);
            vector_push_back(pt_vec, 7);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 7);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 5);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare_if     */
        /*algo_lexicographical_compare_3way_if*/
        {
            list_t* pt_list = create_list(int);
            vector_t* pt_vec = create_vector(int);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 3);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 7);
            vector_push_back(pt_vec, 7);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 7);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_clear(pt_list);
            list_push_back(pt_list, 3);
            list_push_back(pt_list, 2);
            list_push_back(pt_list, 8);
            list_push_back(pt_list, 7);
            vector_clear(pt_vec);
            vector_push_back(pt_vec, 3);
            vector_push_back(pt_vec, 2);
            vector_push_back(pt_vec, 8);
            vector_push_back(pt_vec, 5);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_int));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_max                            */
        /*algo_max_if                         */
        /*algo_min                            */
        /*algo_min_if                         */
        {
            vector_t* pt_vec = create_vector(int);
            list_t* pt_list = create_list(int);
            iterator_t t_min;
            iterator_t t_max;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init_n(pt_vec, 10);
            list_init_n(pt_list, 10);
            algo_iota(list_begin(pt_list), list_end(pt_list), -2);
            algo_iota(vector_begin(pt_vec), vector_end(pt_vec), -9);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            t_min = algo_min(list_begin(pt_list), vector_begin(pt_vec));
            t_max = algo_max(list_begin(pt_list), vector_begin(pt_vec));
            printf("minmum between two begin : %d\n", *(int*)iterator_get_pointer(t_min));
            printf("maxmum between two begin : %d\n", *(int*)iterator_get_pointer(t_max));

            t_min = algo_min_if(list_begin(pt_list), vector_begin(pt_vec), _absless);
            t_max = algo_max_if(list_begin(pt_list), vector_begin(pt_vec), _absless);
            printf("minmum of absolute between two begin : %d\n",
                *(int*)iterator_get_pointer(t_min));
            printf("maxmum of absolute between two begin : %d\n",
                *(int*)iterator_get_pointer(t_max));

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_mismatch                       */
        /*algo_mismatch_if                    */
        {
            vector_t* pt_vec = create_vector(int);
            list_t* pt_list = create_list(int);
            range_t t_range;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init_n(pt_vec, 5);
            list_init_n(pt_list, 5);
            algo_iota(list_begin(pt_list), list_end(pt_list), 2);
            list_push_back(pt_list, 11);
            list_push_back(pt_list, 22);
            list_push_back(pt_list, 33);
            algo_iota(vector_begin(pt_vec), vector_end(pt_vec), 2);
            vector_push_back(pt_vec, 44);
            vector_push_back(pt_vec, 55);
            vector_push_back(pt_vec, 9);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_int);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_int);
            printf("\n");

            t_range = algo_mismatch(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec));
            printf("the first mismatch : %d and %d\n",
                *(int*)iterator_get_pointer(t_range.it_begin),
                *(int*)iterator_get_pointer(t_range.it_end));
            t_range = algo_mismatch_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), fun_less_equal_int);
            printf("not less or equal : %d and %d\n",
                *(int*)iterator_get_pointer(t_range.it_begin),
                *(int*)iterator_get_pointer(t_range.it_end));

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_copy                           */
        /*algo_copy_n                         */
        /*algo_copy_backward                  */
        {
            vector_t* pt_vec1 = create_vector(int);
            vector_t* pt_vec2 = create_vector(int);
            list_t* pt_list1 = create_list(int);
            list_t* pt_list2 = create_list(int);
            if(pt_vec1 == NULL || pt_vec2 == NULL || pt_list1 == NULL || pt_list2 == NULL)
            {
                return;
            }
            vector_init_n(pt_vec1, 10);
            vector_init_n(pt_vec2, 10);
            list_init_n(pt_list1, 10);
            list_init_n(pt_list2, 10);

            algo_iota(vector_begin(pt_vec1), vector_end(pt_vec1), 0);
            algo_iota(vector_begin(pt_vec2), vector_end(pt_vec2), 0);
            algo_iota(list_begin(pt_list1), list_end(pt_list1), 0);
            algo_iota(list_begin(pt_list2), list_end(pt_list2), 0);
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            algo_copy(iterator_advance(list_begin(pt_list1), 4),
                list_end(pt_list1), list_begin(pt_list1));
            algo_copy(iterator_advance(list_begin(pt_list2), 6),
                list_end(pt_list2), list_begin(pt_list2));
            algo_copy(vector_begin(pt_vec1), iterator_advance(vector_begin(pt_vec1), 6),
                iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy(vector_begin(pt_vec2), iterator_advance(vector_begin(pt_vec2), 3),
                iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            algo_iota(vector_begin(pt_vec1), vector_end(pt_vec1), 0);
            algo_iota(vector_begin(pt_vec2), vector_end(pt_vec2), 0);
            algo_iota(list_begin(pt_list1), list_end(pt_list1), 0);
            algo_iota(list_begin(pt_list2), list_end(pt_list2), 0);
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            algo_copy_n(iterator_advance(list_begin(pt_list1), 4), 5, list_begin(pt_list1));
            algo_copy_n(iterator_advance(list_begin(pt_list2), 6), 3, list_begin(pt_list2));
            algo_copy_n(vector_begin(pt_vec1), 6, iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy_n(vector_begin(pt_vec2), 3, iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            algo_iota(vector_begin(pt_vec1), vector_end(pt_vec1), 0);
            algo_iota(vector_begin(pt_vec2), vector_end(pt_vec2), 0);
            algo_iota(list_begin(pt_list1), list_end(pt_list1), 0);
            algo_iota(list_begin(pt_list2), list_end(pt_list2), 0);
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            algo_copy_backward(iterator_advance(list_begin(pt_list1), 4), list_end(pt_list1),
                iterator_advance(list_begin(pt_list1), 7));
            algo_copy_backward(iterator_advance(list_begin(pt_list2), 6), list_end(pt_list2),
                iterator_advance(list_begin(pt_list2), 5));
            algo_copy_backward(vector_begin(pt_vec1),
                iterator_advance(vector_begin(pt_vec1), 6),
                iterator_prev(vector_end(pt_vec1)));
            algo_copy_backward(vector_begin(pt_vec2),
                iterator_advance(vector_begin(pt_vec2), 3),
                iterator_prev(vector_end(pt_vec2)));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_int);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_int);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_int);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_int);
            printf("\n\n");

            vector_destroy(pt_vec1);
            vector_destroy(pt_vec2);
            list_destroy(pt_list1);
            list_destroy(pt_list2);
        }
    }
    /* user define type */
    {
        type_register(algo_sample_t, algo_sample_init, algo_sample_copy,
            algo_sample_less, algo_sample_destroy);
        type_duplicate(algo_sample_t, struct _tagalgosample);
        /*_algo_fill                          */
        {
            list_t* pt_list = create_list(algo_sample_t);
            algo_sample_t t_sample;
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 100;
            t_sample._t_content = 200;
            algo_fill(list_begin(pt_list), list_begin(pt_list), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 90;
            t_sample._t_content = 250;
            algo_fill(list_begin(pt_list), iterator_advance(list_begin(pt_list), 3),
                &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 512;
            t_sample._t_content = 1024;
            algo_fill(iterator_next(list_begin(pt_list)),
                iterator_advance(list_begin(pt_list), 5), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 10000;
            algo_fill(iterator_advance(list_begin(pt_list), 6), list_end(pt_list), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 33;
            t_sample._t_content = 0;
            algo_fill(list_end(pt_list), list_end(pt_list), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 1234;
            t_sample._t_content = 6789;
            algo_fill(list_begin(pt_list), list_end(pt_list), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            list_destroy(pt_list);
        }
        /*_algo_fill_n                        */
        {
            list_t* pt_list = create_list(algo_sample_t);
            algo_sample_t t_sample;
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 455;
            t_sample._t_content = 554;
            algo_fill_n(list_begin(pt_list), 0, &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 90;
            t_sample._t_content = 90;
            algo_fill_n(list_begin(pt_list), 3, &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 512;
            t_sample._t_content = 900;
            algo_fill_n(iterator_next(list_begin(pt_list)), 5, &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 33;
            t_sample._t_content = 33;
            algo_fill_n(list_end(pt_list), 0, &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            t_sample._t_id = 1024;
            t_sample._t_content = 0;
            algo_fill_n(list_begin(pt_list), list_size(pt_list), &t_sample);
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");

            list_destroy(pt_list);
        }
        /*algo_equal                          */
        {
            list_t* pt_list = create_list(algo_sample_t);
            vector_t* pt_vec = create_vector(algo_sample_t);
            size_t t_index = 0;
            algo_sample_t t_sample;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                t_sample._t_id = t_index * 100;
                t_sample._t_content = t_index * 200;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                t_sample._t_content = t_index + 5;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_equal_if                       */
        {
            list_t* pt_list = create_list(algo_sample_t);
            vector_t* pt_vec = create_vector(algo_sample_t);
            size_t t_index = 0;
            algo_sample_t t_sample;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), algo_sample_equal));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                t_sample._t_id = t_index * 100;
                t_sample._t_content = t_index * 200;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), algo_sample_equal));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                t_sample._t_content = t_index + 5;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), algo_sample_equal));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index;
                list_push_back(pt_list, &t_sample);
                vector_push_back(pt_vec, &t_sample);
            }
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), algo_sample_equal));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_swap                           */
        /*algo_iter_swap                      */
        {
            list_t* pt_list = create_list(algo_sample_t);
            vector_t* pt_vec = create_vector(algo_sample_t);
            size_t t_index = 0;
            algo_sample_t t_sample;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index + 1;
                t_sample._t_content = t_index + 10;
                list_push_back(pt_list, &t_sample);
                t_sample._t_id = t_index * 5;
                t_sample._t_content = t_index * 10;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            algo_swap(list_begin(pt_list), list_begin(pt_list));
            algo_iter_swap(vector_begin(pt_vec), vector_begin(pt_vec));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_advance(list_begin(pt_list), 5));
            algo_iter_swap(vector_begin(pt_vec), iterator_next_n(vector_begin(pt_vec), 5));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_next(vector_begin(pt_vec)));
            algo_iter_swap(vector_begin(pt_vec), iterator_next(list_begin(pt_list)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare        */
        /*algo_lexicographical_compare_if     */
        {
            list_t* pt_list = create_list(algo_sample_t);
            vector_t* pt_vec = create_vector(algo_sample_t);
            algo_sample_t t_sample;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 7;
            vector_push_back(pt_vec, &t_sample);
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 7;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 5;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare_3way   */
        /*algo_lexicographical_compare_3way_if*/
        {
            list_t* pt_list = create_list(algo_sample_t);
            vector_t* pt_vec = create_vector(algo_sample_t);
            algo_sample_t t_sample;
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 7;
            vector_push_back(pt_vec, &t_sample);
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 7;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            list_clear(pt_list);
            t_sample._t_id = 3;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 8;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 7;
            list_push_back(pt_list, &t_sample);
            vector_clear(pt_vec);
            t_sample._t_id = 3;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 8;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 5;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), algo_sample_greater));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_max                            */
        /*algo_max_if                         */
        /*algo_min                            */
        /*algo_min_if                         */
        {
            vector_t* pt_vec = create_vector(algo_sample_t);
            list_t* pt_list = create_list(algo_sample_t);
            iterator_t t_min;
            iterator_t t_max;
            algo_sample_t t_sample;
            size_t t_index = 0;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = 10 - t_index;
                list_push_back(pt_list, &t_sample);
                t_sample._t_id = t_index + 3;
                t_sample._t_content = t_index;
                vector_push_back(pt_vec, &t_sample);
            }
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            t_min = algo_min(list_begin(pt_list), vector_begin(pt_vec));
            t_max = algo_max(list_begin(pt_list), vector_begin(pt_vec));
            printf("minmum between two begin : ");
            algo_sample_show(iterator_get_pointer(t_min), NULL);
            printf("\n");
            printf("maxmum between two begin : ");
            algo_sample_show(iterator_get_pointer(t_max), NULL);
            printf("\n");

            t_min = algo_min_if(list_begin(pt_list), vector_begin(pt_vec),
                algo_sample_content_less);
            t_max = algo_max_if(list_begin(pt_list), vector_begin(pt_vec),
                algo_sample_content_less);
            printf("minmum of content between two begin : ");
            algo_sample_show(iterator_get_pointer(t_min), NULL);
            printf("\n");
            printf("maxmum of content between two begin : ");
            algo_sample_show(iterator_get_pointer(t_max), NULL);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_mismatch                       */
        /*algo_mismatch_if                    */
        {
            vector_t* pt_vec = create_vector(algo_sample_t);
            list_t* pt_list = create_list(algo_sample_t);
            range_t t_range;
            size_t t_index = 0;
            algo_sample_t t_sample;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);
            for(t_index = 0; t_index < 5; ++t_index)
            {
                t_sample._t_id = t_index + 2;
                t_sample._t_content = t_index * 2;
                list_push_back(pt_list, &t_sample);
                t_sample._t_content = t_index * 3;
                vector_push_back(pt_vec, &t_sample);
            }
            t_sample._t_id = 11;
            t_sample._t_content = 11 * 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 22;
            t_sample._t_content = 22 * 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 33;
            t_sample._t_content = 33 * 2;
            list_push_back(pt_list, &t_sample);
            t_sample._t_id = 44;
            t_sample._t_content = 44 * 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 55;
            t_sample._t_content = 55 * 2;
            vector_push_back(pt_vec, &t_sample);
            t_sample._t_id = 9;
            t_sample._t_content = 9 * 2;
            vector_push_back(pt_vec, &t_sample);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), algo_sample_show);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), algo_sample_show);
            printf("\n");

            t_range = algo_mismatch(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec));
            printf("the first mismatch : ");
            algo_sample_show(iterator_get_pointer(t_range.it_begin), NULL);
            printf("and ");
            algo_sample_show(iterator_get_pointer(t_range.it_end), NULL);
            printf("\n");
            t_range = algo_mismatch_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), algo_sample_equal);
            printf("the first mismatch : ");
            algo_sample_show(iterator_get_pointer(t_range.it_begin), NULL);
            printf("and ");
            algo_sample_show(iterator_get_pointer(t_range.it_end), NULL);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_copy                           */
        /*algo_copy_n                         */
        /*algo_copy_backward                  */
        {
            vector_t* pt_vec1 = create_vector(algo_sample_t);
            vector_t* pt_vec2 = create_vector(algo_sample_t);
            list_t* pt_list1 = create_list(algo_sample_t);
            list_t* pt_list2 = create_list(algo_sample_t);
            algo_sample_t t_sample;
            size_t t_index = 0;
            if(pt_vec1 == NULL || pt_vec2 == NULL || pt_list1 == NULL || pt_list2 == NULL)
            {
                return;
            }
            vector_init(pt_vec1);
            vector_init(pt_vec2);
            list_init(pt_list1);
            list_init(pt_list2);

            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index * 2;
                vector_push_back(pt_vec1, &t_sample);
                vector_push_back(pt_vec2, &t_sample);
                list_push_back(pt_list1, &t_sample);
                list_push_back(pt_list2, &t_sample);
            }
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            algo_copy(iterator_advance(list_begin(pt_list1), 4),
                list_end(pt_list1), list_begin(pt_list1));
            algo_copy(iterator_advance(list_begin(pt_list2), 6),
                list_end(pt_list2), list_begin(pt_list2));
            algo_copy(vector_begin(pt_vec1), iterator_advance(vector_begin(pt_vec1), 6),
                iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy(vector_begin(pt_vec2), iterator_advance(vector_begin(pt_vec2), 3),
                iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index * 2;
                vector_push_back(pt_vec1, &t_sample);
                vector_push_back(pt_vec2, &t_sample);
                list_push_back(pt_list1, &t_sample);
                list_push_back(pt_list2, &t_sample);
            }
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            algo_copy_n(iterator_advance(list_begin(pt_list1), 4), 5, list_begin(pt_list1));
            algo_copy_n(iterator_advance(list_begin(pt_list2), 6), 3, list_begin(pt_list2));
            algo_copy_n(vector_begin(pt_vec1), 6, iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy_n(vector_begin(pt_vec2), 3, iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                t_sample._t_id = t_index;
                t_sample._t_content = t_index * 2;
                vector_push_back(pt_vec1, &t_sample);
                vector_push_back(pt_vec2, &t_sample);
                list_push_back(pt_list1, &t_sample);
                list_push_back(pt_list2, &t_sample);
            }
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            algo_copy_backward(iterator_advance(list_begin(pt_list1), 4), list_end(pt_list1),
                iterator_advance(list_begin(pt_list1), 7));
            algo_copy_backward(iterator_advance(list_begin(pt_list2), 6), list_end(pt_list2),
                iterator_advance(list_begin(pt_list2), 5));
            algo_copy_backward(vector_begin(pt_vec1),
                iterator_advance(vector_begin(pt_vec1), 6),
                iterator_prev(vector_end(pt_vec1)));
            algo_copy_backward(vector_begin(pt_vec2),
                iterator_advance(vector_begin(pt_vec2), 3),
                iterator_prev(vector_end(pt_vec2)));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), algo_sample_show);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), algo_sample_show);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), algo_sample_show);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), algo_sample_show);
            printf("\n\n");

            vector_destroy(pt_vec1);
            vector_destroy(pt_vec2);
            list_destroy(pt_list1);
            list_destroy(pt_list2);
        }
    }
    /* cstl built-in type */
    {
        /*_algo_fill                          */
        {
            list_t* pt_list = create_list(vector_t<int>);
            vector_t* pt_vec = create_vector(int);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            vector_init(pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 100);
            vector_push_back(pt_vec, 200);
            vector_push_back(pt_vec, 300);
            algo_fill(list_begin(pt_list), list_begin(pt_list), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, -890);
            algo_fill(list_begin(pt_list), iterator_advance(list_begin(pt_list), 3),
                pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, 123);
            vector_push_back(pt_vec, 456);
            vector_push_back(pt_vec, 789);
            algo_fill(iterator_next(list_begin(pt_list)),
                iterator_advance(list_begin(pt_list), 5), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, 1);
            algo_fill(iterator_advance(list_begin(pt_list), 6), list_end(pt_list), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 0);
            vector_push_back(pt_vec, 0);
            algo_fill(list_end(pt_list), list_end(pt_list), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 1000);
            vector_push_back(pt_vec, 2000);
            algo_fill(list_begin(pt_list), list_end(pt_list), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*_algo_fill_n                        */
        {
            list_t* pt_list = create_list(vector_t<int>);
            vector_t* pt_vec = create_vector(int);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            vector_init(pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 100);
            vector_push_back(pt_vec, 200);
            vector_push_back(pt_vec, 300);
            algo_fill_n(list_begin(pt_list), 0, pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, -890);
            algo_fill_n(list_begin(pt_list), 3, pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, 123);
            vector_push_back(pt_vec, 456);
            vector_push_back(pt_vec, 789);
            algo_fill_n(iterator_next(list_begin(pt_list)), 5, pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_clear(pt_vec);
            vector_push_back(pt_vec, 1);
            algo_fill_n(iterator_advance(list_begin(pt_list), 6), 3, pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 0);
            vector_push_back(pt_vec, 0);
            algo_fill_n(list_end(pt_list), 0, pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            vector_push_back(pt_vec, 1000);
            vector_push_back(pt_vec, 2000);
            algo_fill_n(list_begin(pt_list), list_size(pt_list), pt_vec);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_equal                          */
        {
            list_t* pt_list = create_list(list_t<int>);
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_item = create_list(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL || pt_item == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);
            list_init(pt_item);

            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_clear(pt_item);
                list_push_back(pt_item, t_index);
                list_push_back(pt_list, pt_item);
                list_clear(pt_item);
                list_push_back(pt_item, t_index + 5);
                vector_push_back(pt_vec, pt_item);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_clear(pt_item);
                list_push_back(pt_item, t_index);
                list_push_back(pt_list, pt_item);
                vector_push_back(pt_vec, pt_item);
            }
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
            list_destroy(pt_item);
        }
        /*algo_equal_if                       */
        {
            list_t* pt_list = create_list(list_t<int>);
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_item = create_list(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL || pt_item == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);
            list_init(pt_item);

            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _list_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_clear(pt_item);
                list_push_back(pt_item, t_index);
                list_push_back(pt_list, pt_item);
                list_clear(pt_item);
                list_push_back(pt_item, t_index + 5);
                vector_push_back(pt_vec, pt_item);
            }
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _list_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_clear(pt_item);
                list_push_back(pt_item, t_index);
                list_push_back(pt_list, pt_item);
                vector_push_back(pt_vec, pt_item);
            }
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _list_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
            list_destroy(pt_item);
        }
        /*algo_swap                           */
        /*algo_iter_swap                      */
        {
            list_t* pt_list = create_list(vector_t<int>);
            vector_t* pt_vec = create_vector(vector_t<int>);
            vector_t* pt_item = create_vector(int);
            size_t t_index = 0;
            if(pt_list == NULL || pt_vec == NULL || pt_item == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);
            vector_init(pt_item);

            for(t_index = 0; t_index < 7; ++t_index)
            {
                vector_push_back(pt_item, t_index + 1);
                list_push_back(pt_list, pt_item);
            }
            vector_clear(pt_item);
            for(t_index = 0; t_index < 7; ++t_index)
            {
                vector_push_back(pt_item, t_index * 2);
                vector_push_back(pt_vec, pt_item);
            }
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_vector);
            printf("\n");

            algo_swap(list_begin(pt_list), list_begin(pt_list));
            algo_iter_swap(vector_begin(pt_vec), vector_begin(pt_vec));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_vector);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_advance(list_begin(pt_list), 5));
            algo_iter_swap(vector_begin(pt_vec), iterator_next_n(vector_begin(pt_vec), 5));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_vector);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_next(vector_begin(pt_vec)));
            algo_iter_swap(vector_begin(pt_vec), iterator_next(list_begin(pt_list)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_vector);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_vector);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
            vector_destroy(pt_item);
        }
        /*algo_lexicographical_compare        */
        /*algo_lexicographical_compare_if     */
        {
            list_t* pt_list = create_list(list_t<int>);
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_item = create_list(int);
            if(pt_list == NULL || pt_vec == NULL || pt_item == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);
            list_init(pt_item);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_item);
            list_push_back(pt_item, 3);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            list_push_back(pt_list, pt_item);
            vector_clear(pt_vec);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            vector_pop_back(pt_vec);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            vector_pop_back(pt_vec);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_item);
            list_push_back(pt_item, 5);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
            list_destroy(pt_item);
        }
        /*algo_lexicographical_compare_3way   */
        /*algo_lexicographical_compare_3way_if*/
        {
            list_t* pt_list = create_list(list_t<int>);
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_item = create_list(int);
            if(pt_list == NULL || pt_vec == NULL || pt_item == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);
            list_init(pt_item);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            list_clear(pt_item);
            list_push_back(pt_item, 3);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            list_clear(pt_list);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            list_push_back(pt_list, pt_item);
            vector_clear(pt_vec);
            list_clear(pt_item);
            list_push_back(pt_item, 3);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 8);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 7);
            vector_push_back(pt_vec, pt_item);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            vector_pop_back(pt_vec);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            vector_pop_back(pt_vec);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            list_clear(pt_item);
            list_push_back(pt_item, 5);
            vector_push_back(pt_vec, pt_item);
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_list));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
            list_destroy(pt_item);
        }
        /*algo_max                            */
        /*algo_max_if                         */
        /*algo_min                            */
        /*algo_min_if                         */
        {
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_list = create_list(list_t<int>);
            list_t* pt_item = create_list(int);
            iterator_t t_min;
            iterator_t t_max;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);
            list_init(pt_item);

            list_push_back(pt_item, -2);
            list_push_back(pt_item, 89);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 4);
            list_push_back(pt_item, 3);
            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 0);
            list_push_back(pt_list, pt_item);

            list_clear(pt_item);
            list_push_back(pt_item, 9);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, -5);
            list_push_back(pt_item, 5);
            list_push_back(pt_item, 9);
            list_push_back(pt_item, 19);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 1);
            list_push_back(pt_item, 4);
            list_push_back(pt_item, 0);
            vector_push_back(pt_vec, pt_item);
            list_clear(pt_item);
            list_push_back(pt_item, 2);
            list_push_back(pt_item, 9);
            vector_push_back(pt_vec, pt_item);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            t_min = algo_min(list_begin(pt_list), vector_begin(pt_vec));
            t_max = algo_max(list_begin(pt_list), vector_begin(pt_vec));
            printf("minmum between two begin : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_min)),
                list_end((list_t*)iterator_get_pointer(t_min)), _print_int);
            printf("]\n");
            printf("maxmum between two begin : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_max)),
                list_end((list_t*)iterator_get_pointer(t_max)), _print_int);
            printf("]\n");

            t_min = algo_min_if(list_begin(pt_list), vector_begin(pt_vec), _sizeless);
            t_max = algo_max_if(list_begin(pt_list), vector_begin(pt_vec), _sizeless);
            printf("minmum of absolute between two begin : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_min)),
                list_end((list_t*)iterator_get_pointer(t_min)), _print_int);
            printf("]\n");
            printf("maxmum of absolute between two begin : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_max)),
                list_end((list_t*)iterator_get_pointer(t_max)), _print_int);
            printf("]\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
            list_destroy(pt_item);
        }
        /*algo_mismatch                       */
        /*algo_mismatch_if                    */
        {
            vector_t* pt_vec = create_vector(list_t<int>);
            list_t* pt_list = create_list(list_t<int>);
            list_t* pt_item = create_list(int);
            range_t t_range;
            if(pt_vec == NULL || pt_list == NULL || pt_item == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);
            list_init(pt_item);

            list_push_back(pt_item, 2);
            list_push_back(pt_list, pt_item);
            vector_push_back(pt_vec, pt_item);
            *(int*)list_front(pt_item) = 3;
            list_push_back(pt_list, pt_item);
            vector_push_back(pt_vec, pt_item);
            *(int*)list_front(pt_item) = 4;
            list_push_back(pt_list, pt_item);
            vector_push_back(pt_vec, pt_item);
            *(int*)list_front(pt_item) = 5;
            list_push_back(pt_list, pt_item);
            vector_push_back(pt_vec, pt_item);

            *(int*)list_front(pt_item) = 11;
            list_push_back(pt_list, pt_item);
            *(int*)list_front(pt_item) = 22;
            list_push_back(pt_list, pt_item);
            *(int*)list_front(pt_item) = 33;
            list_push_back(pt_list, pt_item);

            *(int*)list_front(pt_item) = 44;
            vector_push_back(pt_vec, pt_item);
            *(int*)list_front(pt_item) = 55;
            vector_push_back(pt_vec, pt_item);
            *(int*)list_front(pt_item) = 9;
            vector_push_back(pt_vec, pt_item);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_list);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_list);
            printf("\n");

            t_range = algo_mismatch(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec));
            printf("the first mismatch : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_range.it_begin)),
                list_end((list_t*)iterator_get_pointer(t_range.it_begin)), _print_int);
            printf("] and [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_range.it_end)),
                list_end((list_t*)iterator_get_pointer(t_range.it_end)), _print_int);
            printf("]\n");
            t_range = algo_mismatch_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), fun_less_equal_list);
            printf("not less or equal : [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_range.it_begin)),
                list_end((list_t*)iterator_get_pointer(t_range.it_begin)), _print_int);
            printf("] and [");
            algo_for_each(list_begin((list_t*)iterator_get_pointer(t_range.it_end)),
                list_end((list_t*)iterator_get_pointer(t_range.it_end)), _print_int);
            printf("]\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
            list_destroy(pt_item);
        }
        /*algo_copy                           */
        /*algo_copy_n                         */
        /*algo_copy_backward                  */
        {
            vector_t* pt_vec1 = create_vector(list_t<int>);
            vector_t* pt_vec2 = create_vector(list_t<int>);
            list_t* pt_list1 = create_list(list_t<int>);
            list_t* pt_list2 = create_list(list_t<int>);
            list_t* pt_item = create_list(int);
            size_t t_index = 0;
            if(pt_vec1 == NULL || pt_vec2 == NULL ||
               pt_list1 == NULL || pt_list2 == NULL || pt_item == NULL)
            {
                return;
            }
            vector_init(pt_vec1);
            vector_init(pt_vec2);
            list_init(pt_list1);
            list_init(pt_list2);
            list_init(pt_item);

            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_item, t_index);
                list_push_back(pt_list1, pt_item);
                list_push_back(pt_list2, pt_item);
                vector_push_back(pt_vec1, pt_item);
                vector_push_back(pt_vec2, pt_item);
            }

            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            algo_copy(iterator_advance(list_begin(pt_list1), 4),
                list_end(pt_list1), list_begin(pt_list1));
            algo_copy(iterator_advance(list_begin(pt_list2), 6),
                list_end(pt_list2), list_begin(pt_list2));
            algo_copy(vector_begin(pt_vec1), iterator_advance(vector_begin(pt_vec1), 6),
                iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy(vector_begin(pt_vec2), iterator_advance(vector_begin(pt_vec2), 3),
                iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            list_clear(pt_item);
            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_item, t_index);
                list_push_back(pt_list1, pt_item);
                list_push_back(pt_list2, pt_item);
                vector_push_back(pt_vec1, pt_item);
                vector_push_back(pt_vec2, pt_item);
            }
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            algo_copy_n(iterator_advance(list_begin(pt_list1), 4), 5, list_begin(pt_list1));
            algo_copy_n(iterator_advance(list_begin(pt_list2), 6), 3, list_begin(pt_list2));
            algo_copy_n(vector_begin(pt_vec1), 6, iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy_n(vector_begin(pt_vec2), 3, iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            list_clear(pt_item);
            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            for(t_index = 0; t_index < 10; ++t_index)
            {
                list_push_back(pt_item, t_index);
                list_push_back(pt_list1, pt_item);
                list_push_back(pt_list2, pt_item);
                vector_push_back(pt_vec1, pt_item);
                vector_push_back(pt_vec2, pt_item);
            }
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            algo_copy_backward(iterator_advance(list_begin(pt_list1), 4), list_end(pt_list1),
                iterator_advance(list_begin(pt_list1), 7));
            algo_copy_backward(iterator_advance(list_begin(pt_list2), 6), list_end(pt_list2),
                iterator_advance(list_begin(pt_list2), 5));
            algo_copy_backward(vector_begin(pt_vec1),
                iterator_advance(vector_begin(pt_vec1), 6),
                iterator_prev(vector_end(pt_vec1)));
            algo_copy_backward(vector_begin(pt_vec2),
                iterator_advance(vector_begin(pt_vec2), 3),
                iterator_prev(vector_end(pt_vec2)));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_list);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_list);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_list);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_list);
            printf("\n\n");

            vector_destroy(pt_vec1);
            vector_destroy(pt_vec2);
            list_destroy(pt_list1);
            list_destroy(pt_list2);
            list_destroy(pt_item);
        }
    }
    /* c string type */
    {
        /*_algo_fill                          */
        {
            list_t* pt_list = create_list(char*);
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(list_begin(pt_list), list_begin(pt_list), "abcdefg");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(list_begin(pt_list), iterator_advance(list_begin(pt_list), 3), "90");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(iterator_next(list_begin(pt_list)),
                iterator_advance(list_begin(pt_list), 5), "love");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(iterator_advance(list_begin(pt_list), 6), list_end(pt_list), "$$$$");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(list_end(pt_list), list_end(pt_list), "libcstl");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill(list_begin(pt_list), list_end(pt_list), "OK");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            list_destroy(pt_list);
        }
        /*_algo_fill_n                        */
        {
            list_t* pt_list = create_list(char*);
            if(pt_list == NULL)
            {
                return;
            }
            list_init_n(pt_list, 10);
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill_n(list_begin(pt_list), 0, "455");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill_n(list_begin(pt_list), 3, "90");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill_n(iterator_next(list_begin(pt_list)), 5, "-512");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill_n(list_end(pt_list), 0, "33");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            algo_fill_n(list_begin(pt_list), list_size(pt_list), "1234");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");

            list_destroy(pt_list);
        }
        /*algo_equal                          */
        {
            list_t* pt_list = create_list(char*);
            vector_t* pt_vec = create_vector(char*);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            list_push_back(pt_list, "t_index");
            vector_push_back(pt_vec, "t_index + 5");
            list_push_back(pt_list, "xxxxxxxxxxxx");
            vector_push_back(pt_vec, "yyyyyyyyyyyyyy");
            list_push_back(pt_list, "lskjflsadk+_(*&^%#@$^&");
            vector_push_back(pt_vec, "BBBBBBBBB");
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            list_push_back(pt_list, "t_index");
            vector_push_back(pt_vec, "t_index");
            list_push_back(pt_list, "char 1 + 2");
            vector_push_back(pt_vec, "char 1 + 2");
            list_push_back(pt_list, "uuuu");
            vector_push_back(pt_vec, "uuuu");
            printf("equal : %d\n", algo_equal(
                list_begin(pt_list), list_end(pt_list), vector_begin(pt_vec)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_equal_if                       */
        {
            list_t* pt_list = create_list(char*);
            vector_t* pt_vec = create_vector(char*);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _cstr_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            list_push_back(pt_list, "lowercase");
            vector_push_back(pt_vec, "lowercase");
            list_push_back(pt_list, "NoCase");
            vector_push_back(pt_vec, "nocase");
            list_push_back(pt_list, "UPPERCASE");
            vector_push_back(pt_vec, "UPPERCASE");

            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _cstr_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            list_clear(pt_list);
            vector_clear(pt_vec);
            list_push_back(pt_list, "lowercase");
            vector_push_back(pt_vec, "lower case");
            list_push_back(pt_list, "NoCase");
            vector_push_back(pt_vec, "no case");
            list_push_back(pt_list, "UPPERCASE");
            vector_push_back(pt_vec, "UPPER CASE");
            printf("equal : %d\n", algo_equal_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), _cstr_equal_ex));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_swap                           */
        /*algo_iter_swap                      */
        {
            list_t* pt_list = create_list(char*);
            vector_t* pt_vec = create_vector(char*);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            list_push_back(pt_list, "t_index");
            vector_push_back(pt_vec, " - 1");
            list_push_back(pt_list, "lklklklkjlkjlkjlkj");
            vector_push_back(pt_vec, "UIOWHBVOADFH");
            list_push_back(pt_list, "bbaidudjfhqwe");
            vector_push_back(pt_vec, "9937849");
            list_push_back(pt_list, "qqqqqqqqqqqqqqqq");
            vector_push_back(pt_vec, "VECTOR");
            list_push_back(pt_list, "<><><><><><>");
            vector_push_back(pt_vec, "MNMNMNMNMNM");
            list_push_back(pt_list, "list");
            vector_push_back(pt_vec, "LIST");
            list_push_back(pt_list, "push");
            vector_push_back(pt_vec, "POP");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            algo_swap(list_begin(pt_list), list_begin(pt_list));
            algo_iter_swap(vector_begin(pt_vec), vector_begin(pt_vec));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_advance(list_begin(pt_list), 5));
            algo_iter_swap(vector_begin(pt_vec), iterator_next_n(vector_begin(pt_vec), 5));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            algo_swap(list_begin(pt_list), iterator_next(vector_begin(pt_vec)));
            algo_iter_swap(vector_begin(pt_vec), iterator_next(list_begin(pt_list)));
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare        */
        /*algo_lexicographical_compare_if     */
        {
            list_t* pt_list = create_list(char*);
            vector_t* pt_vec = create_vector(char*);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "7");
            vector_push_back(pt_vec, "7");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "7");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "5");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec)));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_lexicographical_compare_3way   */
        /*algo_lexicographical_compare_3way_if*/
        {
            list_t* pt_list = create_list(char*);
            vector_t* pt_vec = create_vector(char*);
            if(pt_list == NULL || pt_vec == NULL)
            {
                return;
            }
            list_init(pt_list);
            vector_init(pt_vec);

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "3");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "7");
            vector_push_back(pt_vec, "7");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "7");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_clear(pt_list);
            list_push_back(pt_list, "3");
            list_push_back(pt_list, "2");
            list_push_back(pt_list, "8");
            list_push_back(pt_list, "7");
            vector_clear(pt_vec);
            vector_push_back(pt_vec, "3");
            vector_push_back(pt_vec, "2");
            vector_push_back(pt_vec, "8");
            vector_push_back(pt_vec, "5");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");
            printf("algo_lexicographical_compare() : ");
            algo_lexicographical_compare_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr) == 0 ?
                printf("false\n") : printf("true\n");
            printf("algo_lexicographical_compare_3way() : %d\n",
                algo_lexicographical_compare_3way_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), vector_end(pt_vec), fun_greater_cstr));

            list_destroy(pt_list);
            vector_destroy(pt_vec);
        }
        /*algo_max                            */
        /*algo_max_if                         */
        /*algo_min                            */
        /*algo_min_if                         */
        {
            vector_t* pt_vec = create_vector(char*);
            list_t* pt_list = create_list(char*);
            iterator_t t_min;
            iterator_t t_max;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);

            list_push_back(pt_list, "F");
            list_push_back(pt_list, "G");
            list_push_back(pt_list, "H");
            list_push_back(pt_list, "I");
            list_push_back(pt_list, "J");
            list_push_back(pt_list, "K");
            list_push_back(pt_list, "L");
            list_push_back(pt_list, "M");
            list_push_back(pt_list, "N");
            vector_push_back(pt_vec, "a");
            vector_push_back(pt_vec, "b");
            vector_push_back(pt_vec, "c");
            vector_push_back(pt_vec, "d");
            vector_push_back(pt_vec, "e");
            vector_push_back(pt_vec, "f");
            vector_push_back(pt_vec, "g");
            vector_push_back(pt_vec, "h");
            vector_push_back(pt_vec, "i");
            vector_push_back(pt_vec, "j");

            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            t_min = algo_min(list_begin(pt_list), vector_begin(pt_vec));
            t_max = algo_max(list_begin(pt_list), vector_begin(pt_vec));
            printf("minmum between two begin : %s\n", (char*)iterator_get_pointer(t_min));
            printf("maxmum between two begin : %s\n", (char*)iterator_get_pointer(t_max));

            t_min = algo_min_if(list_begin(pt_list), vector_begin(pt_vec), _nocaseless);
            t_max = algo_max_if(list_begin(pt_list), vector_begin(pt_vec), _nocaseless);
            printf("minmum of absolute between two begin : %s\n",
                (char*)iterator_get_pointer(t_min));
            printf("maxmum of absolute between two begin : %s\n",
                (char*)iterator_get_pointer(t_max));

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_mismatch                       */
        /*algo_mismatch_if                    */
        {
            vector_t* pt_vec = create_vector(char*);
            list_t* pt_list = create_list(char*);
            range_t t_range;
            if(pt_vec == NULL || pt_list == NULL)
            {
                return;
            }
            vector_init(pt_vec);
            list_init(pt_list);
            list_push_back(pt_list, "aa");
            list_push_back(pt_list, "bb");
            list_push_back(pt_list, "cc");
            list_push_back(pt_list, "11");
            list_push_back(pt_list, "22");
            list_push_back(pt_list, "33");
            vector_push_back(pt_vec, "aa");
            vector_push_back(pt_vec, "bb");
            vector_push_back(pt_vec, "cc");
            vector_push_back(pt_vec, "44");
            vector_push_back(pt_vec, "55");
            vector_push_back(pt_vec, "0");
            printf("list  : ");
            algo_for_each(list_begin(pt_list), list_end(pt_list), _print_cstr);
            printf("\n");
            printf("vector: ");
            algo_for_each(vector_begin(pt_vec), vector_end(pt_vec), _print_cstr);
            printf("\n");

            t_range = algo_mismatch(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec));
            printf("the first mismatch : %s and %s\n",
                (char*)iterator_get_pointer(t_range.it_begin),
                (char*)iterator_get_pointer(t_range.it_end));
            t_range = algo_mismatch_if(list_begin(pt_list), list_end(pt_list),
                vector_begin(pt_vec), fun_less_equal_cstr);
            printf("not less or equal : %s and %s\n",
                (char*)iterator_get_pointer(t_range.it_begin),
                (char*)iterator_get_pointer(t_range.it_end));

            vector_destroy(pt_vec);
            list_destroy(pt_list);
        }
        /*algo_copy                           */
        /*algo_copy_n                         */
        /*algo_copy_backward                  */
        {
            vector_t* pt_vec1 = create_vector(char*);
            vector_t* pt_vec2 = create_vector(char*);
            list_t* pt_list1 = create_list(char*);
            list_t* pt_list2 = create_list(char*);
            if(pt_vec1 == NULL || pt_vec2 == NULL || pt_list1 == NULL || pt_list2 == NULL)
            {
                return;
            }
            vector_init(pt_vec1);
            vector_init(pt_vec2);
            list_init(pt_list1);
            list_init(pt_list2);

            list_push_back(pt_list1, "0");
            list_push_back(pt_list1, "1");
            list_push_back(pt_list1, "2");
            list_push_back(pt_list1, "3");
            list_push_back(pt_list1, "4");
            list_push_back(pt_list1, "5");
            list_push_back(pt_list1, "6");
            list_push_back(pt_list1, "7");
            list_push_back(pt_list1, "8");
            list_push_back(pt_list1, "9");
            list_push_back(pt_list2, "0");
            list_push_back(pt_list2, "1");
            list_push_back(pt_list2, "2");
            list_push_back(pt_list2, "3");
            list_push_back(pt_list2, "4");
            list_push_back(pt_list2, "5");
            list_push_back(pt_list2, "6");
            list_push_back(pt_list2, "7");
            list_push_back(pt_list2, "8");
            list_push_back(pt_list2, "9");
            vector_push_back(pt_vec1, "0");
            vector_push_back(pt_vec1, "1");
            vector_push_back(pt_vec1, "2");
            vector_push_back(pt_vec1, "3");
            vector_push_back(pt_vec1, "4");
            vector_push_back(pt_vec1, "5");
            vector_push_back(pt_vec1, "6");
            vector_push_back(pt_vec1, "7");
            vector_push_back(pt_vec1, "8");
            vector_push_back(pt_vec1, "9");
            vector_push_back(pt_vec2, "0");
            vector_push_back(pt_vec2, "1");
            vector_push_back(pt_vec2, "2");
            vector_push_back(pt_vec2, "3");
            vector_push_back(pt_vec2, "4");
            vector_push_back(pt_vec2, "5");
            vector_push_back(pt_vec2, "6");
            vector_push_back(pt_vec2, "7");
            vector_push_back(pt_vec2, "8");
            vector_push_back(pt_vec2, "9");

            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            algo_copy(iterator_advance(list_begin(pt_list1), 4),
                list_end(pt_list1), list_begin(pt_list1));
            algo_copy(iterator_advance(list_begin(pt_list2), 6),
                list_end(pt_list2), list_begin(pt_list2));
            algo_copy(vector_begin(pt_vec1), iterator_advance(vector_begin(pt_vec1), 6),
                iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy(vector_begin(pt_vec2), iterator_advance(vector_begin(pt_vec2), 3),
                iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            list_push_back(pt_list1, "0");
            list_push_back(pt_list1, "1");
            list_push_back(pt_list1, "2");
            list_push_back(pt_list1, "3");
            list_push_back(pt_list1, "4");
            list_push_back(pt_list1, "5");
            list_push_back(pt_list1, "6");
            list_push_back(pt_list1, "7");
            list_push_back(pt_list1, "8");
            list_push_back(pt_list1, "9");
            list_push_back(pt_list2, "0");
            list_push_back(pt_list2, "1");
            list_push_back(pt_list2, "2");
            list_push_back(pt_list2, "3");
            list_push_back(pt_list2, "4");
            list_push_back(pt_list2, "5");
            list_push_back(pt_list2, "6");
            list_push_back(pt_list2, "7");
            list_push_back(pt_list2, "8");
            list_push_back(pt_list2, "9");
            vector_push_back(pt_vec1, "0");
            vector_push_back(pt_vec1, "1");
            vector_push_back(pt_vec1, "2");
            vector_push_back(pt_vec1, "3");
            vector_push_back(pt_vec1, "4");
            vector_push_back(pt_vec1, "5");
            vector_push_back(pt_vec1, "6");
            vector_push_back(pt_vec1, "7");
            vector_push_back(pt_vec1, "8");
            vector_push_back(pt_vec1, "9");
            vector_push_back(pt_vec2, "0");
            vector_push_back(pt_vec2, "1");
            vector_push_back(pt_vec2, "2");
            vector_push_back(pt_vec2, "3");
            vector_push_back(pt_vec2, "4");
            vector_push_back(pt_vec2, "5");
            vector_push_back(pt_vec2, "6");
            vector_push_back(pt_vec2, "7");
            vector_push_back(pt_vec2, "8");
            vector_push_back(pt_vec2, "9");
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            algo_copy_n(iterator_advance(list_begin(pt_list1), 4), 5, list_begin(pt_list1));
            algo_copy_n(iterator_advance(list_begin(pt_list2), 6), 3, list_begin(pt_list2));
            algo_copy_n(vector_begin(pt_vec1), 6, iterator_advance(vector_begin(pt_vec1), 3));
            algo_copy_n(vector_begin(pt_vec2), 3, iterator_advance(vector_begin(pt_vec2), 6));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            list_clear(pt_list1);
            list_clear(pt_list2);
            vector_clear(pt_vec1);
            vector_clear(pt_vec2);
            list_push_back(pt_list1, "0");
            list_push_back(pt_list1, "1");
            list_push_back(pt_list1, "2");
            list_push_back(pt_list1, "3");
            list_push_back(pt_list1, "4");
            list_push_back(pt_list1, "5");
            list_push_back(pt_list1, "6");
            list_push_back(pt_list1, "7");
            list_push_back(pt_list1, "8");
            list_push_back(pt_list1, "9");
            list_push_back(pt_list2, "0");
            list_push_back(pt_list2, "1");
            list_push_back(pt_list2, "2");
            list_push_back(pt_list2, "3");
            list_push_back(pt_list2, "4");
            list_push_back(pt_list2, "5");
            list_push_back(pt_list2, "6");
            list_push_back(pt_list2, "7");
            list_push_back(pt_list2, "8");
            list_push_back(pt_list2, "9");
            vector_push_back(pt_vec1, "0");
            vector_push_back(pt_vec1, "1");
            vector_push_back(pt_vec1, "2");
            vector_push_back(pt_vec1, "3");
            vector_push_back(pt_vec1, "4");
            vector_push_back(pt_vec1, "5");
            vector_push_back(pt_vec1, "6");
            vector_push_back(pt_vec1, "7");
            vector_push_back(pt_vec1, "8");
            vector_push_back(pt_vec1, "9");
            vector_push_back(pt_vec2, "0");
            vector_push_back(pt_vec2, "1");
            vector_push_back(pt_vec2, "2");
            vector_push_back(pt_vec2, "3");
            vector_push_back(pt_vec2, "4");
            vector_push_back(pt_vec2, "5");
            vector_push_back(pt_vec2, "6");
            vector_push_back(pt_vec2, "7");
            vector_push_back(pt_vec2, "8");
            vector_push_back(pt_vec2, "9");
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            algo_copy_backward(iterator_advance(list_begin(pt_list1), 4), list_end(pt_list1),
                iterator_advance(list_begin(pt_list1), 7));
            algo_copy_backward(iterator_advance(list_begin(pt_list2), 6), list_end(pt_list2),
                iterator_advance(list_begin(pt_list2), 5));
            algo_copy_backward(vector_begin(pt_vec1),
                iterator_advance(vector_begin(pt_vec1), 6),
                iterator_prev(vector_end(pt_vec1)));
            algo_copy_backward(vector_begin(pt_vec2),
                iterator_advance(vector_begin(pt_vec2), 3),
                iterator_prev(vector_end(pt_vec2)));
            printf("list1  : ");
            algo_for_each(list_begin(pt_list1), list_end(pt_list1), _print_cstr);
            printf("\n");
            printf("list2  : ");
            algo_for_each(list_begin(pt_list2), list_end(pt_list2), _print_cstr);
            printf("\n");
            printf("vector1: ");
            algo_for_each(vector_begin(pt_vec1), vector_end(pt_vec1), _print_cstr);
            printf("\n");
            printf("vector2: ");
            algo_for_each(vector_begin(pt_vec2), vector_end(pt_vec2), _print_cstr);
            printf("\n\n");

            vector_destroy(pt_vec1);
            vector_destroy(pt_vec2);
            list_destroy(pt_list1);
            list_destroy(pt_list2);
        }
    }
}

void algo_sample_init(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    ((algo_sample_t*)cpv_input)->_t_id = 0;
    ((algo_sample_t*)cpv_input)->_t_content = 0;
    *(bool_t*)pv_output = true;
}
void algo_sample_copy(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    ((algo_sample_t*)cpv_first)->_t_id = ((algo_sample_t*)cpv_second)->_t_id;
    ((algo_sample_t*)cpv_first)->_t_content = ((algo_sample_t*)cpv_second)->_t_content;
    *(bool_t*)pv_output = true;
}
void algo_sample_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((algo_sample_t*)cpv_first)->_t_id < ((algo_sample_t*)cpv_second)->_t_id)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}
void algo_sample_destroy(const void* cpv_input, void* pv_output)
{
    assert(cpv_input != NULL && pv_output != NULL);
    ((algo_sample_t*)cpv_input)->_t_id = 0;
    ((algo_sample_t*)cpv_input)->_t_content = 0;
    *(bool_t*)pv_output = true;
}
void algo_sample_greater(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((algo_sample_t*)cpv_first)->_t_id > ((algo_sample_t*)cpv_second)->_t_id)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}
void algo_sample_content_less(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((algo_sample_t*)cpv_first)->_t_content < ((algo_sample_t*)cpv_second)->_t_content)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}
void algo_sample_equal(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(((algo_sample_t*)cpv_first)->_t_id == ((algo_sample_t*)cpv_second)->_t_id &&
       ((algo_sample_t*)cpv_first)->_t_content == ((algo_sample_t*)cpv_second)->_t_content)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}
void algo_sample_show(const void* cpv_input, void* pv_output)
{
    algo_sample_t* pt_sample = (algo_sample_t*)cpv_input;
    pv_output = NULL;
    printf("<%u, %u>, ", pt_sample->_t_id, pt_sample->_t_content);
}

/** local function implementation section **/
static void _sizeless(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(list_size((list_t*)cpv_first) < list_size((list_t*)cpv_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

static void _absless(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(abs(*(int*)cpv_first) < abs(*(int*)cpv_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

static void _equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(*(int*)cpv_first + 5 == *(int*)cpv_second)
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

static void _list_equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);
    if(list_size((list_t*)cpv_first) == list_size((list_t*)cpv_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }
}

static void _nocaseless(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    string_t* pt_first = create_string();
    string_t* pt_second = create_string();
    size_t t_index = 0;
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);

    if(pt_first == NULL || pt_second == NULL)
    {
        *(bool_t*)pv_output = false;
        return;
    }

    string_init_cstr(pt_first, (char*)cpv_first);
    string_init_cstr(pt_second, (char*)cpv_second);

    for(t_index = 0; t_index < string_size(pt_first); ++t_index)
    {
        *(char*)string_at(pt_first, t_index) = tolower(*(char*)string_at(pt_first, t_index));
    }
    for(t_index = 0; t_index < string_size(pt_second); ++t_index)
    {
        *(char*)string_at(pt_second, t_index) = tolower(*(char*)string_at(pt_second, t_index));
    }

    if(string_less(pt_first, pt_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }

    string_destroy(pt_first);
    string_destroy(pt_second);
}
static void _cstr_equal_ex(const void* cpv_first, const void* cpv_second, void* pv_output)
{
    string_t* pt_first = create_string();
    string_t* pt_second = create_string();
    size_t t_index = 0;
    assert(cpv_first != NULL && cpv_second != NULL && pv_output != NULL);

    if(pt_first == NULL || pt_second == NULL)
    {
        *(bool_t*)pv_output = false;
        return;
    }

    string_init_cstr(pt_first, (char*)cpv_first);
    string_init_cstr(pt_second, (char*)cpv_second);

    for(t_index = 0; t_index < string_size(pt_first); ++t_index)
    {
        *(char*)string_at(pt_first, t_index) = tolower(*(char*)string_at(pt_first, t_index));
    }
    for(t_index = 0; t_index < string_size(pt_second); ++t_index)
    {
        *(char*)string_at(pt_second, t_index) = tolower(*(char*)string_at(pt_second, t_index));
    }

    if(string_equal(pt_first, pt_second))
    {
        *(bool_t*)pv_output = true;
    }
    else
    {
        *(bool_t*)pv_output = false;
    }

    string_destroy(pt_first);
    string_destroy(pt_second);
}

static void _print_int(const void* cpv_input, void* pv_output)
{
    pv_output = NULL;
    printf("%d, ", *(int*)cpv_input);
}

static void _print_vector(const void* cpv_input, void* pv_output)
{
    pv_output = NULL;
    printf("[");
    algo_for_each(vector_begin((vector_t*)cpv_input), vector_end((vector_t*)cpv_input),
        _print_int);
    printf("], ");
}

static void _print_list(const void* cpv_input, void* pv_output)
{
    pv_output = NULL;
    printf("[");
    algo_for_each(list_begin((list_t*)cpv_input), list_end((list_t*)cpv_input), _print_int);
    printf("], ");
}

static void _print_cstr(const void* cpv_input, void* pv_output)
{
    pv_output = NULL;
    printf("\"%s\", ", (char*)cpv_input);
}

/** eof **/


/*
 *  The iterator interface of hash_map.
 *  Copyright (C)  2008,2009,2010,2011  Wangbo
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

#ifndef _CSTL_HASH_MAP_ITERATOR_H_
#define _CSTL_HASH_MAP_ITERATOR_H_

#ifdef __cplusplus
extern "C" {
#endif

/** include section **/

/** constant declaration and macro section **/

/** data type declaration and struct, union, enum section **/
typedef iterator_t hash_map_iterator_t;

/** exported global variable declaration section **/

/** exported function prototype section **/
/**
 * Create hash_map iterator.
 * @return hash_map iterator.
 * @remarks the returned iterator is invalid iterator.
 */
extern hash_map_iterator_t create_hash_map_iterator(void);

/**
 * Get data value referenced by iterator.
 * @param it_iter    hash_map iterator.
 * @param pv_value   data value buffer.
 * @return void.
 * @remarks it_iter must be valid hash_map iterator, otherwise the behavior is undefined. if pv_value == NULL, then the
 *          behavior is undefined.
 */
extern void _hash_map_iterator_get_value(hash_map_iterator_t it_iter, void* pv_value);

/**
 * Get data value pointer referenced by iterator.
 * @param it_iter    hash_map iterator.
 * @return void.
 * @remarks it_iter must be valid hash_map iterator, otherwise the behavior is undefined.
 */
extern const void* _hash_map_iterator_get_pointer(hash_map_iterator_t it_iter); 

/**
 * Return iterator reference previous element.
 * @param  it_iter    current iterator.
 * @return previous iterator.
 * @remarks it_iter and previous iterator must be valid iterator, otherwise the behavior is undefined.
 */
extern hash_map_iterator_t _hash_map_iterator_prev(hash_map_iterator_t it_iter);

/**
 * Return iterator reference next element.
 * @param  it_iter    current iterator.
 * @return next iterator.
 * @remarks it_iter and next iterator must be valid iterator, otherwise the behavior is undefined.
 */
extern hash_map_iterator_t _hash_map_iterator_next(hash_map_iterator_t it_iter);

/**
 * Test the two hash_map iterator are equal.
 * @param it_first    hash_map iterator.
 * @param it_second   hash_map iterator.
 * @return true, if the two iterator are equal, else return false.
 * @remarks the two iterator must be valid hash_map iterator, otherwise the behavior is undefined.
 */
extern bool_t _hash_map_iterator_equal(hash_map_iterator_t it_first, hash_map_iterator_t it_second);

/**
 * Calculate distance between two iterators.
 * @param it_first    hash_map iterator.
 * @param it_second   hash_map iterator.
 * @return distance.
 * @remarks the two iterator must be valid hash_map iterator, and must be belong to same hash_map, otherwise the behavior
 *          is undefined. the result distance may be less than 0, equal to 0 or greater than 0.
 */
extern int _hash_map_iterator_distance(hash_map_iterator_t it_first, hash_map_iterator_t it_second);

/**
 * Test the first iterator is before the second.
 * @param it_first    hash_map iterator.
 * @param it_second   hash_map iterator.
 * @return true, if the first iterator is before the second, else return false.
 * @remarks the two iterator must be valid hash_map iterator, and must be belong to same hash_map, otherwise the behavior
 *          is undefined.
 */
extern bool_t _hash_map_iterator_before(hash_map_iterator_t it_first, hash_map_iterator_t it_second);

#ifdef __cplusplus
}
#endif

#endif /* _CSTL_HASH_MAP_ITERATOR_H_ */
/** eof **/


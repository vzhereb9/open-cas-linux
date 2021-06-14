/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "lfu_no_balance.h"
#include "ops.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../concurrency/ocf_concurrency.h"
#include "../mngt/ocf_mngt_common.h"
#include "../engine/engine_zero.h"
#include "../ocf_cache_priv.h"
#include "../ocf_request.h"
#include "../engine/engine_common.h"

#define OCF_EVICTION_MAX_SCAN 1024

static const ocf_cache_line_t end_marker = (ocf_cache_line_t)-1;

/* Adds the given collision_index to the _head_ of the lfu_no_balance list */
static void add_lfu_no_balance_head(ocf_cache_t cache,
		struct ocf_lfu_no_balance_list *list,
		unsigned int collision_index)

{
	struct lfu_no_balance_eviction_policy_meta *node;
	unsigned int curr_head_index;

	ENV_BUG_ON(collision_index == end_marker);

	node = &ocf_metadata_get_eviction_policy(cache, collision_index)->lfu_no_balance;

	/* First node to be added/ */
	if (!list->num_nodes)  {
		list->head = collision_index;
		list->tail = collision_index;

		node->next = end_marker;
		node->prev = end_marker;
        ++node->num_requests;

		list->num_nodes = 1;
	} else {
		struct lfu_no_balance_eviction_policy_meta *curr_head;

		/* Not the first node to be added. */
		curr_head_index = list->head;

		ENV_BUG_ON(curr_head_index == end_marker);

		curr_head = &ocf_metadata_get_eviction_policy(cache,
				curr_head_index)->lfu_no_balance;

		curr_req = curr_head->num_requests;
		if (curr_req <= node->num_request){
            node->next = curr_head_index;
            node->prev = end_marker;
            curr_head->prev = collision_index;
            ++node->num_requests;

            list->head = collision_index;
		}
		else{
            curr_node = curr_head->next;
            while (curr_node != end_marker && curr_node->num_requests > node->num_requests)
            {
                curr_node = curr_node->next;
            }
            if (curr_node == end_marker){
                struct lfu_no_balance_eviction_policy_meta *prev_tail;

                ENV_BUG_ON(list->tail != curr_node);

                node->prev = list->tail;
                prev_tail = &ocf_metadata_get_eviction_policy(cache,
                                                              list->tail)->lfu_no_balance;
                prev_tail->next = collision_index;

                ++node->num_requests;
                list->tail = collision_index;
            }
            else{
                ENV_BUG_ON(curr_node != end_marker);
                med_node = &ocf_metadata_get_eviction_policy(cache,
                                                             curr_node)->lfu_no_balance;
                med_node->prev = prev_med_iter;
                prev_med_node = &ocf_metadata_get_eviction_policy(cache,
                                                                  prev_med_iter)->lfu_no_balance;
                prev_med_node->next = collision_index;
                med_node->prev = collision_index;
                node->next = curr_node;
                node->prev = prev_med_iter;
                ++node->num_requests;
            }
		}
        ++list->num_nodes;
	}
}

/* Deletes the node with the given collision_index from the lfu_no_balance list */
static void remove_lfu_no_balance_list(ocf_cache_t cache,
		struct ocf_lfu_no_balance_list *list,
		unsigned int collision_index)
{
	int is_head = 0, is_tail = 0;
	uint32_t prev_lfu_no_balance_node, next_lfu_no_balance_node;
	struct lfu_no_balance_eviction_policy_meta *node;

	ENV_BUG_ON(collision_index == end_marker);

	node = &ocf_metadata_get_eviction_policy(cache, collision_index)->lfu_no_balance;

	is_head = (list->head == collision_index);
	is_tail = (list->tail == collision_index);

	/* Set prev and next (even if not existent) */
	next_lfu_no_balance_node = node->next;
	prev_lfu_no_balance_node = node->prev;

	/* Case 1: If we are head AND tail, there is only one node.
	 * So unlink node and set that there is no node left in the list.
	 */
	if (is_head && is_tail) {
		node->next = end_marker;
		node->prev = end_marker;

		list->head = end_marker;
		list->tail = end_marker;
	}

	/* Case 2: else if this collision_index is lfu_no_balance head, but not tail,
	 * update head and return
	 */
	else if (is_head) {
		struct lfu_no_balance_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lfu_no_balance_node == end_marker);

		next_node = &ocf_metadata_get_eviction_policy(cache,
				next_lfu_no_balance_node)->lfu_no_balance;

		list->head = next_lfu_no_balance_node;

		node->next = end_marker;
		next_node->prev = end_marker;
	}

	/* Case 3: else if this collision_index is lfu_no_balance tail, but not head,
	 * update tail and return
	 */
	else if (is_tail) {
		struct lfu_no_balance_eviction_policy_meta *prev_node;

		ENV_BUG_ON(prev_lfu_no_balance_node == end_marker);

		list->tail = prev_lfu_no_balance_node;

		prev_node = &ocf_metadata_get_eviction_policy(cache,
				prev_lfu_no_balance_node)->lfu_no_balance;

		node->prev = end_marker;
		prev_node->next = end_marker;
	}

	/* Case 4: else this collision_index is a middle node. There is no
	 * change to the head and the tail pointers.
	 */
	else {
		struct lfu_no_balance_eviction_policy_meta *prev_node;
		struct lfu_no_balance_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lfu_no_balance_node == end_marker);
		ENV_BUG_ON(prev_lfu_no_balance_node == end_marker);

		next_node = &ocf_metadata_get_eviction_policy(cache,
				next_lfu_no_balance_node)->lfu_no_balance;
		prev_node = &ocf_metadata_get_eviction_policy(cache,
				prev_lfu_no_balance_node)->lfu_no_balance;

		/* Update prev and next nodes */
		prev_node->next = node->next;
		next_node->prev = node->prev;

		/* Update the given node */
		node->next = end_marker;
		node->prev = end_marker;
	}

	--list->num_nodes;
}


/*-- End of lfu_no_balance functions*/

void evp_lfu_no_balance_init_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	struct lfu_no_balance_eviction_policy_meta *node;

	node = &ocf_metadata_get_eviction_policy(cache, cline)->lfu_no_balance;

	node->prev = end_marker;
	node->next = end_marker;
}

static struct ocf_lfu_no_balance_list *evp_lfu_no_balance_get_list(struct ocf_user_part *part,
		uint32_t evp, bool clean)
{
	return clean ? &part->runtime->eviction[evp].policy.lfu_no_balance.clean :
			&part->runtime->eviction[evp].policy.lfu_no_balance.dirty;
}

static inline struct ocf_lfu_no_balance_list *evp_get_cline_list(ocf_cache_t cache,
		ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);

	return evp_lfu_no_balance_get_list(part, ev_list,
			!metadata_test_dirty(cache, cline));
}

/* the caller must hold the metadata lock */
void evp_lfu_no_balance_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	struct ocf_lfu_no_balance_list *list;

	list = evp_get_cline_list(cache, cline);
	remove_lfu_no_balance_list(cache, list, cline);
	balance_lfu_no_balance_list(cache, list);
}

static inline void lfu_no_balance_iter_init(struct ocf_lfu_no_balance_iter *iter, ocf_cache_t cache,
		struct ocf_user_part *part, uint32_t start_evp, bool clean,
		bool cl_lock_write, _lfu_no_balance_hash_locked_pfn hash_locked,
		struct ocf_request *req)
{
	uint32_t i;

	/* entire iterator implementation depends on gcc builtins for
	   bit operations which works on 64 bit integers at most */
	ENV_BUILD_BUG_ON(OCF_NUM_EVICTION_LISTS > sizeof(iter->evp) * 8);

	iter->cache = cache;
	iter->part = part;
	/* set iterator value to start_evp - 1 modulo OCF_NUM_EVICTION_LISTS */
	iter->evp = (start_evp + OCF_NUM_EVICTION_LISTS - 1) % OCF_NUM_EVICTION_LISTS;
	iter->num_avail_evps = OCF_NUM_EVICTION_LISTS;
	iter->next_avail_evp = ((1ULL << OCF_NUM_EVICTION_LISTS) - 1);
	iter->clean = clean;
	iter->cl_lock_write = cl_lock_write;
	iter->hash_locked = hash_locked;
	iter->req = req;

	for (i = 0; i < OCF_NUM_EVICTION_LISTS; i++)
		iter->curr_cline[i] = evp_lfu_no_balance_get_list(part, i, clean)->tail;
}

static inline void lfu_no_balance_iter_cleaning_init(struct ocf_lfu_no_balance_iter *iter,
		ocf_cache_t cache, struct ocf_user_part *part,
		uint32_t start_evp)
{
	/* Lock cachelines for read, non-exclusive access */
	lfu_no_balance_iter_init(iter, cache, part, start_evp, false, false,
			NULL, NULL);
}

static inline void lfu_no_balance_iter_eviction_init(struct ocf_lfu_no_balance_iter *iter,
		ocf_cache_t cache, struct ocf_user_part *part,
		uint32_t start_evp, bool cl_lock_write,
		struct ocf_request *req)
{
	/* Lock hash buckets for write, cachelines according to user request,
	 * however exclusive cacheline access is needed even in case of read
	 * access. _evp_lfu_no_balance_evict_hash_locked tells whether given hash bucket
	 * is already locked as part of request hash locking (to avoid attempt
	 * to acquire the same hash bucket lock twice) */
	lfu_no_balance_iter_init(iter, cache, part, start_evp, true, cl_lock_write,
		ocf_req_hash_in_range, req);
}


static inline uint32_t _lfu_no_balance_next_evp(struct ocf_lfu_no_balance_iter *iter)
{
	unsigned increment;

	increment = __builtin_ffsll(iter->next_avail_evp);
	iter->next_avail_evp = ocf_rotate_right(iter->next_avail_evp,
			increment, OCF_NUM_EVICTION_LISTS);
	iter->evp = (iter->evp + increment) % OCF_NUM_EVICTION_LISTS;

	return iter->evp;
}



static inline bool _lfu_no_balance_evp_is_empty(struct ocf_lfu_no_balance_iter *iter)
{
	return !(iter->next_avail_evp & (1ULL << (OCF_NUM_EVICTION_LISTS - 1)));
}

static inline void _lfu_no_balance_evp_set_empty(struct ocf_lfu_no_balance_iter *iter)
{
	iter->next_avail_evp &= ~(1ULL << (OCF_NUM_EVICTION_LISTS - 1));
	iter->num_avail_evps--;
}

static inline bool _lfu_no_balance_evp_all_empty(struct ocf_lfu_no_balance_iter *iter)
{
	return iter->num_avail_evps == 0;
}

static bool inline _lfu_no_balance_trylock_cacheline(struct ocf_lfu_no_balance_iter *iter,
		ocf_cache_line_t cline)
{
	struct ocf_cache_line_concurrency *c =
			ocf_cache_line_concurrency(iter->cache);

	return iter->cl_lock_write ?
		ocf_cache_line_try_lock_wr(c, cline) :
		ocf_cache_line_try_lock_rd(c, cline);
}

static void inline _lfu_no_balance_unlock_cacheline(struct ocf_lfu_no_balance_iter *iter,
		ocf_cache_line_t cline)
{
	struct ocf_cache_line_concurrency *c =
			ocf_cache_line_concurrency(iter->cache);

	if (iter->cl_lock_write)
		ocf_cache_line_unlock_wr(c, cline);
	else
		ocf_cache_line_unlock_rd(c, cline);
}

static bool inline _lfu_no_balance_trylock_hash(struct ocf_lfu_no_balance_iter *iter,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (iter->hash_locked != NULL && iter->hash_locked(
				iter->req, core_id, core_line)) {
		return true;
	}

	return ocf_hb_cline_naked_trylock_wr(
			&iter->cache->metadata.lock,
			core_id, core_line);
}

static void inline _lfu_no_balance_unlock_hash(struct ocf_lfu_no_balance_iter *iter,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (iter->hash_locked != NULL && iter->hash_locked(
				iter->req, core_id, core_line)) {
		return;
	}

	ocf_hb_cline_naked_unlock_wr(
			&iter->cache->metadata.lock,
			core_id, core_line);
}

static bool inline _lfu_no_balance_iter_evition_lock(struct ocf_lfu_no_balance_iter *iter,
		ocf_cache_line_t cache_line,
		ocf_core_id_t *core_id, uint64_t *core_line)

{
	struct ocf_request *req = iter->req;

	if (!_lfu_no_balance_trylock_cacheline(iter, cache_line))
		return false;

	ocf_metadata_get_core_info(iter->cache, cache_line,
		core_id, core_line);

	/* avoid evicting current request target cachelines */
	if (*core_id == ocf_core_get_id(req->core) &&
			*core_line >= req->core_line_first &&
			*core_line <= req->core_line_last) {
		_lfu_no_balance_unlock_cacheline(iter, cache_line);
		return false;
	}

	if (!_lfu_no_balance_trylock_hash(iter, *core_id, *core_line)) {
		_lfu_no_balance_unlock_cacheline(iter, cache_line);
		return false;
	}

	if (!ocf_cache_line_is_locked_exclusively(iter->cache,
				cache_line)) {
		_lfu_no_balance_unlock_hash(iter, *core_id, *core_line);
		_lfu_no_balance_unlock_cacheline(iter, cache_line);
		return false;
	}

	return true;
}

/* Get next clean cacheline from tail of lfu_no_balance lists. Caller must not hold any
 * eviction list lock. Returned cacheline is read or write locked, depending on
 * iter->write_lock. Returned cacheline has corresponding metadata hash bucket
 * locked. Cacheline is moved to the head of lfu_no_balance list before being returned */
static inline ocf_cache_line_t lfu_no_balance_iter_eviction_next(struct ocf_lfu_no_balance_iter *iter,
		ocf_core_id_t *core_id, uint64_t *core_line)
{
	uint32_t curr_evp;
	ocf_cache_line_t cline;
	ocf_cache_t cache = iter->cache;
	struct ocf_user_part *part = iter->part;
	struct ocf_lfu_no_balance_list *list;

	do {
		curr_evp = _lfu_no_balance_next_evp(iter);

		ocf_metadata_eviction_wr_lock(&cache->metadata.lock, curr_evp);

		list = evp_lfu_no_balance_get_list(part, curr_evp, iter->clean);

		cline = list->tail;
		while (cline != end_marker && !_lfu_no_balance_iter_evition_lock(iter,
				cline, core_id, core_line)) {
			cline = ocf_metadata_get_eviction_policy(
					iter->cache, cline)->lfu_no_balance.prev;
		}

		if (cline != end_marker) {
			remove_lfu_no_balance_list(cache, list, cline);
			add_lfu_no_balance_head(cache, list, cline);
			balance_lfu_no_balance_list(cache, list);
		}

		ocf_metadata_eviction_wr_unlock(&cache->metadata.lock, curr_evp);

		if (cline == end_marker && !_lfu_no_balance_evp_is_empty(iter)) {
			/* mark list as empty */
			_lfu_no_balance_evp_set_empty(iter);
		}
	} while (cline == end_marker && !_lfu_no_balance_evp_all_empty(iter));

	return cline;
}

/* Get next dirty cacheline from tail of lfu_no_balance lists. Caller must hold all
 * eviction list locks during entire iteration proces. Returned cacheline
 * is read or write locked, depending on iter->write_lock */
static inline ocf_cache_line_t lfu_no_balance_iter_cleaning_next(struct ocf_lfu_no_balance_iter *iter)
{
	uint32_t curr_evp;
	ocf_cache_line_t  cline;

	do {
		curr_evp = _lfu_no_balance_next_evp(iter);
		cline = iter->curr_cline[curr_evp];

		while (cline != end_marker && !_lfu_no_balance_trylock_cacheline(iter,
				cline)) {
			cline = ocf_metadata_get_eviction_policy(
					 iter->cache, cline)->lfu_no_balance.prev;
		}
		if (cline != end_marker) {
			iter->curr_cline[curr_evp] =
				ocf_metadata_get_eviction_policy(
						iter->cache , cline)->lfu_no_balance.prev;
		}

		if (cline == end_marker && !_lfu_no_balance_evp_is_empty(iter)) {
			/* mark list as empty */
			_lfu_no_balance_evp_set_empty(iter);
		}
	} while (cline == end_marker && !_lfu_no_balance_evp_all_empty(iter));

	return cline;
}

static void evp_lfu_no_balance_clean_end(void *private_data, int error)
{
	struct ocf_part_cleaning_ctx *ctx = private_data;
	unsigned i;

	for (i = 0; i < OCF_EVICTION_CLEAN_SIZE; i++) {
		if (ctx->cline[i] != end_marker)
			ocf_cache_line_unlock_rd(ctx->cache->device->concurrency
					.cache_line, ctx->cline[i]);
	}

	ocf_refcnt_dec(&ctx->counter);
}

static int evp_lfu_no_balance_clean_get(ocf_cache_t cache, void *getter_context,
		uint32_t idx, ocf_cache_line_t *line)
{
	struct ocf_part_cleaning_ctx *ctx = getter_context;

	if (ctx->cline[idx] == end_marker)
		return -1;

	*line = ctx->cline[idx];

	return 0;
}

void evp_lfu_no_balance_clean(ocf_cache_t cache, struct ocf_user_part *part,
		ocf_queue_t io_queue, uint32_t count)
{
	struct ocf_part_cleaning_ctx *ctx = &part->cleaning;
	struct ocf_cleaner_attribs attribs = {
		.lock_cacheline = false,
		.lock_metadata = true,
		.do_sort = true,

		.cmpl_context = &part->cleaning,
		.cmpl_fn = evp_lfu_no_balance_clean_end,

		.getter = evp_lfu_no_balance_clean_get,
		.getter_context = &part->cleaning,

		.count = min(count, OCF_EVICTION_CLEAN_SIZE),

		.io_queue = io_queue
	};
	ocf_cache_line_t *cline = part->cleaning.cline;
	struct ocf_lfu_no_balance_iter iter;
	unsigned evp;
	int cnt;
	unsigned i;
	unsigned lock_idx;

	if (ocf_mngt_cache_is_locked(cache))
		return;
	cnt = ocf_refcnt_inc(&ctx->counter);
	if (!cnt) {
		/* cleaner disabled by management operation */
		return;
	}

	if (cnt > 1) {
		/* cleaning already running for this partition */
		ocf_refcnt_dec(&ctx->counter);
		return;
	}

	part->cleaning.cache = cache;
	evp = io_queue->eviction_idx++ % OCF_NUM_EVICTION_LISTS;

	lock_idx = ocf_metadata_concurrency_next_idx(io_queue);
	ocf_metadata_start_shared_access(&cache->metadata.lock, lock_idx);

	OCF_METADATA_EVICTION_WR_LOCK_ALL();

	lfu_no_balance_iter_cleaning_init(&iter, cache, part, evp);
	i = 0;
	while (i < OCF_EVICTION_CLEAN_SIZE) {
		cline[i] = lfu_no_balance_iter_cleaning_next(&iter);
		if (cline[i] == end_marker)
			break;
		i++;
	}
	while (i < OCF_EVICTION_CLEAN_SIZE)
		cline[i++] = end_marker;

	OCF_METADATA_EVICTION_WR_UNLOCK_ALL();

	ocf_metadata_end_shared_access(&cache->metadata.lock, lock_idx);

	ocf_cleaner_fire(cache, &attribs);
}

bool evp_lfu_no_balance_can_evict(ocf_cache_t cache)
{
	if (env_atomic_read(&cache->pending_eviction_clines) >=
			OCF_PENDING_EVICTION_LIMIT) {
		return false;
	}

	return true;
}

/* the caller must hold the metadata lock */
uint32_t evp_lfu_no_balance_req_clines(struct ocf_request *req,
		struct ocf_user_part *part, uint32_t cline_no)
{
	struct ocf_lfu_no_balance_iter iter;
	uint32_t i;
	ocf_cache_line_t cline;
	uint64_t core_line;
	ocf_core_id_t core_id;
	ocf_core_t core;
	ocf_cache_t cache = req->cache;
	bool cl_write_lock =
		(req->engine_cbs->get_lock_type(req) ==	ocf_engine_lock_write);
	unsigned evp;
	unsigned req_idx = 0;

	if (cline_no == 0)
		return 0;

	if (unlikely(ocf_engine_unmapped_count(req) < cline_no)) {
		ocf_cache_log(req->cache, log_err, "Not enough space in"
				"request: unmapped %u, requested %u",
				ocf_engine_unmapped_count(req),
				cline_no);
		ENV_BUG();
	}

	evp = req->io_queue->eviction_idx++ % OCF_NUM_EVICTION_LISTS;

	lfu_no_balance_iter_eviction_init(&iter, cache, part, evp, cl_write_lock, req);

	i = 0;
	while (i < cline_no) {
		if (!evp_lfu_no_balance_can_evict(cache))
			break;

		cline = lfu_no_balance_iter_eviction_next(&iter, &core_id, &core_line);

		if (cline == end_marker)
			break;

		ENV_BUG_ON(metadata_test_dirty(cache, cline));

		/* TODO: if atomic mode is restored, need to zero metadata
		 * before proceeding with cleaning (see version <= 20.12) */

		/* find next unmapped cacheline in request */
		while (req_idx + 1 < req->core_line_count &&
				req->map[req_idx].status != LOOKUP_MISS) {
			req_idx++;
		}

		ENV_BUG_ON(req->map[req_idx].status != LOOKUP_MISS);

		ocf_metadata_start_collision_shared_access(
				cache, cline);
		metadata_clear_valid_sec(cache, cline, 0, ocf_line_end_sector(cache));
		ocf_metadata_remove_from_collision(cache, cline, part->id);
		ocf_metadata_end_collision_shared_access(
				cache, cline);

		core = ocf_cache_get_core(cache, core_id);
		env_atomic_dec(&core->runtime_meta->cached_clines);
		env_atomic_dec(&core->runtime_meta->
				part_counters[part->id].cached_clines);

		_lfu_no_balance_unlock_hash(&iter, core_id, core_line);

		ocf_map_cache_line(req, req_idx, cline);

		req->map[req_idx].status = LOOKUP_REMAPPED;
		ocf_engine_patch_req_info(cache, req, req_idx);

		if (cl_write_lock)
			req->map[req_idx].wr_locked = true;
		else
			req->map[req_idx].rd_locked = true;

		++req_idx;
		++i;
		/* Number of cachelines to evict have to match space in the request */
		ENV_BUG_ON(req_idx == req->core_line_count && i != cline_no );
	}

	return i;
}

/* the caller must hold the metadata lock */
void evp_lfu_no_balance_hot_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	struct lfu_no_balance_eviction_policy_meta *node;
	struct ocf_lfu_no_balance_list *list;

	node = &ocf_metadata_get_eviction_policy(cache, cline)->lfu_no_balance;

	list = evp_get_cline_list(cache, cline);

	OCF_METADATA_EVICTION_WR_LOCK(cline);

	if (node->next != end_marker ||
			node->prev != end_marker ||
			list->head == cline || list->tail == cline) {
		remove_lfu_no_balance_list(cache, list, cline);
	}

	/* Update lfu_no_balance */
	add_lfu_no_balance_head(cache, list, cline);

	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}

static inline void _lfu_no_balance_init(struct ocf_lfu_no_balance_list *list)
{
	list->num_nodes = 0;
	list->head = end_marker;
	list->tail = end_marker;
}

void evp_lfu_no_balance_init_evp(ocf_cache_t cache, struct ocf_user_part *part)
{
	struct ocf_lfu_no_balance_list *clean_list;
	struct ocf_lfu_no_balance_list *dirty_list;
	uint32_t i;

	for (i = 0; i < OCF_NUM_EVICTION_LISTS; i++) {
		clean_list = evp_lfu_no_balance_get_list(part, i, true);
		dirty_list = evp_lfu_no_balance_get_list(part, i, false);

		_lfu_no_balance_init(clean_list);
		_lfu_no_balance_init(dirty_list);
	}
}

void evp_lfu_no_balance_clean_cline(ocf_cache_t cache, struct ocf_user_part *part,
		uint32_t cline)
{
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	struct ocf_lfu_no_balance_list *clean_list;
	struct ocf_lfu_no_balance_list *dirty_list;

	clean_list = evp_lfu_no_balance_get_list(part, ev_list, true);
	dirty_list = evp_lfu_no_balance_get_list(part, ev_list, false);

	OCF_METADATA_EVICTION_WR_LOCK(cline);
	remove_lfu_no_balance_list(cache, dirty_list, cline);
	balance_lfu_no_balance_list(cache, dirty_list);
	add_lfu_no_balance_head(cache, clean_list, cline);
	balance_lfu_no_balance_list(cache, clean_list);
	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}

void evp_lfu_no_balance_dirty_cline(ocf_cache_t cache, struct ocf_user_part *part,
		uint32_t cline)
{
	uint32_t ev_list = (cline % OCF_NUM_EVICTION_LISTS);
	struct ocf_lfu_no_balance_list *clean_list;
	struct ocf_lfu_no_balance_list *dirty_list;

	clean_list = evp_lfu_no_balance_get_list(part, ev_list, true);
	dirty_list = evp_lfu_no_balance_get_list(part, ev_list, false);

	OCF_METADATA_EVICTION_WR_LOCK(cline);
	remove_lfu_no_balance_list(cache, clean_list, cline);
	balance_lfu_no_balance_list(cache, clean_list);
	add_lfu_no_balance_head(cache, dirty_list, cline);
	balance_lfu_no_balance_list(cache, dirty_list);
	OCF_METADATA_EVICTION_WR_UNLOCK(cline);
}


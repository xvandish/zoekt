package json

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sourcegraph/zoekt"
	"github.com/sourcegraph/zoekt/query"
)

// defaultTimeout is the maximum amount of time a search request should
// take. This is the same default used by Sourcegraph.
const defaultTimeout = 20 * time.Second

func JSONServer(searcher zoekt.Searcher) http.Handler {
	s := jsonSearcher{searcher}
	mux := http.NewServeMux()
	mux.HandleFunc("/search", s.jsonSearch)
	mux.HandleFunc("/list", s.jsonList)
	mux.HandleFunc("/v2/search", s.jsonSearchV2)
	return mux
}

type jsonSearcher struct {
	Searcher zoekt.Searcher
}

type jsonSearchArgs struct {
	Q       string
	RepoIDs *[]uint32
	Opts    *zoekt.SearchOptions
}

type jsonSearchReply struct {
	Result *zoekt.SearchResult
}

type jsonListArgs struct {
	Q    string
	Opts *zoekt.ListOptions
}

type jsonListReply struct {
	List *zoekt.RepoList
}

// to avoid nesting, we just directly reply with
// a zoekt.SearchResultV2, instead of putting it inside
// of Result
// type jsonSearchV2Reply

type jsonSearchV2Args struct {
	Q          string
	RepoIDs    *[]uint32
	SearchOpts *zoekt.SearchOptions
	ListOpts   *zoekt.ListOptions
}

func (s *jsonSearcher) jsonSearch(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	w.Header().Add("Content-Type", "application/json")

	if req.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}

	searchArgs := jsonSearchArgs{}
	err := json.NewDecoder(req.Body).Decode(&searchArgs)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if searchArgs.Q == "" {
		jsonError(w, http.StatusBadRequest, "missing query")
		return
	}
	if searchArgs.Opts == nil {
		searchArgs.Opts = &zoekt.SearchOptions{}
	}

	q, err := query.Parse(searchArgs.Q)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if searchArgs.RepoIDs != nil {
		q = query.NewAnd(q, query.NewRepoIDs(*searchArgs.RepoIDs...))
	}

	// Set a timeout if the user hasn't specified one.
	if searchArgs.Opts.MaxWallTime == 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	if err := CalculateDefaultSearchLimits(ctx, q, s.Searcher, searchArgs.Opts); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	searchResult, err := s.Searcher.Search(ctx, q, searchArgs.Opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = json.NewEncoder(w).Encode(jsonSearchReply{searchResult})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

// identical it jsonSearch, except it detects the type of search and includes it in the response,
// so frontend clients know what to expect.
// additionally, if a search is repoOnly, it will call searcher.List instead of searcher.Search, much
// like the built in zoekt/webserver
func (s *jsonSearcher) jsonSearchV2(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	w.Header().Add("Content-Type", "application/json")

	if req.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}

	searchArgs := jsonSearchV2Args{}
	err := json.NewDecoder(req.Body).Decode(&searchArgs)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if searchArgs.Q == "" {
		jsonError(w, http.StatusBadRequest, "missing query")
		return
	}

	q, err := query.Parse(searchArgs.Q)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// now, check if the query is a repo only query, if so, call list
	repoOnly := true
	query.VisitAtoms(q, func(q query.Q) {
		_, ok := q.(*query.Repo)
		repoOnly = repoOnly && ok
	})

	if repoOnly {
		listResult, err := s.Searcher.List(ctx, q, searchArgs.ListOpts)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}

		err = json.NewEncoder(w).Encode(zoekt.SearchResultV2{
			RepoResults: *listResult,
			SearchType:  zoekt.SearchTypeRepoOnly,
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// otherwise, this is a default, non-list search
	if searchArgs.SearchOpts == nil {
		searchArgs.SearchOpts = &zoekt.SearchOptions{}
	}
	if searchArgs.RepoIDs != nil {
		q = query.NewAnd(q, query.NewRepoIDs(*searchArgs.RepoIDs...))
	}

	// Set a timeout if the user hasn't specified one.
	if searchArgs.SearchOpts.MaxWallTime == 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	if err := CalculateDefaultSearchLimits(ctx, q, s.Searcher, searchArgs.SearchOpts); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	searchResult, err := s.Searcher.Search(ctx, q, searchArgs.SearchOpts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = json.NewEncoder(w).Encode(zoekt.SearchResultV2{
		Results:    *searchResult,
		SearchType: zoekt.SearchTypeDefault,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func jsonError(w http.ResponseWriter, statusCode int, err string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(struct{ Error string }{Error: err})
}

// Calculates and sets heuristic defaults on opts for various upper bounds on
// the number of matches when searching, if none are already specified. The
// defaults are derived from opts.MaxDocDisplayCount, so if none is set, there
// is no calculation to do.
func CalculateDefaultSearchLimits(ctx context.Context,
	q query.Q,
	searcher zoekt.Searcher,
	opts *zoekt.SearchOptions) error {
	if opts.MaxDocDisplayCount == 0 || opts.ShardMaxMatchCount != 0 {
		return nil
	}

	maxResultDocs := opts.MaxDocDisplayCount
	// This is a special mode of Search that _only_ calculates ShardFilesConsidered and bails ASAP.
	if result, err := searcher.Search(ctx, q, &zoekt.SearchOptions{EstimateDocCount: true}); err != nil {
		return err
	} else if numdocs := result.ShardFilesConsidered; numdocs > 10000 {
		// If the search touches many shards and many files, we
		// have to limit the number of matches.  This setting
		// is based on the number of documents eligible after
		// considering reponames, so large repos (both
		// android, chromium are about 500k files) aren't
		// covered fairly.

		// 10k docs, 50 maxResultDocs -> max match = (250 + 250 / 10)
		opts.ShardMaxMatchCount = maxResultDocs*5 + (5*maxResultDocs)/(numdocs/1000)

	} else {
		// Virtually no limits for a small corpus.
		n := numdocs + maxResultDocs*100
		opts.ShardMaxMatchCount = n
		opts.TotalMaxMatchCount = n
	}

	return nil
}

func (s *jsonSearcher) jsonList(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	if req.Method != "POST" {
		jsonError(w, http.StatusMethodNotAllowed, "Only POST is supported")
		return
	}

	listArgs := jsonListArgs{}
	err := json.NewDecoder(req.Body).Decode(&listArgs)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	query, err := query.Parse(listArgs.Q)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	listResult, err := s.Searcher.List(req.Context(), query, listArgs.Opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = json.NewEncoder(w).Encode(jsonListReply{listResult})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
}

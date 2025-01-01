package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bmizerany/pat"
	"github.com/google/uuid"
)

var (
	zoektRepoCache = flag.String("zoekt-repo-cache", "", "path to zoekt bare git repos")
	listen         = flag.String("listen", ":8080", "listen on this address.")
	docRoot        = flag.String("doc-root", "", "where to find runtime files")
)

const (
	// API version
	V2 = "/api/v2"

	// Git operations
	GitLogRoute                           = V2 + "/getGitLogForZoekt/:parent/:repo/+/"
	GitListBranchesRoute                  = V2 + "/getAllBranchesForZoekt/:parent/:repo/+/"
	GitListTagsRoute                      = V2 + "/getAllTagsForZoekt/:parent/:repo/+/"
	GetSyntaxHighlightedFileForZoektRoute = V2 + "/getSyntaxHighlightedFileForZoekt/:parent/:repo/+/"
	GitLsTreeRoute                        = V2 + "/getDirectoryTreeForZoekt/:parent/:repo/+/"
)

func main() {
	flag.Parse()

	if *zoektRepoCache == "" {
		log.Fatal("--zoekt-repo-cache is required")
	}
	if *docRoot == "" {
		log.Fatal("--doc-root is required")
	}

	// Create server configuration
	cfg := &config{
		ZoektRepoCache: *zoektRepoCache,
		DocRoot:        *docRoot,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		Port:           *listen,
	}

	// Initialize server
	server := NewServer(cfg)
	server.loadTemplates()
	if err := server.setupRoutes(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func parseRevisionAndPath(repoRevAndPath string) (revision, path string) {
	sp := strings.Split(repoRevAndPath, ":")

	if len(sp) == 2 {
		return sp[0], sp[1]
	}

	// Handle case where we just have a revision or empty string
	if len(sp) == 1 && sp[0] != "" {
		return sp[0], ""
	}

	return "HEAD", ""
}

type config struct {
	ZoektRepoCache string
	DocRoot        string
	Port           string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}
type Server struct {
	config      *config
	Templates   map[string]*template.Template
	AssetHashes map[string]string
	router      *pat.PatternServeMux
	server      *http.Server
}

func NewServer(config *config) *Server {
	return &Server{
		router: pat.New(),
		config: config,
	}
}

// Key type for request ID context
type contextKey string

const requestIDKey contextKey = "requestID"

func (s *Server) setupRoutes() error {
	// Add routes
	s.router.Get(GitLogRoute, http.HandlerFunc(s.ServeGitLogForZoekt))
	s.router.Get(GitListBranchesRoute, http.HandlerFunc(s.ServeListAllBranchesForZoekt))
	s.router.Get(GitListTagsRoute, http.HandlerFunc(s.ServeListAllTagsForZoekt))
	s.router.Get(GetSyntaxHighlightedFileForZoektRoute, http.HandlerFunc(s.ServeSyntaxHighlightedFileForZoekt))
	s.router.Get(GitLsTreeRoute, http.HandlerFunc(s.ServeGitLsTreeForZoekt))

	// 	m.Add("GET", "/api/v2/getSyntaxHighlightedFileForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeSyntaxHighlightedFileForZoekt))
	// 	m.Add("GET", "/api/v2/getDirectoryTreeForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeGitLsTreeForZoekt))
	// 	m.Add("GET", "/api/v2/getGitLogForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeGitLogForZoekt))
	// 	m.Add("GET", "/api/v2/getAllBranchesForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeListAllBranchesForZoekt))
	// 	m.Add("GET", "/api/v2/getAllTagsForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeListAllTagsForZoekt))
	handler := requestIDMiddleware(logMiddleware(s.router))

	s.server = &http.Server{
		Addr:         s.config.Port,
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	log.Printf("Starting server on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate request ID
		requestID := uuid.New().String()

		// Add it to response headers
		w.Header().Set("X-Request-ID", requestID)

		// Add it to context
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		requestID := r.Context().Value(requestIDKey).(string)

		// Log incoming request
		log.Printf("[%s] Started %s %s", requestID, r.Method, r.URL.Path)

		// Call next handler
		next.ServeHTTP(w, r)

		// Log completion
		log.Printf("[%s] Completed %s %s in %v",
			requestID,
			r.Method,
			r.URL.Path,
			time.Since(start),
		)
	})
}

// func (s *server) Handler(f func(c context.Context, w http.ResponseWriter))

func (s *Server) loadTemplates() {
	s.Templates = make(map[string]*template.Template)
	err := LoadTemplates(s.config.DocRoot, s.Templates)
	if err != nil {
		panic(fmt.Sprintf("loading templates: %v\n", err))
	}
	log.Printf("loaded %d templates\n", len(s.Templates))
}

func (s *Server) ServeSyntaxHighlightedFileForZoekt(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get(":parent")
	repo := r.URL.Query().Get(":repo")
	repoRevAndPath := pat.Tail(GetSyntaxHighlightedFileForZoektRoute, r.URL.Path)
	revision, path := parseRevisionAndPath(repoRevAndPath)
	repoPath := fmt.Sprintf("%s/%s/%s.git", s.config.ZoektRepoCache, parent, repo)

	data, err := BuildFileDataForZoektFilePreview(path, repoPath, parent+"/"+repo, revision)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file or tree - %s", err), 500)
		return
	}

	s.renderPage(w, r, "raw_blob_or_tree.html", &page{
		IncludeHeader: false,
		Data:          data,
	})
}

type page struct {
	Title         string
	ScriptName    string
	ScriptData    interface{}
	IncludeHeader bool
	Data          interface{}
	// Config Config
	AssetHashes map[string]string
	Nonce       template.HTMLAttr
	BodyId      string
}

func (s *Server) renderPage(w io.Writer, r *http.Request, templateName string, pageData *page) {
	log.Printf("in renderPage!\n")
	t, ok := s.Templates[templateName]
	if !ok {
		log.Printf("Error: no template named %s", templateName)
		return
	}

	pageData.AssetHashes = s.AssetHashes

	err := t.ExecuteTemplate(w, templateName, pageData)
	if err != nil {
		log.Printf("Error rendering: %v: %s", templateName, err)
		return
	} else {
		log.Printf("Success rendering %s\n", templateName)
	}
}

func replyJSON(ctx context.Context, w http.ResponseWriter, status int, obj interface{}) {
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(obj); err != nil {
		log.Printf("writing http response, data=%s err=%q", "TODO", err.Error())
	}
}

func writeError(ctx context.Context, w http.ResponseWriter, status int, code, message string) {
	replyJSON(ctx, w, status, ReplyError{Err: InnerError{Code: code, Message: message}})
}

func (s *Server) ServeGitLsTreeForZoekt(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get(":parent")
	repo := r.URL.Query().Get(":repo")
	repoRevAndPath := pat.Tail(GitLogRoute, r.URL.Path)
	revision, path := parseRevisionAndPath(repoRevAndPath)
	repoPath := fmt.Sprintf("%s/%s/%s.git", s.config.ZoektRepoCache, parent, repo)

	data, err := GetLsTreeOutput(path, repoPath, revision)
	if err != nil {
		writeError(context.Background(), w, 500, "", err.Error())
		return
	}

	w.Write(data)
}

func (s *Server) ServeGitLogForZoekt(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get(":parent")
	repo := r.URL.Query().Get(":repo")
	repoRevAndPath := pat.Tail(GitLogRoute, r.URL.Path)
	revision, path := parseRevisionAndPath(repoRevAndPath)
	repoPath := fmt.Sprintf("%s/%s/%s.git", s.config.ZoektRepoCache, parent, repo)

	queryVals := r.URL.Query()
	var err error
	// see fileviewer.CommitOptions documentation for details
	// on each option
	// check the numerical values
	first := queryVals.Get("first")

	var firstVal uint64
	if queryVals.Has("first") {
		firstVal, err = strconv.ParseUint(first, 10, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not parse first: %s\n", err.Error()), 500)
			return
		}
	}

	var afterCursorVal uint64
	if queryVals.Has("afterCursor") {
		afterCursorVal, err = strconv.ParseUint(queryVals.Get("afterCursor"), 10, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not parse afterCursor: %s\n", err.Error()), 500)
			return
		}

	}

	opts := CommitOptions{
		Range: revision,
		Path:  path,
		N:     uint(firstVal),
		SkipN: uint(afterCursorVal),
	}

	commitLog, err := BuildGitLog(opts, repoPath)

	if err != nil {
		fmt.Printf("err=%v\n", err)
		http.Error(w, err.Error(), 500)
		return
	}

	replyJSON(context.Background(), w, 200, commitLog)
}

func (s *Server) ServeListAllBranchesForZoekt(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get(":parent")
	repo := r.URL.Query().Get(":repo")
	repoPath := fmt.Sprintf("%s/%s/%s.git", s.config.ZoektRepoCache, parent, repo)

	branches, err := ListAllBranches(repoPath)
	if err != nil {
		fmt.Printf("err=%v\n", err)
		http.Error(w, "could not list branches for repo provided", 500)
		return
	}

	replyJSON(context.Background(), w, 200, branches)
}

func (s *Server) ServeListAllTagsForZoekt(w http.ResponseWriter, r *http.Request) {
	parent := r.URL.Query().Get(":parent")
	repo := r.URL.Query().Get(":repo")
	repoPath := fmt.Sprintf("%s/%s/%s.git", s.config.ZoektRepoCache, parent, repo)

	tags, err := ListAllTags(repoPath)
	if err != nil {
		fmt.Printf("err=%v\n", err)
		http.Error(w, "could not list branches for repo provided", 500)
		return
	}

	replyJSON(context.Background(), w, 200, tags)
}

// get all tags, get all branches, getgitlog, getdirectorytreeforzoekt,
// getsyntaxhighlightedfileforzoekt

// 	m.Add("GET", "/api/v2/getSyntaxHighlightedFileForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeSyntaxHighlightedFileForZoekt))
// 	m.Add("GET", "/api/v2/getDirectoryTreeForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeGitLsTreeForZoekt))
// 	m.Add("GET", "/api/v2/getGitLogForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeGitLogForZoekt))
// 	m.Add("GET", "/api/v2/getAllBranchesForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeListAllBranchesForZoekt))
// 	m.Add("GET", "/api/v2/getAllTagsForZoekt/:parent/:repo/+/", srv.Handler(srv.ServeListAllTagsForZoekt))
// 	m.Add("GET", "/api/v2/getDirectoryTreeForZoekt/", srv.Handler(srv.TestHandler))

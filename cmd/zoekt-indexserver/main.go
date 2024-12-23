// Copyright 2016 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This program manages a zoekt indexing deployment:
// * recycling logs
// * periodically fetching new data.
// * periodically reindexing all git repos.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xvandish/zoekt"
)

const day = time.Hour * 24
const iso8601Format = "2006-01-02T15:04:05Z07:00"

var (
	// we use this for 3 things:
	// 1. prevent the same git repo from being indexed concurrently
	// 2. prevent a repo from being indexed and fetched concurrently
	// 3. stop all indexing/fetching while the periodic backup happens
	muIndexAndDataDirs indexMutex
)

func loggedRun(cmd *exec.Cmd) (out, err []byte) {
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	log.Printf("run %v", cmd.Args)
	if err := cmd.Run(); err != nil {
		log.Printf("command %s failed: %v\nOUT: %s\nERR: %s",
			cmd.Args, err, outBuf.String(), errBuf.String())
	}

	return outBuf.Bytes(), errBuf.Bytes()
}

type Options struct {
	cpuFraction          float64
	cpuCount             int
	fetchInterval        time.Duration
	fetchIntervalSlow    time.Duration
	mirrorInterval       time.Duration
	bruteReindexInterval time.Duration
	backupInterval       time.Duration
	indexFlagsStr        string
	indexFlags           []string
	mirrorConfigFile     string
	maxLogAge            time.Duration
	indexTimeout         time.Duration
	parallelListApiReqs  int
	parallelClones       int
	parallelFetches      int
	parallelIndexes      int
	useSmartGHFetch      bool
	workingHoursStart    int
	workingHoursEnd      int
	// time.Location
	workingHoursZoneStr string
	workingHoursZone    *time.Location
	appPK               string
	appID               int64
	appInstallID        int64
	initRestoreIndexDir string
	initRestoreGitDir   string
}

func (o *Options) validate() {
	if o.cpuFraction <= 0.0 || o.cpuFraction > 1.0 {
		log.Fatal("cpu_fraction must be between 0.0 and 1.0")
	}

	o.cpuCount = int(math.Trunc(float64(runtime.GOMAXPROCS(0)) * o.cpuFraction))
	if o.cpuCount < 1 {
		o.cpuCount = 1
	}
	if o.indexFlagsStr != "" {
		o.indexFlags = strings.Split(o.indexFlagsStr, " ")
	}

	if o.workingHoursZoneStr != "" {
		l, err := time.LoadLocation(o.workingHoursZoneStr)
		if err != nil {
			log.Fatalf("could not load location=%s. %v\n", o.workingHoursZoneStr, err)
		}
		o.workingHoursZone = l
	}

	if o.workingHoursStart > 0 {
		if o.workingHoursStart >= o.workingHoursEnd {
			log.Fatal("working_hours_start must be smaller than working_hours_end")
		}
		if o.workingHoursZoneStr == "" {
			log.Fatal("you must set a location if using working_hours. See time.Location for valid locations")
		}
	}

	if o.appPK != "" {
		if o.appID == -1 || o.appInstallID == -1 {
			log.Fatal("appID and appInstallID must be provided to use a github app")
		}
	}
}

func (o *Options) defineFlags() {
	flag.DurationVar(&o.indexTimeout, "index_timeout", time.Hour, "kill index job after this much time")
	flag.DurationVar(&o.maxLogAge, "max_log_age", 3*day, "recycle index logs after this much time")
	flag.DurationVar(&o.fetchInterval, "fetch_interval", time.Hour, "run fetches this often")
	flag.DurationVar(&o.fetchIntervalSlow, "fetch_interval_slow", time.Hour*5, "run fetches this often during non-work hours")
	flag.StringVar(&o.mirrorConfigFile, "mirror_config",
		"", "JSON file holding mirror configuration.")
	flag.DurationVar(&o.mirrorInterval, "mirror_duration", 24*time.Hour, "find and clone new repos at this frequency.")
	flag.DurationVar(&o.bruteReindexInterval, "brute_reindex_interval", 24*time.Hour, "re-index all repos even if they had no update. Still runs with -incremental by default.")
	flag.DurationVar(&o.backupInterval, "backup_interval", 24*time.Hour, "backup indices and git repos at this interval. Uses gsutil and backs up to codesearch_backup bucket")
	flag.Float64Var(&o.cpuFraction, "cpu_fraction", 0.25,
		"use this fraction of the cores for indexing.")
	flag.StringVar(&o.indexFlagsStr, "git_index_flags", "", "space separated list of flags passed through to zoekt-git-index (e.g. -git_index_flags='-symbols=false -submodules=false'")
	flag.IntVar(&o.parallelListApiReqs, "parallel_list_api_reqs", 1, "number of concurrent list apis reqs to fetch org/user repos. Not all mirrors support this flag")
	flag.IntVar(&o.parallelClones, "parallel_clones", 1, "number of concurrent gitindex/clone operations. Not all mirrors support this flag")
	flag.IntVar(&o.parallelFetches, "parallel_fetches", 1, "number of concurrent git fetch ops")
	flag.IntVar(&o.parallelIndexes, "parallel_indexes", 1, "number of concurrent zoekt-git-index ops")
	flag.BoolVar(&o.useSmartGHFetch, "use_smart_gh_fetch", false, "When enabled, uses the GitHub search api to find which repos to run git fetch on")
	flag.IntVar(&o.workingHoursStart, "working_hours_start", -1, "The start of working hours in 24 hour representation. E.g 9 for 9AM and 17 for 5pm. If set to a non-negative value, it will be used, along with working_hours_end, to decide between fetchInterval or fetchIntervalSlow")
	flag.IntVar(&o.workingHoursEnd, "working_hours_end", -1, "The end of working hours in 24 hour format. E.g 9 for 9AM and 17 for 5PM. If set to a non-negative value, it will be used, along with working_hours_start, to decide between fetchInterval and fetchIntervalSlow")
	flag.StringVar(&o.workingHoursZoneStr, "working_hours_zone", "America/New_York", "A time.Location string to set work location")
	flag.StringVar(&o.appPK, "app-pk", "", "The filepath of a GitHub App PrivateKey. Used to create installation tokens to interact with the API")
	flag.Int64Var(&o.appID, "app-id", -1, "The ID of the GithubAP")
	flag.Int64Var(&o.appInstallID, "app-install-id", -1, "The installation ID of the GitHub app")
	flag.StringVar(&o.initRestoreGitDir, "restore-dir-git", "zoekt-backup/repos/", "Initialize dataDir with the data in this folder")
	flag.StringVar(&o.initRestoreIndexDir, "restore-dir-index", "zoekt-backup/indices/", "Initialize indexDir with the data in this folder")
}

func periodicBackup(dataDir, indexDir string, opts *Options) {
	t := time.NewTicker(opts.backupInterval)
	for {
		// lock the index and git directories from being written to
		muIndexAndDataDirs.GlobalWaitForPending(func() {
			fmt.Printf("starting backup...\n")
			idxSyncCmd := exec.Command("rsync", "-ruv", indexDir+"/", "zoekt-backup/indices/")
			err := idxSyncCmd.Run()
			if err != nil {
				fmt.Printf("ERROR: error backup up index shards %v\n", err)
			}

			gitSyncCmd := exec.Command("rsync", "-ruv", dataDir+"/", "zoekt-backup/repos/")
			err = gitSyncCmd.Run()
			if err != nil {
				fmt.Printf("ERROR: error backing up git repos %v\n", err)
			}
			fmt.Printf("finished backup\n")
		})
		<-t.C
	}
}

// indexPendingRepos consumes the directories on the repos channel and
// indexes them, sequentially.
func indexPendingRepos(indexDir, repoDir string, opts *Options, repos <-chan string) {
	// set up n listeners on the channel
	for i := 0; i < opts.parallelIndexes; i++ {
		go func(r <-chan string) {
			for dir := range r {
				ran := muIndexAndDataDirs.With(dir, func() {
					indexPendingRepo(dir, indexDir, repoDir, opts)
				})
				if !ran {
					fmt.Printf("index job for repository: %s already running\n", dir)
				}

				// TODO: handle failures better. For now, as this is causing
				// problems with parallel indexing, so we don't make an effor to
				// clean up. We can have zoekt-git-index be the one to clean up,
				// or we can propgate exit status and still handle it here

				// Failures (eg. timeout) will leave temp files
				// around. We have to clean them, or they will fill up the indexing volume.
				// Okay, I think what's going on here is indexPendingRepos isn't cleanly working - when
				// one index finishes (but another is still running and has temp files), the finished
				// index triggers the filepath.Glob(), and then removes the indexes from the indexer that
				// hasn't finished!
				// if failures, err := filepath.Glob(filepath.Join(indexDir, "*.tmp")); err != nil {
				// 	log.Printf("Glob: %v", err)
				// } else {
				// 	for _, f := range failures {
				// 		os.Remove(f)
				// 	}
				// }
			}
		}(repos)
	}
}

func indexPendingRepo(dir, indexDir, repoDir string, opts *Options) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.indexTimeout)
	defer cancel()
	args := []string{
		"-require_ctags",
		fmt.Sprintf("-parallelism=%d", opts.cpuCount),
		"-repo_cache", repoDir,
		"-index", indexDir,
		"-incremental",
	}
	args = append(args, opts.indexFlags...)
	args = append(args, dir)
	cmd := exec.CommandContext(ctx, "zoekt-git-index", args...)
	loggedRun(cmd)
}

// deleteLogs deletes old logs.
func deleteLogs(logDir string, maxAge time.Duration) {
	fs, err := filepath.Glob(filepath.Join(logDir, "*"))
	if err != nil {
		log.Fatalf("filepath.Glob(%s): %v", logDir, err)
	}

	threshold := time.Now().Add(-maxAge)
	for _, fn := range fs {
		if fi, err := os.Lstat(fn); err == nil && fi.ModTime().Before(threshold) {
			os.Remove(fn)
		}
	}
}

func deleteLogsLoop(logDir string, maxAge time.Duration) {
	tick := time.NewTicker(maxAge / 100)
	for {
		deleteLogs(logDir, maxAge)
		<-tick.C
	}
}

// Delete the shard if its corresponding git repo can't be found.
func deleteIfOrphan(repoDir string, fn string) error {
	f, err := os.Open(fn)
	if err != nil {
		return nil
	}
	defer f.Close()

	ifile, err := zoekt.NewIndexFile(f)
	if err != nil {
		return nil
	}
	defer ifile.Close()

	repos, _, err := zoekt.ReadMetadata(ifile)
	if err != nil {
		return nil
	}

	// TODO support compound shards in zoekt-indexserver
	if len(repos) != 1 {
		return nil
	}
	repo := repos[0]

	_, err = os.Stat(repo.Source)
	if os.IsNotExist(err) {
		log.Printf("deleting orphan shard %s; source %q not found", fn, repo.Source)
		return os.Remove(fn)
	}

	return err
}

func deleteOrphanIndexes(indexDir, repoDir string, watchInterval time.Duration) {
	t := time.NewTicker(watchInterval)

	expr := indexDir + "/*"
	for {
		fs, err := filepath.Glob(expr)
		if err != nil {
			log.Printf("Glob(%q): %v", expr, err)
		}

		for _, f := range fs {
			if err := deleteIfOrphan(repoDir, f); err != nil {
				log.Printf("deleteIfOrphan(%q): %v", f, err)
			}
		}
		<-t.C
	}
}

func main() {
	var opts Options
	opts.defineFlags()
	dataDir := flag.String("data_dir",
		filepath.Join(os.Getenv("HOME"), "zoekt-serving"), "directory holding all data.")
	indexDir := flag.String("index_dir", "", "directory holding index shards. Defaults to $data_dir/index/")
	flag.Parse()
	opts.validate()

	if *dataDir == "" {
		log.Fatal("must set --data_dir")
	}

	// Automatically prepend our own path at the front, to minimize
	// required configuration.
	if l, err := os.Readlink("/proc/self/exe"); err == nil {
		os.Setenv("PATH", filepath.Dir(l)+":"+os.Getenv("PATH"))
	}

	logDir := filepath.Join(*dataDir, "logs")
	if *indexDir == "" {
		*indexDir = filepath.Join(*dataDir, "index")
	}
	repoDir := filepath.Join(*dataDir, "repos")
	for _, s := range []string{logDir, *indexDir, repoDir} {
		if _, err := os.Stat(s); err == nil {
			continue
		}

		if err := os.MkdirAll(s, 0o755); err != nil {
			log.Fatalf("MkdirAll %s: %v", s, err)
		}
	}

	cfgs, err := readConfigURL(opts.mirrorConfigFile)
	if err != nil {
		log.Fatalf("readConfigURL(%s): %v", opts.mirrorConfigFile, err)
	}

	if opts.useSmartGHFetch {
		for _, cfg := range cfgs {
			if !cfg.IsGithubConfig() {
				log.Fatal("use_smart_gh_fetch is only valid if a config ONLY contains GitHub configs")
			}
		}
	}

	if opts.initRestoreGitDir != "" {
		log.Printf("starting git restore...\n")
		gitSyncCmd := exec.Command("rsync", "-ruv", opts.initRestoreGitDir, *dataDir+"/")
		_, errBuf := loggedRun(gitSyncCmd)
		if errBuf != nil {
			log.Fatalf("ERROR: error initializing git repos %v\n", err)
		}
		log.Printf("\tDONE\n")
	}
	if opts.initRestoreIndexDir != "" {
		log.Printf("starting index restore...")
		idxSyncCmd := exec.Command("rsync", "-ruv", opts.initRestoreIndexDir, *indexDir+"/")
		_, errBuf := loggedRun(idxSyncCmd)
		if errBuf != nil {
			log.Fatalf("ERROR: error initializing index shards %v\n", err)
		}
		log.Printf("\tDONE\n")
	}

	pendingRepos := make(chan string, 6000)
	go periodicMirrorFile(repoDir, &opts, pendingRepos)
	go deleteLogsLoop(logDir, opts.maxLogAge)
	go deleteOrphanIndexes(*indexDir, repoDir, opts.fetchInterval)
	go periodicBackup(repoDir, *indexDir, &opts)
	go indexPendingRepos(*indexDir, repoDir, &opts, pendingRepos)

	if opts.useSmartGHFetch {
		periodicSmartGHFetchV2(repoDir, *indexDir, &opts, pendingRepos)
	} else {
		periodicFetch(repoDir, *indexDir, &opts, pendingRepos)
	}
}

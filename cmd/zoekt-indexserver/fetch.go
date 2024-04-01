package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	openTracingLog "github.com/opentracing/opentracing-go/log"
	"github.com/xvandish/zoekt/gitindex"
	internalTrace "github.com/xvandish/zoekt/trace"
	"golang.org/x/sync/errgroup"
)

// finds all git repos available, and calls git fetch on them
// it does so in parallel, with opts.parallelFetches as the bound
func periodicFetch(ctx context.Context, repoDir, indexDir string, opts *Options, pendingRepos chan<- string) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.periodicFetch", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
		openTracingLog.String("indexDir", indexDir),
	)

	t := time.NewTicker(opts.fetchInterval)
	lastBruteReindex := time.Now()
	for {
		fmt.Printf("starting periodicFetch\n")
		lastBruteReindex = gitFetchNeededRepos(ctx, repoDir, indexDir, opts, pendingRepos, lastBruteReindex)
		<-t.C
	}
}

func callGetReposModifiedSinceForCfgs(ctx context.Context, cfgs []ConfigEntry, lookbackInterval time.Time, repoDir string) []string {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.callGetReposModifiedSinceForCfgs", "")
	defer trace.Finish()

	var reposToFetchAndIndex []string
	for _, c := range cfgs {
		var cmd *exec.Cmd
		cmd = exec.Command("zoekt-github-get-repos-modified-since",
			"-dest", repoDir)
		cmd.Args = append(cmd.Args, createGithubArgsMirrorAndFetchArgs(ctx, c)...)
		cmd.Args = append(cmd.Args, "-since", lookbackInterval.Format(iso8601Format))

		stdout, _ := loggedRun(trace, cmd)
		reposPushed := 0
		for _, fn := range bytes.Split(stdout, []byte{'\n'}) {
			if len(fn) == 0 {
				continue
			}
			reposToFetchAndIndex = append(reposToFetchAndIndex, string(fn))
			reposPushed += 1
		}

		fmt.Printf("%v - there are %d repos to fetch and index\n", cmd.Args, reposPushed)
	}

	// add list of repos to trace
	trace.LogFields(
		openTracingLog.String("reposToFetchAndIndex", strings.Join(reposToFetchAndIndex, ",")),
	)

	return reposToFetchAndIndex
}

func processReposToFetchAndIndex(ctx context.Context, reposToFetchAndIndex []string, parallelFetches int, pendingRepos chan<- string) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.processReposToFetchAndIndex", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("reposToFetchAndIndex", strings.Join(reposToFetchAndIndex, ",")),
		openTracingLog.Int("parallelFetches", parallelFetches),
	)

	g, _ := errgroup.WithContext(context.Background())
	g.SetLimit(parallelFetches)
	for _, dir := range reposToFetchAndIndex {
		dir := dir
		g.Go(func() error {
			ran := muIndexAndDataDirs.With(dir, func() {
				if hasUpdate := fetchGitRepo(ctx, dir); !hasUpdate {
					fmt.Printf("ERROR: we mistakenly thought %s had an update. Check smartGH logic\n", dir)
				} else {
					fmt.Printf("dir=%s has update\n", dir)
					pendingRepos <- dir
				}
			})

			if !ran {
				fmt.Printf("either an index or fetch job for repo=%s already running\n", dir)
			}
			return nil
		})
	}
	g.Wait()
}

// I think I need to re-think this logic
// When we run periodic, we should use now-fetchInterval as our time
// when we finish a run, what time should we write? The time we used to query (now-fetchInterval)
// The next run, should read the previous run time. If the previous time is < (now-fetchInterval-fetchInterval)
// then we use it

func writeFetchTimeToFile(ctx context.Context, repoDir string, t time.Time) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.writeFetchTimeToFile", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
		openTracingLog.String("time", t.String()),
	)

	f := filepath.Join(repoDir, "time-of-last-update.txt")

	trace.LogFields(
		openTracingLog.String("file-path", f),
	)

	err := os.WriteFile(f, []byte(t.Format(iso8601Format)), 0644)
	if err != nil {
		trace.SetError(err)
		fmt.Printf("error writing time to file: %v\n", err)
	}
}

func readFetchTimeFromFile(ctx context.Context, repoDir string) (time.Time, error) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.readFetchTimeFromFile", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
	)

	f := filepath.Join(repoDir, "time-of-last-update.txt")
	trace.LogFields(
		openTracingLog.String("file-path", f),
	)

	bytes, err := os.ReadFile(f)
	if err != nil {
		trace.SetError(err)
		fmt.Printf("error reading fetchTime from file: %v\n", err)
		return time.Time{}, err
	}

	lastLookbackIntervalStart := strings.TrimSpace(string(bytes))

	p, err := time.Parse(iso8601Format, lastLookbackIntervalStart)
	if err != nil {
		trace.SetError(err)
		fmt.Printf("error reading fetchTime from file: %v\n", err)
		return time.Time{}, err
	}

	trace.LogFields(
		openTracingLog.String("time", p.String()),
	)

	return p, nil
}

const accetableLookbackDiffThreshold = 5 * time.Second
const dayAgo = 24 * time.Hour

// this function determines the "lookback" period -
// i.e. the time that github will use to find all repos that
// have been updated since. In the case that that time is > fetchInterval ago,
// we also return a newer timeToWrite that will be written to the file. This prevents an
// endless loop, which I will explain later...
func getLookbackWindowStart(ctx context.Context, repoDir string, fetchInterval time.Duration) (time.Time, time.Time) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.getLookbackWindowStart", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
		openTracingLog.String("fetchInterval", fetchInterval.String()),
	)

	now := time.Now()
	lookbackIntervalStart := now.Add(-fetchInterval)
	trace.LogFields(
		openTracingLog.String("lookbackIntervalStart", lookbackIntervalStart.String()),
	)

	// if there is an error reading the previousLookbackInterval
	prevLookbackIntervalStart, err := readFetchTimeFromFile(ctx, repoDir)
	if err != nil { // no file exists, or format wrong
		trace.SetError(err)
		fmt.Printf("using a 24 hour lookback window.\n")
		return now, lookbackIntervalStart.Add(time.Duration(-24) * time.Hour)
	}

	diff := lookbackIntervalStart.Sub(prevLookbackIntervalStart)
	trace.LogFields(
		openTracingLog.String("diff", diff.String()),
	)

	// this should never happen. If it does, we have a problem, most likely in the
	// file writing phase
	if diff < 0 {
		fmt.Printf("Diff of prevLookback=%s and lookback=%s is < 0. Using current time.\n", prevLookbackIntervalStart.String(), lookbackIntervalStart.String())
		return now, lookbackIntervalStart
	}

	// if the prevLookbackIntervalStart happened longer ago than we're comfortable with
	// we use it, in the case that repos haven't been updated since that time
	if diff > accetableLookbackDiffThreshold {
		fmt.Printf("Diff of prevLookback=%s and lookback=%s > %s. Using prevLookbackIntervalStart\n", prevLookbackIntervalStart.Format(iso8601Format), lookbackIntervalStart.Format(iso8601Format), accetableLookbackDiffThreshold)
		return now, prevLookbackIntervalStart
	}

	return now, lookbackIntervalStart
}

func isDuringWorkHours(ctx context.Context, timeToCheck time.Time, startHour, endHour int, zone *time.Location) bool {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.isDuringWorkHours", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("timeToCheck", timeToCheck.String()),
		openTracingLog.Int("startHour", startHour),
		openTracingLog.Int("endHour", endHour),
		openTracingLog.String("zone", zone.String()),
	)

	currHour := timeToCheck.In(zone).Hour()
	trace.LogFields(
		openTracingLog.Int("currHour", currHour),
	)

	return currHour >= startHour && currHour <= endHour
}
func workingHoursEnabled(ctx context.Context, opts *Options) bool {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.workingHoursEnabled", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.Int("workingHoursStart", opts.workingHoursStart),
	)

	return opts.workingHoursStart >= 0
}

func periodicSmartGHFetchV2(ctx context.Context, repoDir, indexDir string, opts *Options, pendingRepos chan<- string) {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.periodicSmartGHFetchV2", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
	)

	currInterval := opts.fetchInterval
	if workingHoursEnabled(ctx, opts) && !isDuringWorkHours(ctx, time.Now(), opts.workingHoursStart, opts.workingHoursEnd, opts.workingHoursZone) {
		currInterval = opts.fetchIntervalSlow
		fmt.Printf("not during working hours. Starting interval is %s\n", opts.fetchIntervalSlow)
	}

	t := time.NewTicker(currInterval)
	lastBruteReindex := time.Now()

	for {
		timeToWrite, lookbackIntervalStart := getLookbackWindowStart(ctx, repoDir, currInterval)
		fmt.Printf("lookbackIntervalStart=%s\n", lookbackIntervalStart.String())

		if time.Since(lastBruteReindex) >= opts.bruteReindexInterval {
			fmt.Printf("bruteReindexing\n")
			lastBruteReindex = gitFetchNeededRepos(ctx, repoDir, indexDir, opts, pendingRepos, lastBruteReindex)
			continue
		}

		cfg, err := readConfigURL(ctx, opts.mirrorConfigFile)
		if err != nil {
			// we'd have a lot of problems anyways, so just error out
			trace.SetError(err)
			fmt.Printf("ERROR: can't read configUrl: %v\n", err)
			continue
		}

		// for every config, call github-thing
		reposToFetchAndIndex := callGetReposModifiedSinceForCfgs(ctx, cfg, lookbackIntervalStart, repoDir)
		processReposToFetchAndIndex(ctx, reposToFetchAndIndex, opts.parallelFetches, pendingRepos)

		writeFetchTimeToFile(ctx, repoDir, timeToWrite)

		// this code has a bit of an issue. If fetchIntervalSlow is much slower, than it's possible
		// that the entire fetchIntervalSlow elapses before we switch back to the faster fetchInterval.
		// As I'm planning on using only a 10min slow interval, this is a problem for later.
		if workingHoursEnabled(ctx, opts) {
			if isDuringWorkHours(ctx, time.Now(), opts.workingHoursStart, opts.workingHoursEnd, opts.workingHoursZone) {
				t.Reset(opts.fetchInterval)
				currInterval = opts.fetchInterval
			} else {
				fmt.Printf("not during working hours. Setting interval to=%s\n", opts.fetchIntervalSlow)
				t.Reset(opts.fetchIntervalSlow)
				currInterval = opts.fetchIntervalSlow
			}
		}

		<-t.C
	}

}

func gitFetchNeededRepos(ctx context.Context, repoDir, indexDir string, opts *Options, pendingRepos chan<- string, lastBruteReindex time.Time) time.Time {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.gitFetchNeededRepos", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("repoDir", repoDir),
		openTracingLog.String("indexDir", indexDir),
	)

	fmt.Printf("running gitFetchNeededRepos\n")
	repos, err := gitindex.FindGitRepos(repoDir)
	if err != nil {
		trace.SetError(err)
		log.Println(err)
		return lastBruteReindex
	}
	if len(repos) == 0 {
		log.Printf("no repos found under %s", repoDir)
	} else {
		fmt.Printf("found %d repos to fetch with %d workers\n", len(repos), opts.parallelFetches)
	}

	g, _ := errgroup.WithContext(context.Background())
	g.SetLimit(opts.parallelFetches)

	// TODO: Randomize to make sure quota throttling hits everyone.
	var mu sync.Mutex
	later := map[string]struct{}{}
	count := 0
	for _, dir := range repos {
		dir := dir
		g.Go(func() error {
			ran := muIndexAndDataDirs.With(dir, func() {
				if hasUpdate := fetchGitRepo(ctx, dir); !hasUpdate {
					mu.Lock()
					later[dir] = struct{}{}
					mu.Unlock()
				} else {
					fmt.Printf("dir=%s has update\n", dir)
					pendingRepos <- dir
					count += 1
				}
			})
			if !ran {
				fmt.Printf("either an index or fetch job for repo=%s already running\n", dir)
			}
			return nil
		})
	}
	g.Wait()
	fmt.Printf("%d repos had git updates\n", count)

	if time.Since(lastBruteReindex) >= opts.bruteReindexInterval {
		fmt.Printf("re-indexing the %d repos that had no update\n", len(later))
		for r := range later {
			pendingRepos <- r
		}
		lastBruteReindex = time.Now()
	} else {
		fmt.Printf("not re-indexing the %d repos that had no update\n", len(later))
	}

	return lastBruteReindex
}

// fetchGitRepo runs git-fetch, and returns true if there was an
// update.
func fetchGitRepo(ctx context.Context, dir string) bool {
	trace, ctx := internalTrace.New(ctx, "zoekt-indexserver.gitFetchNeededRepos", "")
	defer trace.Finish()

	trace.LogFields(
		openTracingLog.String("dir", dir),
	)

	cmd := exec.Command("git", "--git-dir", dir, "fetch", "origin")
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}

	// Prevent prompting
	cmd.Stdin = &bytes.Buffer{}
	cmd.Stderr = errBuf
	cmd.Stdout = outBuf
	if err := cmd.Run(); err != nil {
		trace.SetError(err)
		log.Printf("command %s failed: %v\nOUT: %s\nERR: %s",
			cmd.Args, err, outBuf.String(), errBuf.String())
	} else {
		return len(errBuf.Bytes()) != 0
	}
	return false
}
